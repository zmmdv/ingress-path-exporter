package parser

import (
    "bufio"
    "context"
    "fmt"
    "log"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
)

type MetricsCollector struct {
    requestsTotal *prometheus.CounterVec
    requestCount  map[string]float64
    mutex         sync.RWMutex
    startTime     time.Time
}

type LogParser struct {
    accessPattern *regexp.Regexp
    lineCount     int
    sampleRate    int
    metrics       *MetricsCollector
}

func NewMetricsCollector() *MetricsCollector {
    collector := &MetricsCollector{
        requestsTotal: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "nginx_http_requests_total",
                Help: "Total number of HTTP requests by method, path, host, status, and source IP",
            },
            []string{"method", "path", "host", "status", "source_ip"},
        ),
        requestCount: make(map[string]float64),
        mutex:       sync.RWMutex{},
        startTime:   time.Now(),
    }
    
    // Register the metrics
    err := prometheus.Register(collector.requestsTotal)
    if err != nil {
        log.Printf("❌ Error registering metrics: %v", err)
        // If it's already registered, try to unregister and register again
        if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
            prometheus.Unregister(are.ExistingCollector)
            err = prometheus.Register(collector.requestsTotal)
            if err != nil {
                log.Printf("❌ Error re-registering metrics: %v", err)
                return nil
            }
        } else {
            return nil
        }
    }
    
    log.Printf("✅ Metrics collector initialized successfully")
    return collector
}

func NewLogParser() *LogParser {
    // Updated pattern to handle the timestamp prefix and exact log format
    accessPattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z\s+(\S+)\s+"([^"]+)"\s+"[^"]+"\s+"[^"]+"\[([^\]]+)\]\s+"(\w+)\s+([^"]+)\s+HTTP/[0-9.]+"\s+.*?\s+(\d{3})\s+[a-f0-9]+$`)
    
    return &LogParser{
        accessPattern: accessPattern,
        metrics:      NewMetricsCollector(),
    }
}

func (p *LogParser) ParseLine(line string) {
    log.Printf("Attempting to parse line: %s", line)
    
    matches := p.accessPattern.FindStringSubmatch(line)
    if matches == nil {
        log.Printf("❌ Line did not match pattern")
        return
    }

    log.Printf("✅ Found matches: %#v", matches)

    // matches should now contain:
    // [0] - full match
    // [1] - sourceIP (5.134.48.221)
    // [2] - host (https://api-hyncmh.develop.dcmapis.com)
    // [3] - timestamp from brackets
    // [4] - method (POST)
    // [5] - path (/api/v1/test/request/id)
    // [6] - status (404)

    if len(matches) != 7 {
        log.Printf("❌ Wrong number of matches. Expected 7, got %d", len(matches))
        return
    }

    sourceIP := matches[1]
    host := strings.TrimPrefix(matches[2], "https://")
    host = strings.TrimPrefix(host, "http://")
    method := matches[4]
    path := matches[5]
    status := matches[6]

    log.Printf("📊 Parsed values: sourceIP=%s, host=%s, method=%s, path=%s, status=%s",
        sourceIP, host, method, path, status)

    // Validate status code
    statusCode, err := strconv.Atoi(status)
    if err != nil || statusCode < 100 || statusCode > 599 {
        log.Printf("❌ Invalid status code: %s", status)
        return
    }

    p.metrics.mutex.Lock()
    defer p.metrics.mutex.Unlock()

    // Increment the Prometheus counter
    p.metrics.requestsTotal.WithLabelValues(method, path, host, status, sourceIP).Inc()

    log.Printf("✨ Successfully updated metric - method=%s, path=%s, host=%s, status=%s, sourceIP=%s",
        method, path, host, status, sourceIP)
}

func (p *LogParser) cleanupOldEntries() {
    p.metrics.mutex.Lock()
    defer p.metrics.mutex.Unlock()

    cutoff := time.Now().Add(-1 * time.Hour)
    for key := range p.metrics.requestCount {
        parts := strings.Split(key, "_")
        if len(parts) < 6 {
            continue
        }
        timestamp := parts[5]
        t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestamp)
        if err != nil {
            continue
        }
        if t.Before(cutoff) {
            delete(p.metrics.requestCount, key)
        }
    }
}

func NewK8sClient() (*kubernetes.Clientset, error) {
    config, err := rest.InClusterConfig()
    if err != nil {
        return nil, err
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }

    return clientset, nil
}

func (p *LogParser) SetSampleRate(rate int) {
    p.sampleRate = rate
}

type LogCollector struct {
    client         *kubernetes.Clientset
    parser         *LogParser
    namespace      string
    labelSelectors []string
    stopChan       chan struct{}
}

func NewLogCollector(client *kubernetes.Clientset, parser *LogParser, namespace string, labelSelectors []string) *LogCollector {
    return &LogCollector{
        client:         client,
        parser:         parser,
        namespace:      namespace,
        labelSelectors: labelSelectors,
        stopChan:       make(chan struct{}),
    }
}

func (c *LogCollector) Start() {
    log.Printf("Starting log collector for namespace: %s", c.namespace)
    
    podStreams := make(map[string]context.CancelFunc)
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-c.stopChan:
            for _, cancel := range podStreams {
                cancel()
            }
            return
        case <-ticker.C:
            pods, err := c.client.CoreV1().Pods(c.namespace).List(context.Background(), metav1.ListOptions{
                LabelSelector: strings.Join(c.labelSelectors, ","),
            })
            if err != nil {
                log.Printf("Error listing pods: %v", err)
                continue
            }

            currentPods := make(map[string]bool)
            for _, pod := range pods.Items {
                podKey := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
                currentPods[podKey] = true
                
                if _, exists := podStreams[podKey]; !exists {
                    ctx, cancel := context.WithCancel(context.Background())
                    podStreams[podKey] = cancel
                    go c.streamPodLogs(ctx, &pod)
                }
            }
            
            // Cleanup old streams
            for podKey, cancel := range podStreams {
                if !currentPods[podKey] {
                    cancel()
                    delete(podStreams, podKey)
                }
            }
        }
    }
}

func (c *LogCollector) streamPodLogs(ctx context.Context, pod *corev1.Pod) {
    log.Printf("🔄 Starting to stream logs from pod: %s", pod.Name)

    req := c.client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
        Follow:     true,
        Timestamps: true,
    })
    
    stream, err := req.Stream(ctx)
    if err != nil {
        log.Printf("❌ Error getting log stream for pod %s: %v", pod.Name, err)
        return
    }
    defer stream.Close()
    
    log.Printf("✅ Successfully connected to pod %s log stream", pod.Name)
    
    scanner := bufio.NewScanner(stream)
    for scanner.Scan() {
        select {
        case <-ctx.Done():
            log.Printf("⏹️ Stopping log stream for pod %s", pod.Name)
            return
        default:
            line := scanner.Text()
            log.Printf("📝 Received log line from pod %s: %s", pod.Name, line)
            c.parser.ParseLine(line)
        }
    }
    
    if err := scanner.Err(); err != nil {
        log.Printf("❌ Error reading log stream for pod %s: %v", pod.Name, err)
    }
}

func (c *LogCollector) Stop() {
    close(c.stopChan)
} 