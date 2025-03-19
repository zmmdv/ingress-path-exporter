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
    prometheus.MustRegister(collector.requestsTotal)
    
    return collector
}

func NewLogParser() *LogParser {
    accessPattern := regexp.MustCompile(`^(\S+)\s+"([^"]+)"\s+"[^"]+"\s+"[^"]+"\[([^\]]+)\]\s+"(\w+)\s+([^"]+)\s+HTTP/[0-9.]+"\s+.*\s+(\d{3})\s+[a-f0-9]+$`)
    
    return &LogParser{
        accessPattern: accessPattern,
        metrics:      NewMetricsCollector(),
    }
}

func (p *LogParser) ParseLine(line string) {
    log.Printf("Processing line: %s", line)
    
    matches := p.accessPattern.FindStringSubmatch(line)
    if matches == nil {
        log.Printf("Line did not match pattern: %s", line)
        return
    }

    for i, match := range matches {
        log.Printf("Match[%d]: %s", i, match)
    }

    sourceIP := matches[1]
    host := strings.TrimPrefix(matches[2], "https://")
    host = strings.TrimPrefix(host, "http://")
    method := matches[4]
    path := matches[5]
    status := matches[6]

    statusCode, err := strconv.Atoi(status)
    if err != nil || statusCode < 100 || statusCode > 599 {
        log.Printf("Invalid status code: %s", status)
        return
    }

    timestamp := matches[3]
    key := fmt.Sprintf("%s_%s_%s_%s_%s_%s", method, path, host, status, sourceIP, timestamp)

    p.metrics.mutex.Lock()
    defer p.metrics.mutex.Unlock()

    if _, exists := p.metrics.requestCount[key]; exists {
        return
    }

    p.metrics.requestCount[key] = 1

    p.metrics.requestsTotal.WithLabelValues(method, path, host, status, sourceIP).Inc()

    log.Printf("Updated metric - method=%s, path=%s, host=%s, status=%s, sourceIP=%s, count=1",
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
    sinceSeconds := int64(60) // Only get last minute of logs
    req := c.client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
        Follow:       true,
        SinceSeconds: &sinceSeconds,
        Timestamps:   true,
    })
    
    stream, err := req.Stream(ctx)
    if err != nil {
        log.Printf("Error getting log stream for pod %s: %v", pod.Name, err)
        return
    }
    defer stream.Close()
    
    scanner := bufio.NewScanner(stream)
    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return
        default:
            c.parser.ParseLine(scanner.Text())
        }
    }
}

func (c *LogCollector) Stop() {
    close(c.stopChan)
} 