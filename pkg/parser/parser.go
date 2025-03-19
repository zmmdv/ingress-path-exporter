package parser

import (
    "bufio"
    "context"
    "fmt"
    "log"
    "regexp"
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
    accessPattern := regexp.MustCompile(`^(\S+)\s+"([^"]+)"\s+"[^"]+"\s+"[^"]+"\[([^\]]+)\]\s+"(\w+)\s+([^"]+)\s+HTTP/[0-9.]+"\s+.*?\s+(\d{3})\s+.*$`)
    
    return &LogParser{
        accessPattern: accessPattern,
        metrics:      NewMetricsCollector(),
    }
}

func (p *LogParser) ParseLine(line string) {
    matches := p.accessPattern.FindStringSubmatch(line)
    if matches == nil {
        log.Printf("Line did not match pattern: %s", line)
        return
    }

    // The matches should now contain:
    // matches[1] = sourceIP (5.134.48.221)
    // matches[2] = host (https://api-hyncmh.develop.dcmapis.com)
    // matches[3] = timestamp (19/Mar/2025:14:05:03 +0000)
    // matches[4] = method (POST)
    // matches[5] = path (/api/v1/test/request/id)
    // matches[6] = status (404)

    sourceIP := matches[1]
    host := strings.TrimPrefix(matches[2], "https://")
    host = strings.TrimPrefix(host, "http://")
    method := matches[4]
    path := matches[5]
    status := matches[6]

    // Create a unique key for this request
    key := fmt.Sprintf("%s_%s_%s_%s_%s", method, path, host, status, sourceIP)

    p.metrics.mutex.Lock()
    defer p.metrics.mutex.Unlock()

    // Update the count in the map
    p.metrics.requestCount[key]++

    // Increment the Prometheus counter
    p.metrics.requestsTotal.WithLabelValues(method, path, host, status, sourceIP).Inc()

    log.Printf("Updated metric - method=%s, path=%s, host=%s, status=%s, sourceIP=%s, count=%.0f",
        method, path, host, status, sourceIP, p.metrics.requestCount[key])
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
    
    for {
        select {
        case <-c.stopChan:
            log.Println("Stopping log collector")
            return
        default:
            pods, err := c.client.CoreV1().Pods(c.namespace).List(context.Background(), metav1.ListOptions{
                LabelSelector: strings.Join(c.labelSelectors, ","),
            })
            if err != nil {
                log.Printf("Error listing pods: %v", err)
                time.Sleep(5 * time.Second)
                continue
            }
            
            log.Printf("Found %d pods matching selectors", len(pods.Items))
            
            for _, pod := range pods.Items {
                go c.streamPodLogs(&pod)
            }
            
            time.Sleep(30 * time.Second)
        }
    }
}

func (c *LogCollector) streamPodLogs(pod *corev1.Pod) {
    req := c.client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
        Follow: true,
    })
    
    stream, err := req.Stream(context.Background())
    if err != nil {
        log.Printf("Error getting log stream for pod %s: %v", pod.Name, err)
        return
    }
    defer stream.Close()
    
    log.Printf("Started streaming logs from pod: %s", pod.Name)
    
    scanner := bufio.NewScanner(stream)
    for scanner.Scan() {
        c.parser.ParseLine(scanner.Text())
    }
    
    if err := scanner.Err(); err != nil {
        log.Printf("Error reading log stream for pod %s: %v", pod.Name, err)
    }
}

func (c *LogCollector) Stop() {
    close(c.stopChan)
} 