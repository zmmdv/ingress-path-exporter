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
    "net/url"

    "github.com/prometheus/client_golang/prometheus"
    "k8s.io/client-go/kubernetes"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/client-go/rest"
)

var (
    startTime = time.Now().Format(time.RFC3339)
)

// MetricsCollector holds all our metrics
type MetricsCollector struct {
    requestsTotal *prometheus.GaugeVec
    requestCount  map[string]float64  // To track counts in memory
    mutex         sync.RWMutex        // To make map operations thread-safe
}

// Create a global collector instance
var (
    collector *MetricsCollector
    once      sync.Once
)

// NewMetricsCollector creates or returns the existing metrics collector
func NewMetricsCollector() *MetricsCollector {
    collector := &MetricsCollector{
        requestsTotal: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: "nginx",
                Subsystem: "ingress",
                Name:      "requests_total",
                Help:      "Total number of HTTP requests since exporter start",
            },
            []string{"method", "path", "host", "status", "source_ip"},
        ),
        requestCount: make(map[string]float64),
    }

    // Reset counts every hour (or adjust the duration as needed)
    go func() {
        for {
            time.Sleep(1 * time.Hour)
            collector.Reset()
        }
    }()

    return collector
}

func (mc *MetricsCollector) Reset() {
    mc.mutex.Lock()
    defer mc.mutex.Unlock()
    
    // Clear the internal map
    mc.requestCount = make(map[string]float64)
    
    // Reset all metrics
    mc.requestsTotal.Reset()
}

// LogParser represents the structure for parsing Nginx log lines
type LogParser struct {
    accessPattern *regexp.Regexp
    lineCount     int
    sampleRate    int
    metrics       *MetricsCollector
}

type LogCollector struct {
    client         *kubernetes.Clientset
    parser         *LogParser
    namespace      string
    podLabels      []string
    stopChan       chan struct{}
    wg             sync.WaitGroup
}

// Initialize metrics when creating a new parser instead of init()
func NewLogParser() *LogParser {
    metrics := NewMetricsCollector()
    prometheus.DefaultRegisterer.MustRegister(metrics.requestsTotal)

    // Pattern based on the exact nginx log format
    pattern := `^(?P<remote_addr>[^ ]+) ` + // $remote_addr
        `"https://(?P<host>[^"]+)" ` + // "https://$host"
        `"OAK: [^"]+" ` + // "OAK: $sent_http_oak"
        `"Requests status: (?P<initial_status>[^"]+)"` + // "Requests status: $status"
        `\[(?P<time_local>[^\]]+)\] ` + // [$time_local]
        `"(?P<method>[^ ]+) (?P<path>[^ ]+)[^"]+" ` + // "$request"
        `(?P<remote_user>[^ ]+) ` + // $remote_user
        `(?P<body_bytes_sent>\d+) ` + // $body_bytes_sent
        `(?P<http_referer>[^ ]+) ` + // $http_referer
        `(?P<http_user_agent>[^ ]+) ` + // $http_user_agent
        `(?P<request_length>\d+) ` + // $request_length
        `(?P<request_time>[^ ]+) ` + // $request_time
        `\[(?P<proxy_upstream_name>[^\]]*)\] ` + // [$proxy_upstream_name]
        `\[(?P<proxy_alternative_upstream_name>[^\]]*)\] ` + // [$proxy_alternative_upstream_name]
        `(?P<upstream_addr>[^ ]+) ` + // $upstream_addr
        `(?P<upstream_response_length>\d+) ` + // $upstream_response_length
        `(?P<upstream_response_time>[^ ]+) ` + // $upstream_response_time
        `(?P<status>\d+) ` + // $upstream_status
        `(?P<req_id>[a-f0-9]+)$` // $req_id

    regex, err := regexp.Compile(pattern)
    if err != nil {
        log.Printf("Error compiling regex pattern: %v", err)
        return nil
    }

    log.Printf("Compiled regex pattern: %s", pattern)

    return &LogParser{
        accessPattern: regex,
        lineCount:    0,
        sampleRate:   1,
        metrics:      metrics,
    }
}

// SetSampleRate sets the sampling rate for log processing
func (p *LogParser) SetSampleRate(rate int) {
    if rate < 1 {
        rate = 1
    }
    p.sampleRate = rate
}

func (p *LogParser) extractHostFromURL(urlStr string) string {
    if urlStr == "" || urlStr == "-" {
        return ""
    }
    
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        return ""
    }
    
    if parsedURL.Host == "" {
        return ""
    }

    return strings.Split(parsedURL.Host, ":")[0]
}

// ParseLine parses a single log line and updates metrics
func (p *LogParser) ParseLine(line string) {
    // Skip processing based on sample rate
    p.lineCount++
    if p.sampleRate > 1 && p.lineCount%p.sampleRate != 0 {
        return
    }

    // Skip Kubernetes internal logs
    if len(line) > 0 && (line[0] == 'I' || line[0] == 'W' || line[0] == 'E' || line[0] == 'F') {
        return
    }

    matches := p.accessPattern.FindStringSubmatch(line)
    if matches == nil {
        log.Printf("No matches found for line: %s", line)
        return
    }

    // Create a map to store our extracted values
    values := make(map[string]string)
    
    // Extract all named groups
    for i, name := range p.accessPattern.SubexpNames() {
        if i > 0 && i < len(matches) && name != "" {
            values[name] = matches[i]
        }
    }

    // Extract required fields
    method, ok1 := values["method"]
    path, ok2 := values["path"]
    status, ok3 := values["status"]
    sourceIP, ok4 := values["remote_addr"]
    host := values["host"]

    if !ok1 || !ok2 || !ok3 || !ok4 {
        log.Printf("Missing required fields: method=%v, path=%v, status=%v, sourceIP=%v",
            ok1, ok2, ok3, ok4)
        return
    }

    // Clean the path by removing query parameters
    cleanPath := path
    if idx := strings.Index(path, "?"); idx != -1 {
        cleanPath = path[:idx]
    }

    // Clean the host (already clean as we capture without https:// prefix)
    if host == "" {
        host = "unknown"
    }

    // Create a unique key for this request
    key := fmt.Sprintf("%s_%s_%s_%s_%s", 
        method, cleanPath, host, status, sourceIP)

    // Update the count in our map
    p.metrics.mutex.Lock()
    p.metrics.requestCount[key]++
    count := p.metrics.requestCount[key]
    p.metrics.mutex.Unlock()

    // Update the gauge with the current count
    p.metrics.requestsTotal.WithLabelValues(
        method,
        cleanPath,
        host,
        status,
        sourceIP,
    ).Set(count)

    log.Printf("Updated metric - method=%s, path=%s, host=%s, status=%s, sourceIP=%s, count=%.0f",
        method, cleanPath, host, status, sourceIP, count)
}

func NewK8sClient() (*kubernetes.Clientset, error) {
    // Get in-cluster config
    config, err := rest.InClusterConfig()
    if err != nil {
        return nil, err
    }

    // Create clientset
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }

    return clientset, nil
}

func NewLogCollector(client *kubernetes.Clientset, parser *LogParser, namespace string, podLabels []string) *LogCollector {
    return &LogCollector{
        client:     client,
        parser:     parser,
        namespace:  namespace,
        podLabels:  podLabels,
        stopChan:   make(chan struct{}),
    }
}

func (c *LogCollector) Start() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-c.stopChan:
            return
        case <-ticker.C:
            c.collectLogs()
        }
    }
}

func (c *LogCollector) Stop() {
    close(c.stopChan)
    c.wg.Wait()
}

func (c *LogCollector) collectLogs() {
    for _, labelSelector := range c.podLabels {
        pods, err := c.client.CoreV1().Pods(c.namespace).List(context.TODO(), metav1.ListOptions{
            LabelSelector: labelSelector,
        })
        if err != nil {
            log.Printf("Error listing pods for selector %s: %v", labelSelector, err)
            continue
        }

        for _, pod := range pods.Items {
            c.wg.Add(1)
            go func(podName, selector string) {
                defer c.wg.Done()
                c.processPodLogs(podName)
                log.Printf("Started collecting logs from pod %s (selector: %s)", podName, selector)
            }(pod.Name, labelSelector)
        }
    }
}

func (c *LogCollector) processPodLogs(podName string) {
    req := c.client.CoreV1().Pods(c.namespace).GetLogs(podName, &corev1.PodLogOptions{
        Follow: true,
    })

    stream, err := req.Stream(context.TODO())
    if err != nil {
        log.Printf("Error opening log stream for pod %s: %v", podName, err)
        return
    }
    defer stream.Close()

    scanner := bufio.NewScanner(stream)
    for scanner.Scan() {
        select {
        case <-c.stopChan:
            return
        default:
            c.parser.ParseLine(scanner.Text())
        }
    }
} 