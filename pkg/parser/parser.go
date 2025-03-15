package parser

import (
    "bufio"
    "context"
    "log"
    "regexp"
    "strings"
    "sync"
    "time"
    "net/url"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "k8s.io/client-go/kubernetes"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/client-go/rest"
)

// MetricsCollector holds all our metrics
type MetricsCollector struct {
    requestsTotal *prometheus.CounterVec
}

// Create a global collector instance
var (
    collector *MetricsCollector
    once      sync.Once
)

// NewMetricsCollector creates or returns the existing metrics collector
func NewMetricsCollector() *MetricsCollector {
    once.Do(func() {
        collector = &MetricsCollector{
            requestsTotal: prometheus.NewCounterVec(
                prometheus.CounterOpts{
                    Namespace: "nginx",
                    Subsystem: "ingress",
                    Name:      "requests_total",
                    Help:      "Total number of HTTP requests",
                },
                []string{"method", "path", "host", "status", "source_ip"},
            ),
        }
    })
    return collector
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
    // Create or get the metrics collector
    metrics := NewMetricsCollector()
    
    // Register metrics only if they haven't been registered
    prometheus.DefaultRegisterer.MustRegister(metrics.requestsTotal)

    // Create and compile regex pattern
    accessPattern := `^(?P<remote_addr>[^ ]+) [^ ]+ [^ ]+ \[(?P<timestamp>[^\]]+)\] "(?P<method>[^ ]+) (?P<path>[^ ]+) HTTP/[^"]+" (?P<status>\d+) (?P<bytes>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)".*$`
    
    regex, err := regexp.Compile(accessPattern)
    if err != nil {
        log.Printf("Error compiling regex pattern: %v", err)
        return nil
    }

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

    // Extract and validate required fields
    method, ok1 := values["method"]
    path, ok2 := values["path"]
    status, ok3 := values["status"]
    sourceIP, ok4 := values["remote_addr"]
    referrer := values["referrer"]

    if !ok1 || !ok2 || !ok3 || !ok4 {
        log.Printf("Missing required fields in log line")
        return
    }

    // Clean the path by removing query parameters
    cleanPath := path
    if idx := strings.Index(path, "?"); idx != -1 {
        cleanPath = path[:idx]
    }

    // Extract host from referrer
    host := p.extractHostFromURL(referrer)
    if host == "" {
        host = "unknown"
    }

    // Use metrics from the parser instance
    p.metrics.requestsTotal.WithLabelValues(
        method,
        cleanPath,
        host,
        status,
        sourceIP,
    ).Inc()
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