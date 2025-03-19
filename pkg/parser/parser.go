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
    "os"
    "os/signal"
    "syscall"

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
    requestCount  map[string]float64
    mutex         sync.RWMutex
    startTime     time.Time
}

// Create a global collector instance
var (
    collector *MetricsCollector
    once      sync.Once
)

// NewMetricsCollector creates or returns the existing metrics collector
func NewMetricsCollector() *MetricsCollector {
    // Create new collector
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
        startTime:   time.Now(),
    }

    // Unregister any existing metrics with the same name
    prometheus.Unregister(collector.requestsTotal)
    
    // Register the new metrics
    prometheus.MustRegister(collector.requestsTotal)

    log.Printf("Metrics collector initialized at: %v", collector.startTime)
    return collector
}

func (mc *MetricsCollector) Reset() {
    mc.mutex.Lock()
    defer mc.mutex.Unlock()
    
    // Clear all existing metrics
    mc.requestsTotal.Reset()
    
    // Reset the counter map
    mc.requestCount = make(map[string]float64)
    
    // Update start time
    mc.startTime = time.Now()
    
    log.Printf("Metrics reset at: %v", mc.startTime)
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
    // Create metrics collector
    metrics := NewMetricsCollector()
    
    // Create and compile regex pattern
    accessPattern := `^(?P<remote_addr>[^ ]+) "https://(?P<host>[^"]+)" "OAK: [^"]+" "Requests status: [^"]+"\[(?P<timestamp>[^\]]+)\] "(?P<method>[^ ]+) (?P<path>[^ ]+)[^"]+" [^ ]+ \d+ [^ ]+ [^ ]+ \d+ [^ ]+ \[[^\]]+\] \[[^\]]+\] [^ ]+ \d+ [^ ]+ (?P<status>\d+)`
    
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

    // Create a unique key for this request
    key := fmt.Sprintf("%s_%s_%s_%s_%s", 
        method, cleanPath, host, status, sourceIP)

    p.metrics.mutex.Lock()
    // Increment the count
    p.metrics.requestCount[key]++
    count := p.metrics.requestCount[key]
    p.metrics.mutex.Unlock()

    // Set the gauge to the current count
    p.metrics.requestsTotal.WithLabelValues(
        method,
        cleanPath,
        host,
        status,
        sourceIP,
    ).Set(float64(count))

    log.Printf("Request logged - method=%s, path=%s, host=%s, status=%s, sourceIP=%s, current_count=%.0f",
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

func main() {
    // ... existing code ...

    // Create metrics collector
    metricsCollector := NewMetricsCollector()
    
    // Create log parser with the metrics collector
    logParser := NewLogParser()
    
    // Reset metrics on SIGHUP
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGHUP)
    go func() {
        for {
            <-sigChan
            log.Println("Received SIGHUP, resetting metrics...")
            metricsCollector.Reset()
        }
    }()

    // ... rest of your main function ...
} 