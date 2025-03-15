package parser

import (
    "bufio"
    "context"
    "log"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"
    "net/url"

    "github.com/prometheus/client_golang/prometheus"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    corev1 "k8s.io/api/core/v1"
    promauto "github.com/prometheus/client_golang/prometheus"
)

var (
    // Metrics collectors
    requestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "nginx_ingress_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "path", "host", "status", "source_ip"},
    )

    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "nginx_ingress_request_duration_seconds",
            Help:    "Request duration in seconds",
            Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
        },
        []string{"method", "status", "path"},
    )

    backendLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "nginx_ingress_backend_latency_seconds",
            Help:    "Backend latency in seconds",
            Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
        },
        []string{"backend_service"},
    )

    statusCodeCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "nginx_ingress_status_codes_total",
            Help: "Number of requests by HTTP status code",
        },
        []string{"status", "method"},
    )

    methodCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "nginx_ingress_http_methods_total",
            Help: "Number of requests by HTTP method",
        },
        []string{"method"},
    )
)

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(requestsTotal)
    prometheus.MustRegister(requestDuration)
    prometheus.MustRegister(backendLatency)
    prometheus.MustRegister(statusCodeCounter)
    prometheus.MustRegister(methodCounter)

    // Move the metrics initialization here
    requestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "nginx_ingress_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "path", "host", "status", "source_ip"},
    )
}

// LogParser represents the structure for parsing Nginx log lines
type LogParser struct {
    pattern    *regexp.Regexp
    lineCount  int
    sampleRate int
}

type LogCollector struct {
    client         *kubernetes.Clientset
    parser         *LogParser
    namespace      string
    podLabels      []string
    stopChan       chan struct{}
    wg             sync.WaitGroup
}

// NewLogParser creates a new LogParser instance
func NewLogParser() *LogParser {
    // Updated pattern to better match Nginx ingress log format
    pattern := `^(?P<remote_addr>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>[^"]+) HTTP/[0-9.]+" (?P<status>\d+) \d+ "(?P<referrer>[^"]*)" "[^"]*" \d+ \d+\.\d+ \[[^\]]+\] \[[^\]]+\] \S+ \d+ \d+\.\d+ (?P<status2>\d+)`

    regex, err := regexp.Compile(pattern)
    if err != nil {
        log.Printf("Error compiling regex pattern: %v", err)
        return nil
    }

    return &LogParser{
        pattern:    regex,
        lineCount:  0,
        sampleRate: 1,
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
    
    // Remove any port number and protocol
    return strings.Split(parsedURL.Host, ":")[0]
}

// ParseLine parses a single log line and updates metrics
func (p *LogParser) ParseLine(line string) {
    // Skip processing based on sample rate
    p.lineCount++
    if p.sampleRate > 1 && p.lineCount%p.sampleRate != 0 {
        return
    }

    matches := p.pattern.FindStringSubmatch(line)
    if matches == nil {
        log.Printf("No matches found for line: %s", line)
        return
    }

    // Safely get indices first
    methodIdx := p.pattern.SubexpIndex("method")
    pathIdx := p.pattern.SubexpIndex("path")
    statusIdx := p.pattern.SubexpIndex("status")
    sourceIPIdx := p.pattern.SubexpIndex("remote_addr")
    referrerIdx := p.pattern.SubexpIndex("referrer")

    // Validate indices
    if methodIdx < 0 || pathIdx < 0 || statusIdx < 0 || sourceIPIdx < 0 || referrerIdx < 0 {
        log.Printf("Invalid regex capture groups. Indices: method=%d, path=%d, status=%d, sourceIP=%d, referrer=%d",
            methodIdx, pathIdx, statusIdx, sourceIPIdx, referrerIdx)
        return
    }

    // Safely access matches with bounds checking
    if len(matches) <= methodIdx || len(matches) <= pathIdx || 
       len(matches) <= statusIdx || len(matches) <= sourceIPIdx || 
       len(matches) <= referrerIdx {
        log.Printf("Matches array too short. Length: %d, Required indices: method=%d, path=%d, status=%d, sourceIP=%d, referrer=%d",
            len(matches), methodIdx, pathIdx, statusIdx, sourceIPIdx, referrerIdx)
        return
    }

    method := matches[methodIdx]
    path := matches[pathIdx]
    status := matches[statusIdx]
    sourceIP := matches[sourceIPIdx]
    referrer := matches[referrerIdx]

    // Extract host from referrer
    host := p.extractHostFromURL(referrer)
    if host == "" {
        // If no referrer, try to extract from the path if it's an absolute URL
        if strings.HasPrefix(path, "http") {
            host = p.extractHostFromURL(path)
        } else {
            host = "unknown"
        }
    }

    // Clean the path by removing query parameters if needed
    cleanPath := path
    if idx := strings.Index(path, "?"); idx != -1 {
        cleanPath = path[:idx]
    }

    // Log successful parsing
    log.Printf("Parsed log: method=%s, path=%s, host=%s, status=%s, sourceIP=%s",
        method, cleanPath, host, status, sourceIP)

    // Increment the counter with the extracted host
    requestsTotal.WithLabelValues(method, cleanPath, host, status, sourceIP).Inc()
    methodCounter.WithLabelValues(method).Inc()
    statusCodeCounter.WithLabelValues(status, method).Inc()

    if duration, err := strconv.ParseFloat(matches[p.pattern.SubexpIndex("request_time")], 64); err == nil {
        requestDuration.WithLabelValues(method, status, path).Observe(duration)
        backendLatency.WithLabelValues(host).Observe(duration)
    }
}

func NewK8sClient() (*kubernetes.Clientset, error) {
    config, err := rest.InClusterConfig()
    if err != nil {
        return nil, err
    }
    return kubernetes.NewForConfig(config)
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