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

    "github.com/prometheus/client_golang/prometheus"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    corev1 "k8s.io/api/core/v1"
)

var (
    // Metrics collectors
    requestCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "nginx_ingress_requests_total",
            Help: "Number of HTTP requests",
        },
        []string{"method", "status", "path", "source_ip"},
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
    prometheus.MustRegister(requestCounter)
    prometheus.MustRegister(requestDuration)
    prometheus.MustRegister(backendLatency)
    prometheus.MustRegister(statusCodeCounter)
    prometheus.MustRegister(methodCounter)
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
    pattern := `^(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>[^\"]+)" (?P<status>\d+) (?P<response_size>\d+) "(?P<referrer>[^\"]*)" "(?P<user_agent>[^\"]*)" (?P<request_size>\d+) (?P<request_time>\d+\.\d+) \[(?P<backend>[^\]]+)\]`
    
    return &LogParser{
        pattern:    regexp.MustCompile(pattern),
        lineCount:  0,
        sampleRate: 1, // Default to processing every line
    }
}

// SetSampleRate sets the sampling rate for log processing
func (p *LogParser) SetSampleRate(rate int) {
    if rate < 1 {
        rate = 1
    }
    p.sampleRate = rate
}

// ParseLine parses a single log line and updates metrics
func (p *LogParser) ParseLine(line string) {
    p.lineCount++
    if p.sampleRate > 1 && p.lineCount%p.sampleRate != 0 {
        return
    }

    matches := p.pattern.FindStringSubmatch(line)
    if matches == nil {
        return
    }

    groups := make(map[string]string)
    for i, name := range p.pattern.SubexpNames() {
        if i != 0 && name != "" {
            groups[name] = matches[i]
        }
    }

    method := groups["method"]
    status := groups["status"]
    path := groups["path"]
    sourceIP := groups["ip"]  // Get source IP from log
    backend := groups["backend"]

    // Clean path by removing query parameters
    if idx := strings.Index(path, "?"); idx != -1 {
        path = path[:idx]
    }

    // Update metrics with source IP
    requestCounter.WithLabelValues(method, status, path, sourceIP).Inc()
    methodCounter.WithLabelValues(method).Inc()
    statusCodeCounter.WithLabelValues(status, method).Inc()

    if duration, err := strconv.ParseFloat(groups["request_time"], 64); err == nil {
        requestDuration.WithLabelValues(method, status, path).Observe(duration)
        backendLatency.WithLabelValues(backend).Observe(duration)
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