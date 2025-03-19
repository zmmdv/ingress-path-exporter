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
    "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/api/meta"
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
    metrics := NewMetricsCollector()
    
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

func (p *LogParser) ParseLine(line string) {
    log.Printf("Parsing line: %s", line) // Debug log
    
    p.lineCount++
    if p.sampleRate > 1 && p.lineCount%p.sampleRate != 0 {
        return
    }

    if len(line) > 0 && (line[0] == 'I' || line[0] == 'W' || line[0] == 'E' || line[0] == 'F') {
        return
    }

    matches := p.accessPattern.FindStringSubmatch(line)
    if matches == nil {
        log.Printf("Line did not match pattern: %s", line) // Debug log
        return
    }

    values := make(map[string]string)
    for i, name := range p.accessPattern.SubexpNames() {
        if i > 0 && i < len(matches) && name != "" {
            values[name] = matches[i]
        }
    }

    method, ok1 := values["method"]
    path, ok2 := values["path"]
    status, ok3 := values["status"]
    sourceIP, ok4 := values["remote_addr"]
    host := values["host"]

    if !ok1 || !ok2 || !ok3 || !ok4 {
        return
    }

    cleanPath := path
    if idx := strings.Index(path, "?"); idx != -1 {
        cleanPath = path[:idx]
    }

    key := fmt.Sprintf("%s_%s_%s_%s_%s", 
        method, cleanPath, host, status, sourceIP)

    p.metrics.mutex.Lock()
    defer p.metrics.mutex.Unlock()
    
    p.metrics.requestCount[key]++
    count := p.metrics.requestCount[key]

    p.metrics.requestsTotal.WithLabelValues(
        method,
        cleanPath,
        host,
        status,
        sourceIP,
    ).Inc()

    log.Printf("Updated metric - method=%s, path=%s, host=%s, status=%s, sourceIP=%s, count=%.0f",
        method, cleanPath, host, status, sourceIP, count)
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
    log.Printf("Starting log collector for namespace: %s", c.namespace) // Debug log
    
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
            
            log.Printf("Found %d pods matching selectors", len(pods.Items)) // Debug log
            
            for _, pod := range pods.Items {
                go c.streamPodLogs(&pod)
            }
            
            // Wait before checking for new pods
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
    
    log.Printf("Started streaming logs from pod: %s", pod.Name) // Debug log
    
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