package parser

import (
    "fmt"
    "log"
    "net/url"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
)

type MetricsCollector struct {
    requestsTotal *prometheus.GaugeVec
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

    prometheus.Unregister(collector.requestsTotal)
    prometheus.MustRegister(collector.requestsTotal)

    log.Printf("Metrics collector initialized at: %v", collector.startTime)
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
    if p.sampleRate > 1 && p.lineCount%p.sampleRate != 0 {
        return
    }

    if len(line) > 0 && (line[0] == 'I' || line[0] == 'W' || line[0] == 'E' || line[0] == 'F') {
        return
    }

    matches := p.accessPattern.FindStringSubmatch(line)
    if matches == nil {
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
    p.metrics.requestCount[key]++
    count := p.metrics.requestCount[key]
    p.metrics.mutex.Unlock()

    p.metrics.requestsTotal.WithLabelValues(
        method,
        cleanPath,
        host,
        status,
        sourceIP,
    ).Set(float64(count))

    log.Printf("Request logged - method=%s, path=%s, host=%s, status=%s, sourceIP=%s, count=%.0f",
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