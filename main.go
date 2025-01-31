package main

import (
    "flag"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"

    "github.com/yourusername/nginx-log-exporter/pkg/parser"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    namespace    = flag.String("namespace", "default", "Kubernetes namespace for nginx ingress")
    podLabel     = flag.String("pod-label", "app=nginx-ingress", "Label selector for nginx pods")
    listenAddr   = flag.String("listen-address", ":9113", "Address to listen on for metrics")
    sampleRate   = flag.Int("sample-rate", 1, "Sample rate for log processing (1 = process all lines)")
)

func main() {
    flag.Parse()

    // Create new parser
    logParser, err := parser.NewLogParser(*sampleRate)
    if err != nil {
        log.Fatalf("Error creating log parser: %v", err)
    }

    // Create Kubernetes client
    k8sClient, err := parser.NewK8sClient()
    if err != nil {
        log.Fatalf("Error creating Kubernetes client: %v", err)
    }

    // Start log collector
    collector := parser.NewLogCollector(k8sClient, logParser, *namespace, *podLabel)
    go collector.Start()

    // Setup signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
    go func() {
        sig := <-sigChan
        log.Printf("Received signal %v, shutting down...", sig)
        collector.Stop()
        os.Exit(0)
    }()

    // Start metrics server
    http.Handle("/metrics", promhttp.Handler())
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("healthy"))
    })

    log.Printf("Starting metrics server on %s", *listenAddr)
    if err := http.ListenAndServe(*listenAddr, nil); err != nil {
        log.Fatalf("Error starting metrics server: %v", err)
    }
} 