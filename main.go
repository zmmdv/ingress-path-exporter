package main

import (
    "flag"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"

    "nginx-log-exporter/pkg/parser"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    // Parse command line flags
    namespace := flag.String("namespace", "default", "Kubernetes namespace for nginx ingress")
    podLabels := flag.String("pod-labels", "app=nginx-ingress", "Comma-separated list of label selectors for nginx pods (e.g., 'app=nginx-1,app=nginx-2')")
    listenAddr := flag.String("listen-address", ":9113", "Address to listen on for metrics")
    flag.Parse()

    // Split pod labels into slice
    labelSelectors := strings.Split(*podLabels, ",")
    for i, selector := range labelSelectors {
        labelSelectors[i] = strings.TrimSpace(selector)
    }

    // Create log parser
    logParser, err := parser.NewLogParser()
    if err != nil {
        log.Fatalf("Error creating log parser: %v", err)
    }

    // Create Kubernetes client
    k8sClient, err := parser.NewK8sClient()
    if err != nil {
        log.Fatalf("Error creating K8s client: %v", err)
    }

    // Start log collector
    collector := parser.NewLogCollector(k8sClient, logParser, *namespace, labelSelectors)
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