// Attestation Collector - Aggregates TEE attestation reports from CoCo pod sidecars
// Phase 1: In-memory storage, no Rekor integration
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// TrustVector represents the EAR trust tier values
type TrustVector struct {
	InstanceIdentity int `json:"instance_identity"`
	Configuration    int `json:"configuration"`
	Executables      int `json:"executables"`
	FileSystem       int `json:"file_system"`
	Hardware         int `json:"hardware"`
	RuntimeOpaque    int `json:"runtime_opaque"`
	StorageOpaque    int `json:"storage_opaque"`
	SourcedData      int `json:"sourced_data"`
}

// AttestationReport is the report received from sidecars
type AttestationReport struct {
	PodName     string       `json:"pod_name"`
	Namespace   string       `json:"namespace"`
	TEEType     string       `json:"tee_type,omitempty"`
	Attested    bool         `json:"attested"`
	TrustVector *TrustVector `json:"trust_vector,omitempty"`
	EARToken    string       `json:"ear_token,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
	Error       string       `json:"error,omitempty"`
}

// Store holds attestation reports in memory
type Store struct {
	mu      sync.RWMutex
	reports map[string]AttestationReport // key: namespace/podname
	history map[string][]AttestationReport // historical reports per pod
}

var store = &Store{
	reports: make(map[string]AttestationReport),
	history: make(map[string][]AttestationReport),
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/api/v1/reports", handleReports)
	http.HandleFunc("/api/v1/reports/", handleReportByKey)
	http.HandleFunc("/api/v1/health", handleHealth)
	http.HandleFunc("/api/v1/ready", handleReady)

	log.Printf("Attestation Collector starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, corsMiddleware(http.DefaultServeMux)))
}

// CORS middleware for dashboard access
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// POST /api/v1/reports - receive report from sidecar
// GET /api/v1/reports - list all current reports
func handleReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handlePostReport(w, r)
	case http.MethodGet:
		handleGetReports(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePostReport(w http.ResponseWriter, r *http.Request) {
	var report AttestationReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if report.PodName == "" || report.Namespace == "" {
		http.Error(w, "pod_name and namespace are required", http.StatusBadRequest)
		return
	}

	// Set timestamp if not provided
	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now()
	}

	key := report.Namespace + "/" + report.PodName

	store.mu.Lock()
	store.reports[key] = report
	// Keep last 100 reports in history
	history := store.history[key]
	history = append(history, report)
	if len(history) > 100 {
		history = history[1:]
	}
	store.history[key] = history
	store.mu.Unlock()

	log.Printf("Received report: %s attested=%v", key, report.Attested)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "key": key})
}

func handleGetReports(w http.ResponseWriter, r *http.Request) {
	store.mu.RLock()
	reports := make([]AttestationReport, 0, len(store.reports))
	for _, report := range store.reports {
		reports = append(reports, report)
	}
	store.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reports)
}

// GET /api/v1/reports/{namespace}/{podname} - get specific report
// GET /api/v1/reports/{namespace}/{podname}/history - get history
// DELETE /api/v1/reports/{namespace}/{podname} - delete a report
func handleReportByKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /api/v1/reports/{namespace}/{podname}[/history]
	path := r.URL.Path[len("/api/v1/reports/"):]

	// Check if requesting history
	isHistory := false
	if len(path) > 8 && path[len(path)-8:] == "/history" {
		isHistory = true
		path = path[:len(path)-8]
	}

	// Handle DELETE request
	if r.Method == http.MethodDelete {
		store.mu.Lock()
		defer store.mu.Unlock()

		if _, exists := store.reports[path]; !exists {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		delete(store.reports, path)
		delete(store.history, path)
		log.Printf("Deleted report: %s", path)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	if isHistory {
		history, exists := store.history[path]
		if !exists {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
		return
	}

	report, exists := store.reports[path]
	if !exists {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}
