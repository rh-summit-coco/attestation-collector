// Attestation Collector - Aggregates TEE attestation reports from CoCo pod sidecars
// Phase 1: In-memory storage, no Rekor integration
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
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

// SignedAttestationReport wraps the report with cryptographic signature
type SignedAttestationReport struct {
	Report    AttestationReport `json:"report"`
	Signature string           `json:"signature"`
	PublicKey string           `json:"public_key_pem"`
	Algorithm string           `json:"algorithm"`
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
	// Read the body
	bodyBytes := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			bodyBytes = append(bodyBytes, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	r.Body.Close()

	var report AttestationReport
	var verified bool = false

	// Try to decode as signed report first
	var signedReport SignedAttestationReport
	if err := json.Unmarshal(bodyBytes, &signedReport); err == nil &&
		signedReport.Signature != "" && signedReport.PublicKey != "" {
		// This is a signed report
		valid, err := verifySignedAttestationReport(&signedReport)
		if err != nil {
			log.Printf("Signature verification error: %v", err)
			http.Error(w, fmt.Sprintf("Signature verification failed: %v", err), http.StatusBadRequest)
			return
		}

		if !valid {
			log.Printf("Invalid signature for report from %s/%s", signedReport.Report.Namespace, signedReport.Report.PodName)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		report = signedReport.Report
		verified = true
		log.Printf("Signature verified for %s/%s", report.Namespace, report.PodName)
	} else {
		// Try as plain report (backward compatibility)
		if err := json.Unmarshal(bodyBytes, &report); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		log.Printf("Warning: Received unsigned report from %s/%s", report.Namespace, report.PodName)
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

	status := "unsigned"
	if verified {
		status = "verified"
	}

	log.Printf("Received %s report: %s attested=%v", status, key, report.Attested)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"key":      key,
		"verified": fmt.Sprintf("%v", verified),
	})
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

// Security functions for mTLS and signed report verification

// createMTLSServer creates an HTTPS server with mutual TLS
func createMTLSServer(addr string, serverCert, serverKey, caCert []byte) (*httptest.Server, error) {
	// Load server certificate
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Load CA certificate for client verification
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Create a new ServeMux with our routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports", handleReports)
	mux.HandleFunc("/api/v1/reports/", handleReportByKey)
	mux.HandleFunc("/api/v1/health", handleHealth)
	mux.HandleFunc("/api/v1/ready", handleReady)

	// Create server with mTLS configuration
	server := httptest.NewUnstartedServer(corsMiddleware(mux))

	// Configure TLS with mutual authentication
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Start the server
	server.StartTLS()

	return server, nil
}

// verifySignedAttestationReport verifies a signed attestation report
func verifySignedAttestationReport(signedReport *SignedAttestationReport) (bool, error) {
	// Check if signature exists
	if signedReport.Signature == "" || signedReport.PublicKey == "" {
		return false, fmt.Errorf("missing signature or public key")
	}

	// Check algorithm
	if signedReport.Algorithm != "RS256" {
		return false, fmt.Errorf("unsupported algorithm: %s", signedReport.Algorithm)
	}

	// Parse public key
	publicKey, err := parsePublicKeyFromPEM(signedReport.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Serialize report for verification
	reportJSON, err := json.Marshal(signedReport.Report)
	if err != nil {
		return false, fmt.Errorf("failed to serialize report: %v", err)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signedReport.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Verify signature
	hash := sha256.Sum256(reportJSON)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return false, nil // Invalid signature, but no error
	}

	return true, nil
}

// parsePublicKeyFromPEM parses PEM-encoded RSA public key
func parsePublicKeyFromPEM(keyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}
