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
	"strconv"
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

// EnhancedSecurityReport represents the enhanced report format from secure-access integration
type EnhancedSecurityReport struct {
	// Attestation data (from CDH via secure-access)
	AttestationData struct {
		Status    string `json:"status"`     // "verified"/"failed"
		Timestamp string `json:"timestamp"`  // RFC3339
		Details   string `json:"details"`    // Error details if failed
	} `json:"attestation_data"`

	// mTLS access control data
	AccessControlData struct {
		MTLSEnabled   bool `json:"mtls_enabled"`    // Always true for secure-access
		CertValid     bool `json:"cert_valid"`      // TLS cert status
		ClientCAValid bool `json:"client_ca_valid"` // CA cert status
		HTTPSPort     int  `json:"https_port"`      // Port number
	} `json:"access_control_data"`

	// Pod metadata
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
	Timestamp string `json:"timestamp"`
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

// reportTTL is how long a report is considered live; older reports are excluded from API responses (no sidecar = no refresh).
var reportTTL time.Duration

// convertEnhancedToStandard converts EnhancedSecurityReport to AttestationReport format
func convertEnhancedToStandard(enhanced *EnhancedSecurityReport) (*AttestationReport, error) {
	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, enhanced.Timestamp)
	if err != nil {
		timestamp = time.Now()
	}

	// Determine if attested based on status
	attested := (enhanced.AttestationData.Status == "verified")

	// Map error details if present and status is failed
	var errorMsg string
	if !attested && enhanced.AttestationData.Details != "" {
		errorMsg = enhanced.AttestationData.Details
	}

	report := &AttestationReport{
		PodName:   enhanced.PodName,
		Namespace: enhanced.Namespace,
		TEEType:   "secure-access", // Indicate this came from secure-access sidecar
		Attested:  attested,
		Timestamp: timestamp,
		Error:     errorMsg,
	}

	// Add trust vector if attestation was successful
	if attested {
		report.TrustVector = &TrustVector{
			InstanceIdentity: 3, // Verified identity
			Configuration:    3, // Verified configuration
			Executables:      3, // Verified executables
			FileSystem:       2, // Limited verification
			Hardware:         3, // TEE hardware verified
			RuntimeOpaque:    2, // Limited runtime verification
			StorageOpaque:    2, // Limited storage verification
			SourcedData:      3, // CDH verified data
		}
	}

	return report, nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	// Check if mTLS is enabled
	enableMTLS := os.Getenv("ENABLE_MTLS") == "true"

	// Report TTL: reports older than this are excluded from GET (dashboard won't see them). Prevents showing stale reports when no sidecar is connected.
	reportTTL = 90 * time.Second
	if s := os.Getenv("REPORT_TTL_SECONDS"); s != "" {
		if sec, err := strconv.Atoi(s); err == nil && sec > 0 {
			reportTTL = time.Duration(sec) * time.Second
		}
	}
	log.Printf("Report TTL: %v (reports older than this are hidden from API)", reportTTL)

	http.HandleFunc("/api/v1/reports", handleReports)
	http.HandleFunc("/api/v1/reports/", handleReportByKey)
	http.HandleFunc("/api/v1/health", handleHealth)
	http.HandleFunc("/api/v1/ready", handleReady)

	// Start mTLS server if enabled
	if enableMTLS {
		go func() {
			if err := startMTLSServer(httpsPort); err != nil {
				log.Printf("mTLS server error: %v", err)
			}
		}()
	}

	log.Printf("Attestation Collector starting on port %s", port)
	if enableMTLS {
		log.Printf("mTLS server enabled on port %s", httpsPort)
	}
	log.Fatal(http.ListenAndServe(":"+port, corsMiddleware(http.DefaultServeMux)))
}

// startMTLSServer starts an HTTPS server with mutual TLS authentication
func startMTLSServer(port string) error {
	// Load certificates from environment-specified paths
	serverCertFile := getEnvOrDefault("SERVER_CERT_FILE", "/etc/certs/server.crt")
	serverKeyFile := getEnvOrDefault("SERVER_KEY_FILE", "/etc/certs/server.key")
	caCertFile := getEnvOrDefault("CA_CERT_FILE", "/etc/certs/ca.crt")

	// Load server certificate
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Load CA certificate for client verification
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Create TLS configuration with mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create server with mTLS
	server := &http.Server{
		Addr:      ":" + port,
		Handler:   corsMiddleware(http.DefaultServeMux),
		TLSConfig: tlsConfig,
	}

	log.Printf("mTLS server listening on :%s", port)
	return server.ListenAndServeTLS("", "")
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
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

	// Try to decode as enhanced security report first (from secure-access)
	var enhancedReport EnhancedSecurityReport
	if err := json.Unmarshal(bodyBytes, &enhancedReport); err == nil &&
		enhancedReport.AttestationData.Status != "" && enhancedReport.PodName != "" {
		// This is an enhanced security report - convert to standard format
		convertedReport, err := convertEnhancedToStandard(&enhancedReport)
		if err != nil {
			log.Printf("Enhanced report conversion error: %v", err)
			http.Error(w, fmt.Sprintf("Enhanced report conversion failed: %v", err), http.StatusBadRequest)
			return
		}
		report = *convertedReport
		verified = false // Enhanced reports are not cryptographically signed
		log.Printf("Received enhanced security report from %s/%s (status: %s)",
			report.Namespace, report.PodName, enhancedReport.AttestationData.Status)
	} else {
		// Try to decode as signed report
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
	now := time.Now()
	store.mu.RLock()
	reports := make([]AttestationReport, 0, len(store.reports))
	var expiredKeys []string
	for key, report := range store.reports {
		if reportTTL > 0 && now.Sub(report.Timestamp) > reportTTL {
			expiredKeys = append(expiredKeys, key)
		} else {
			reports = append(reports, report)
		}
	}
	store.mu.RUnlock()

	// Remove expired reports from store when TTL is enabled (reportTTL > 0)
	if reportTTL > 0 && len(expiredKeys) > 0 {
		store.mu.Lock()
		for _, key := range expiredKeys {
			delete(store.reports, key)
			delete(store.history, key)
		}
		store.mu.Unlock()
		log.Printf("Expired %d report(s) (no refresh within TTL)", len(expiredKeys))
	}

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
	if isHistory {
		history, exists := store.history[path]
		if !exists {
			store.mu.RUnlock()
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
		store.mu.RUnlock()
		return
	}

	report, exists := store.reports[path]
	if !exists {
		store.mu.RUnlock()
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if reportTTL > 0 && time.Since(report.Timestamp) > reportTTL {
		store.mu.RUnlock()
		// Remove expired report
		store.mu.Lock()
		delete(store.reports, path)
		delete(store.history, path)
		store.mu.Unlock()
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	store.mu.RUnlock()

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
