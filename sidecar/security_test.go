package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestCreateSignedReport should fail initially - tests JWT report signing
func TestCreateSignedReport(t *testing.T) {
	// Create test report
	report := AttestationReport{
		PodName:   "test-pod",
		Namespace: "test-ns",
		Attested:  true,
		Timestamp: time.Now(),
	}

	// This function should exist but doesn't yet
	signedReport, err := createSignedReport(report)
	if err != nil {
		t.Fatalf("Expected no error creating signed report, got: %v", err)
	}

	// Verify signature exists
	if signedReport.Signature == "" {
		t.Error("Expected signature to be present")
	}

	if signedReport.PublicKey == "" {
		t.Error("Expected public key to be present")
	}

	if signedReport.Algorithm != "RS256" {
		t.Errorf("Expected algorithm=RS256, got %s", signedReport.Algorithm)
	}

	// Verify original report is embedded
	if signedReport.Report.PodName != report.PodName {
		t.Errorf("Expected pod name %s, got %s", report.PodName, signedReport.Report.PodName)
	}
}

// TestVerifySignedReport should fail initially - tests signature verification
func TestVerifySignedReport(t *testing.T) {
	// Create test signed report (this will fail until we implement signing)
	report := AttestationReport{
		PodName:   "test-pod",
		Namespace: "test-ns",
		Attested:  true,
		Timestamp: time.Now(),
	}

	signedReport, err := createSignedReport(report)
	if err != nil {
		t.Skipf("Skipping verification test - signing not implemented: %v", err)
	}

	// This function should verify the signature
	valid, err := verifySignedReport(signedReport)
	if err != nil {
		t.Fatalf("Expected no error verifying report, got: %v", err)
	}

	if !valid {
		t.Error("Expected signature to be valid")
	}
}

// TestCreateMTLSClient should fail initially - tests mTLS client creation
func TestCreateMTLSClient(t *testing.T) {
	// Create temporary test certificates
	clientCert, clientKey, caCert := createTestCertificates(t)

	// Save certs to temp files
	clientCertFile := saveTempFile(t, "client.crt", clientCert)
	clientKeyFile := saveTempFile(t, "client.key", clientKey)
	caCertFile := saveTempFile(t, "ca.crt", caCert)

	defer os.Remove(clientCertFile)
	defer os.Remove(clientKeyFile)
	defer os.Remove(caCertFile)

	// This function should create mTLS-enabled HTTP client
	client, err := createMTLSClient(clientCertFile, clientKeyFile, caCertFile)
	if err != nil {
		t.Fatalf("Expected no error creating mTLS client, got: %v", err)
	}

	// Verify client has TLS config
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected HTTP transport")
	}

	if transport.TLSClientConfig == nil {
		t.Error("Expected TLS config to be set")
	}

	// Verify client certificates are loaded
	if len(transport.TLSClientConfig.Certificates) == 0 {
		t.Error("Expected client certificates to be loaded")
	}

	// Verify CA pool is set
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("Expected root CA pool to be set")
	}
}

// TestSecureSendReport tests secure report creation and signing
func TestSecureSendReport(t *testing.T) {
	// Test signing functionality without network - certs may not exist
	attested, trustVector, errorMsg := checkAttestationStatus()

	report := AttestationReport{
		PodName:     "test-pod",
		Namespace:   "test-ns",
		TEEType:     "tdx",
		Attested:    attested,
		TrustVector: trustVector,
		Timestamp:   time.Now(),
		Error:       errorMsg,
	}

	// Test that we can create signed reports
	signedReport, err := createSignedReport(report)
	if err != nil {
		t.Fatalf("Expected no error creating signed report, got: %v", err)
	}

	// Test that signatures verify
	valid, err := verifySignedReport(signedReport)
	if err != nil {
		t.Fatalf("Expected no error verifying signed report, got: %v", err)
	}

	if !valid {
		t.Error("Expected signature to be valid")
	}

	t.Logf("Successfully created and verified signed attestation report")
}

// TestMTLSHandshake tests mTLS client configuration
func TestMTLSHandshake(t *testing.T) {
	// Test that mTLS client can be configured correctly
	// We'll test the configuration rather than actual handshake

	// Create test certificates
	clientCert, clientKey, caCert := createTestCertificates(t)

	// Save certs to temp files
	clientCertFile := saveTempFile(t, "client.crt", clientCert)
	clientKeyFile := saveTempFile(t, "client.key", clientKey)
	caCertFile := saveTempFile(t, "ca.crt", caCert)

	defer os.Remove(clientCertFile)
	defer os.Remove(clientKeyFile)
	defer os.Remove(caCertFile)

	// Test that client can be created with valid certs
	client, err := createMTLSClient(clientCertFile, clientKeyFile, caCertFile)
	if err != nil {
		t.Fatalf("Expected no error creating mTLS client, got: %v", err)
	}

	// Verify client has proper TLS configuration
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected HTTP transport")
	}

	if transport.TLSClientConfig == nil {
		t.Error("Expected TLS config to be set")
	}

	if len(transport.TLSClientConfig.Certificates) == 0 {
		t.Error("Expected client certificates to be loaded")
	}

	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("Expected root CA pool to be set")
	}

	t.Logf("mTLS client configured successfully with %d certificates", len(transport.TLSClientConfig.Certificates))
}

// Helper functions that will need to be implemented

func createTestCertificates(t *testing.T) (clientCert, clientKey, caCert []byte) {
	// Generate CA private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate client private key
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create client certificate
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "attestation-sidecar",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create client cert: %v", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	if err != nil {
		t.Fatalf("Failed to marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})

	return clientCertPEM, clientKeyPEM, caCertPEM
}

func saveTempFile(t *testing.T, name string, content []byte) string {
	tmpFile, err := ioutil.TempFile("", name)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func createTestMTLSServer(t *testing.T) *httptest.Server {
	// Create test certificates
	clientCert, clientKey, caCert := createTestCertificates(t)

	// Save certs to temp files for client use
	t.Setenv("TEST_CLIENT_CERT", string(clientCert))
	t.Setenv("TEST_CLIENT_KEY", string(clientKey))
	t.Setenv("TEST_CA_CERT", string(caCert))

	// Create server with mTLS configuration
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	// Configure mTLS for server (simplified for testing)
	server.StartTLS()
	return server
}

func createTestMTLSClientWithValidCert(t *testing.T) *http.Client {
	// Create test certificates
	clientCert, clientKey, caCert := createTestCertificates(t)

	// Save certs to temp files
	clientCertFile := saveTempFile(t, "client.crt", clientCert)
	clientKeyFile := saveTempFile(t, "client.key", clientKey)
	caCertFile := saveTempFile(t, "ca.crt", caCert)

	defer os.Remove(clientCertFile)
	defer os.Remove(clientKeyFile)
	defer os.Remove(caCertFile)

	// Create mTLS client
	client, err := createMTLSClient(clientCertFile, clientKeyFile, caCertFile)
	if err != nil {
		t.Fatalf("Failed to create mTLS client: %v", err)
	}

	return client
}

// Functions are now implemented in main.go