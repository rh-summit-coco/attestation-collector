package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// SignedAttestationReport is now defined in main.go

// TestMTLSServerSetup should fail initially - tests mTLS server configuration
func TestMTLSServerSetup(t *testing.T) {
	// Create test certificates
	serverCert, serverKey, caCert := createTestCertificatesForServer(t)

	// This function should create an mTLS-enabled HTTP server
	server, err := createMTLSServer(":0", serverCert, serverKey, caCert)
	if err != nil {
		t.Fatalf("Expected no error creating mTLS server, got: %v", err)
	}
	defer server.Close()

	// Server should require client certificates
	if server.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("Expected server to require client certificates")
	}

	// Server should have CA pool configured
	if server.TLS.ClientCAs == nil {
		t.Error("Expected server to have client CA pool configured")
	}
}

// TestVerifySignedReport should fail initially - tests signed report verification
func TestVerifySignedReport(t *testing.T) {
	// Create a signed report (using helper from sidecar test)
	report := AttestationReport{
		PodName:   "test-pod",
		Namespace: "test-ns",
		Attested:  true,
		Timestamp: time.Now(),
	}

	signedReport := createTestSignedReport(t, report)

	// This function should verify the signature
	valid, err := verifySignedAttestationReport(signedReport)
	if err != nil {
		t.Fatalf("Expected no error verifying signed report, got: %v", err)
	}

	if !valid {
		t.Error("Expected signed report to be valid")
	}
}

// TestRejectUnsignedReport should fail initially - tests rejection of unsigned reports
func TestRejectUnsignedReport(t *testing.T) {
	// Create unsigned report (plain AttestationReport)
	report := AttestationReport{
		PodName:   "test-pod",
		Namespace: "test-ns",
		Attested:  true,
		Timestamp: time.Now(),
	}

	// This should fail to verify (or return false)
	valid, err := verifySignedAttestationReport(&SignedAttestationReport{
		Report:    report,
		Signature: "",
		PublicKey: "",
		Algorithm: "",
	})

	if err == nil && valid {
		t.Error("Expected unsigned report to be rejected")
	}
}

// TestMTLSClientAuth should fail initially - tests client certificate authentication
func TestMTLSClientAuth(t *testing.T) {
	// Create mTLS server
	serverCert, serverKey, caCert := createTestCertificatesForServer(t)
	server, err := createMTLSServer(":0", serverCert, serverKey, caCert)
	if err != nil {
		t.Skipf("mTLS server not implemented: %v", err)
	}
	defer server.Close()

	// Test 1: Valid client certificate should be accepted
	clientCert, clientKey := createTestClientCert(t, caCert)
	client := createClientWithCert(t, clientCert, clientKey, caCert)

	resp, err := client.Post(server.URL+"/api/v1/reports", "application/json",
		bytes.NewReader([]byte(`{"pod_name":"test","namespace":"test","attested":true}`)))
	if err != nil {
		t.Fatalf("Expected valid client to connect, got: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated { // Created because unsigned reports are accepted for backward compatibility
		t.Errorf("Expected Created for valid client request, got %d", resp.StatusCode)
	}

	// Test 2: Invalid client certificate should be rejected
	invalidClient := &http.Client{}
	_, err = invalidClient.Post(server.URL+"/api/v1/reports", "application/json",
		bytes.NewReader([]byte(`{"pod_name":"test","namespace":"test","attested":true}`)))

	if err == nil {
		t.Error("Expected invalid client to be rejected")
	}
}

// TestSecureReportSubmission should fail initially - tests end-to-end secure submission
func TestSecureReportSubmission(t *testing.T) {
	// Create mTLS server
	serverCert, serverKey, caCert := createTestCertificatesForServer(t)
	server, err := createMTLSServer(":0", serverCert, serverKey, caCert)
	if err != nil {
		t.Skipf("mTLS server not implemented: %v", err)
	}
	defer server.Close()

	// Create signed report
	report := AttestationReport{
		PodName:   "secure-pod",
		Namespace: "secure-ns",
		Attested:  true,
		Timestamp: time.Now(),
	}

	signedReport := createTestSignedReport(t, report)

	// Submit with valid client certificate
	clientCert, clientKey := createTestClientCert(t, caCert)
	client := createClientWithCert(t, clientCert, clientKey, caCert)

	body, _ := json.Marshal(signedReport)
	resp, err := client.Post(server.URL+"/api/v1/reports", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Expected successful submission, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	// Verify report was stored with correct verification status
	stored, exists := store.reports["secure-ns/secure-pod"]
	if !exists {
		t.Fatal("Expected report to be stored")
	}

	if !stored.Attested {
		t.Error("Expected stored report to be attested")
	}
}

// Helper functions are now implemented in main.go

// Helper functions for testing

// Global test CA for consistent certificate generation
var testCA *testCAData

type testCAData struct {
	cert    []byte
	key     *rsa.PrivateKey
	certPEM []byte
}

func getTestCA(t *testing.T) *testCAData {
	if testCA == nil {
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
			NotAfter:              time.Now().Add(24 * time.Hour),
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

		testCA = &testCAData{
			cert:    caCertDER,
			key:     caPrivKey,
			certPEM: caCertPEM,
		}
	}
	return testCA
}

func createTestCertificatesForServer(t *testing.T) (serverCert, serverKey, caCert []byte) {
	ca := getTestCA(t)

	// Parse CA certificate
	caCertParsed, err := x509.ParseCertificate(ca.cert)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	// Generate server private key
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	// Create server certificate
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCertParsed, &serverPrivKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("Failed to create server cert: %v", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverPrivKey)
	if err != nil {
		t.Fatalf("Failed to marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})

	return serverCertPEM, serverKeyPEM, ca.certPEM
}

func createTestClientCert(t *testing.T, caCert []byte) (clientCert, clientKey []byte) {
	ca := getTestCA(t)

	// Parse CA certificate
	caCertParsed, err := x509.ParseCertificate(ca.cert)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	// Generate client private key
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create client certificate
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "attestation-sidecar",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCertParsed, &clientPrivKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("Failed to create client cert: %v", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	if err != nil {
		t.Fatalf("Failed to marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})

	return clientCertPEM, clientKeyPEM
}

func createClientWithCert(t *testing.T, clientCert, clientKey, caCert []byte) *http.Client {
	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatalf("Failed to load client cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		t.Fatal("Failed to parse CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:     caCertPool,
		MinVersion:  tls.VersionTLS12,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func createTestSignedReport(t *testing.T, report AttestationReport) *SignedAttestationReport {
	// Generate test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get public key PEM
	pubKeyPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyPKIX,
	})

	// Serialize report for signing
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to serialize report: %v", err)
	}

	// Create signature
	hash := sha256.Sum256(reportJSON)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign report: %v", err)
	}

	return &SignedAttestationReport{
		Report:    report,
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: string(pubKeyPEM),
		Algorithm: "RS256",
	}
}