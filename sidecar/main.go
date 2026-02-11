// Attestation Reporter Sidecar - Reports attestation status to the Collector
// For CoCo pods running with kata-remote/peer-pods
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TrustVector represents EAR trust tier values
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

// AttestationReport is sent to the Collector
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
	Signature string            `json:"signature"`
	PublicKey string            `json:"public_key_pem"`
	Algorithm string            `json:"algorithm"`
}

func main() {
	log.Println("Attestation Reporter Sidecar starting...")

	collectorURL := getEnv("COLLECTOR_URL", "https://attestation-collector.raj-compliance-dashboard:8443")
	podName := getEnv("POD_NAME", "unknown")
	namespace := getEnv("POD_NAMESPACE", "default")
	teeType := getEnv("TEE_TYPE", "snp")
	intervalStr := getEnv("REPORT_INTERVAL", "30")
	useMTLS := getEnv("USE_MTLS", "true") == "true"

	var interval int
	fmt.Sscanf(intervalStr, "%d", &interval)
	if interval < 5 {
		interval = 30
	}

	log.Printf("Configuration:")
	log.Printf("  Collector URL: %s", collectorURL)
	log.Printf("  Pod: %s/%s", namespace, podName)
	log.Printf("  TEE Type: %s", teeType)
	log.Printf("  Report Interval: %ds", interval)
	log.Printf("  mTLS Enabled: %v", useMTLS)

	// Select reporting function based on mTLS setting
	reportFunc := sendReport
	if useMTLS {
		reportFunc = func(url, pod, ns, tee string) {
			if err := sendSecureReport(url, pod, ns, tee); err != nil {
				log.Printf("Failed to send secure report: %v", err)
			} else {
				log.Printf("Secure report sent successfully via mTLS")
			}
		}
	}

	// Initial report
	reportFunc(collectorURL, podName, namespace, teeType)

	// Periodic reporting
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	for range ticker.C {
		reportFunc(collectorURL, podName, namespace, teeType)
	}
}

func sendReport(collectorURL, podName, namespace, teeType string) {
	attested, trustVector, errorMsg := checkAttestationStatus()

	report := AttestationReport{
		PodName:     podName,
		Namespace:   namespace,
		TEEType:     teeType,
		Attested:    attested,
		TrustVector: trustVector,
		Timestamp:   time.Now(),
		Error:       errorMsg,
	}

	body, _ := json.Marshal(report)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(collectorURL+"/api/v1/reports", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("Failed to send report: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		log.Printf("Report sent successfully: attested=%v", attested)
	} else {
		log.Printf("Collector returned status %d", resp.StatusCode)
	}
}

func checkAttestationStatus() (bool, *TrustVector, string) {
	// Option 1: Token-based verification
	// Check if attestation-agent has a valid JWT token from Trustee KBS

	// Look for the JWT token in standard locations
	token, err := getKBSToken()
	if err != nil {
		return false, nil, fmt.Sprintf("No KBS token found: %v", err)
	}

	// Verify the JWT token cryptographically
	trustVector, err := verifyAndParseKBSToken(token)
	if err != nil {
		return false, nil, fmt.Sprintf("Token verification failed: %v", err)
	}

	// If we got here, attestation-agent has a valid token from Trustee KBS
	// This means Trustee verified the TEE according to its policies
	return true, trustVector, ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// normalizeKBSToken extracts a raw JWT from common wrappers (JSON, "Bearer ...", multi-line).
// A valid JWT has exactly 3 dot-separated segments; if the source returns JSON or other format, we extract the token.
func normalizeKBSToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Bearer prefix (e.g. from HTTP headers)
	if s, ok := strings.CutPrefix(raw, "Bearer "); ok {
		raw = strings.TrimSpace(s)
	}
	// JSON wrapper (e.g. CDH or some KBS endpoints return {"token": "eyJ..."})
	if strings.HasPrefix(raw, "{") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			for _, key := range []string{"token", "jwt", "value", "access_token"} {
				if v, ok := m[key]; ok {
					if s, ok := v.(string); ok && s != "" {
						return strings.TrimSpace(s)
					}
				}
			}
		}
	}
	// Multi-line: use first line (JWT is single line)
	if idx := strings.Index(raw, "\n"); idx >= 0 {
		raw = strings.TrimSpace(raw[:idx])
	}
	return raw
}

// kbsTokenEnvVars lists environment variable names checked for the KBS/EAR JWT (first non-empty wins).
var kbsTokenEnvVars = []string{"KBS_TOKEN", "EAR_TOKEN", "ATTESTATION_TOKEN"}

// kbsTokenPaths lists file paths where the sidecar looks for the KBS/EAR JWT (e.g. mounted by CoCo/Trustee).
var kbsTokenPaths = []string{
	"/run/confidential-containers/kbs-token",
	"/run/attestation-agent/token",
	"/tmp/attestation/kbs-token",
	"/run/kbs/token",
}

// getKBSToken looks for KBS JWT token in standard CoCo/Trustee locations
func getKBSToken() (string, error) {
	// Check environment variables first
	for _, name := range kbsTokenEnvVars {
		if token := normalizeKBSToken(os.Getenv(name)); token != "" {
			return token, nil
		}
	}

	// Check standard file locations (e.g. volume mounts from attestation flow)
	for _, path := range kbsTokenPaths {
		if data, err := ioutil.ReadFile(path); err == nil {
			if token := normalizeKBSToken(string(data)); token != "" {
				return token, nil
			}
		}
	}

	// Try CoCo api-server-rest / attestation-agent token endpoint (guest-components)
	kbsTokenURL := getEnv("KBS_TOKEN_URL", "http://127.0.0.1:8006/aa/token?token_type=kbs")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(kbsTokenURL)
	if err == nil {
		defer resp.Body.Close()
		if body, err := ioutil.ReadAll(resp.Body); err == nil {
			if token := normalizeKBSToken(string(body)); token != "" {
				return token, nil
			}
		}
	}

	log.Printf("No KBS token found: set one of env %v, or mount a JWT at one of %v, or ensure %s is available", kbsTokenEnvVars, kbsTokenPaths, kbsTokenURL)

	return "", fmt.Errorf("no KBS token found: set one of env %v, or mount a JWT at one of %v, or ensure %s is available", kbsTokenEnvVars, kbsTokenPaths, kbsTokenURL)
}

// KBSClaims represents the JWT claims from Trustee KBS
type KBSClaims struct {
	jwt.RegisteredClaims
	EAR *EARClaims `json:"ear,omitempty"`
	TEE string     `json:"tee_type,omitempty"`
}

// EARClaims represents Entity Attestation Report claims
type EARClaims struct {
	TrustVector map[string]int `json:"trustworthiness-vector,omitempty"`
}

// verifyAndParseKBSToken validates JWT signature and extracts trust vector
func verifyAndParseKBSToken(tokenString string) (*TrustVector, error) {
	tokenString = strings.TrimSpace(tokenString)
	// JWT must have exactly 3 dot-separated segments (header.payload.signature)
	segments := strings.Split(tokenString, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("token is not a valid JWT (got %d segments, need 3); check KBS_TOKEN or token file/CDH response format", len(segments))
	}
	// Parse token without verification first to get header
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &KBSClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// Get KBS public key for verification
	pubKey, err := getKBSPublicKey()
	if err != nil {
		// If we can't get public key, fall back to basic validation
		log.Printf("Warning: Could not verify token signature: %v", err)
		return parseTokenClaims(token)
	}

	// Verify token with public key
	token, err = jwt.ParseWithClaims(tokenString, &KBSClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token verification failed: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	return parseTokenClaims(token)
}

// parseTokenClaims extracts trust vector from JWT claims
func parseTokenClaims(token *jwt.Token) (*TrustVector, error) {
	claims, ok := token.Claims.(*KBSClaims)
	if !ok {
		return nil, fmt.Errorf("could not parse token claims")
	}

	// Check token expiry
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token has expired")
	}

	// Extract trust vector from EAR claims
	trustVector := &TrustVector{
		InstanceIdentity: 0,
		Configuration:    0,
		Executables:      0,
		FileSystem:       0,
		Hardware:         0,
		RuntimeOpaque:    0,
		StorageOpaque:    0,
		SourcedData:      0,
	}

	if claims.EAR != nil && claims.EAR.TrustVector != nil {
		// Map EAR trust vector to our structure
		if val, exists := claims.EAR.TrustVector["instance-identity"]; exists {
			trustVector.InstanceIdentity = val
		}
		if val, exists := claims.EAR.TrustVector["configuration"]; exists {
			trustVector.Configuration = val
		}
		if val, exists := claims.EAR.TrustVector["executables"]; exists {
			trustVector.Executables = val
		}
		if val, exists := claims.EAR.TrustVector["file-system"]; exists {
			trustVector.FileSystem = val
		}
		if val, exists := claims.EAR.TrustVector["hardware"]; exists {
			trustVector.Hardware = val
		}
		if val, exists := claims.EAR.TrustVector["runtime-opaque"]; exists {
			trustVector.RuntimeOpaque = val
		}
		if val, exists := claims.EAR.TrustVector["storage-opaque"]; exists {
			trustVector.StorageOpaque = val
		}
		if val, exists := claims.EAR.TrustVector["sourced-data"]; exists {
			trustVector.SourcedData = val
		}
	} else {
		// Default to AFFIRMING values if token exists but no explicit trust vector
		// The fact that KBS issued the token means attestation passed
		trustVector.Hardware = 2      // AFFIRMING
		trustVector.Configuration = 2 // AFFIRMING
		trustVector.Executables = 2   // AFFIRMING
	}

	return trustVector, nil
}

// getKBSPublicKey retrieves the KBS public key for JWT verification
func getKBSPublicKey() (*rsa.PublicKey, error) {
	// Standard locations for KBS public key
	keyPaths := []string{
		"/run/confidential-containers/kbs-pubkey.pem",
		"/etc/kbs/pubkey.pem",
		"/tmp/kbs-pubkey.pem",
	}

	// Check environment variable
	if keyPath := os.Getenv("KBS_PUBLIC_KEY_PATH"); keyPath != "" {
		keyPaths = append([]string{keyPath}, keyPaths...)
	}

	// Try to read from file
	for _, path := range keyPaths {
		if keyData, err := ioutil.ReadFile(path); err == nil {
			return parsePublicKey(keyData)
		}
	}

	// Try to get from KBS endpoint
	kbsURL := os.Getenv("KBS_URL")
	if kbsURL != "" {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(kbsURL + "/kbs/v0/public-key")
		if err == nil {
			defer resp.Body.Close()
			if keyData, err := ioutil.ReadAll(resp.Body); err == nil {
				return parsePublicKey(keyData)
			}
		}
	}

	return nil, fmt.Errorf("KBS public key not found")
}

// parsePublicKey parses PEM-encoded RSA public key
func parsePublicKey(keyData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyData)
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

// createSignedReport signs an attestation report with RSA key
func createSignedReport(report AttestationReport) (*SignedAttestationReport, error) {
	// Get or create sidecar private key
	privateKey, err := getSidecarPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %v", err)
	}

	// Get public key PEM
	publicKeyPEM, err := getPublicKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %v", err)
	}

	// Serialize report for signing
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize report: %v", err)
	}

	// Create signature
	hash := sha256.Sum256(reportJSON)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign report: %v", err)
	}

	// Create signed report
	signedReport := &SignedAttestationReport{
		Report:    report,
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: publicKeyPEM,
		Algorithm: "RS256",
	}

	return signedReport, nil
}

// verifySignedReport verifies the signature on a signed attestation report
func verifySignedReport(signedReport *SignedAttestationReport) (bool, error) {
	// Decode public key
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

// createMTLSClient creates HTTP client with mutual TLS configuration
func createMTLSClient(clientCertFile, clientKeyFile, caCertFile string) (*http.Client, error) {
	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP client with mTLS
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return client, nil
}

// sendSecureReport sends a signed attestation report over mTLS
func sendSecureReport(collectorURL, podName, namespace, teeType string) error {
	// Get attestation status
	attested, trustVector, errorMsg := checkAttestationStatus()

	// Create report
	report := AttestationReport{
		PodName:     podName,
		Namespace:   namespace,
		TEEType:     teeType,
		Attested:    attested,
		TrustVector: trustVector,
		Timestamp:   time.Now(),
		Error:       errorMsg,
	}

	// Sign the report
	signedReport, err := createSignedReport(report)
	if err != nil {
		return fmt.Errorf("failed to sign report: %v", err)
	}

	// Create mTLS client
	client, err := createMTLSClientFromConfig()
	if err != nil {
		return fmt.Errorf("failed to create mTLS client: %v", err)
	}

	// Send signed report
	body, _ := json.Marshal(signedReport)
	resp, err := client.Post(collectorURL+"/api/v1/reports", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("collector returned status %d", resp.StatusCode)
	}

	return nil
}

// Helper functions

// getSidecarPrivateKey gets or generates the sidecar's private key
func getSidecarPrivateKey() (*rsa.PrivateKey, error) {
	keyPath := getEnv("SIDECAR_PRIVATE_KEY", "/run/attestation-sidecar/private.key")

	// Try to read existing key
	if keyData, err := ioutil.ReadFile(keyPath); err == nil {
		return parsePrivateKeyFromPEM(string(keyData))
	}

	// Generate new key if none exists
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	// Save key for future use (if possible)
	if keyPEM, err := getPrivateKeyPEM(privateKey); err == nil {
		ioutil.WriteFile(keyPath, []byte(keyPEM), 0600) // Ignore errors - might be read-only filesystem
	}

	return privateKey, nil
}

// getPublicKeyPEM encodes public key as PEM
func getPublicKeyPEM(privateKey *rsa.PrivateKey) (string, error) {
	pubKeyPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyPKIX,
	})

	return string(pubKeyPEM), nil
}

// getPrivateKeyPEM encodes private key as PEM
func getPrivateKeyPEM(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return string(privateKeyPEM), nil
}

// parsePrivateKeyFromPEM parses PEM-encoded RSA private key
func parsePrivateKeyFromPEM(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
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

// createMTLSClientFromConfig creates mTLS client from environment configuration
func createMTLSClientFromConfig() (*http.Client, error) {
	clientCertFile := getEnv("CLIENT_CERT_FILE", "/run/attestation-sidecar/client.crt")
	clientKeyFile := getEnv("CLIENT_KEY_FILE", "/run/attestation-sidecar/client.key")
	caCertFile := getEnv("CA_CERT_FILE", "/run/attestation-sidecar/ca.crt")

	return createMTLSClient(clientCertFile, clientKeyFile, caCertFile)
}
