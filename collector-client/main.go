// Attestation Collector Client - polls secure-access sidecar APIs and reports to central collector
// Supports multiple targets: CoCo sidecars on OpenShift and standalone RHEL CVM attestation-agents
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	defaultSecureAccessURL = "https://localhost:8443"
	defaultCollectorURL    = "http://attestation-collector:8080"
	defaultReportInterval  = 30 * time.Second
)

// TargetType identifies the type of attestation target
type TargetType string

const (
	TargetTypeCoCo    TargetType = "coco-sidecar"
	TargetTypeRHELCVM TargetType = "rhel-cvm"
)

// Target represents an attestation target to poll
type Target struct {
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	Type      TargetType `json:"type"`
	Namespace string     `json:"namespace,omitempty"` // For CoCo pods
}

// SecureAccessStatus represents the response from secure-access /api/status
type SecureAccessStatus struct {
	PodName   string `json:"podName"`
	Namespace string `json:"namespace"`
	Attested  bool   `json:"attested"`
}

// SecureAccessAttestation represents the response from secure-access /api/attestation
type SecureAccessAttestation struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Details   string `json:"details"`
}

// EnhancedSecurityReport represents the enhanced report format for the collector
type EnhancedSecurityReport struct {
	// Existing attestation data (from CDH via secure-access)
	AttestationData struct {
		Status    string `json:"status"`    // "verified"/"failed"
		Timestamp string `json:"timestamp"` // RFC3339
		Details   string `json:"details"`   // Error details if failed
	} `json:"attestation_data"`

	// mTLS access control data
	AccessControlData struct {
		MTLSEnabled   bool `json:"mtls_enabled"`    // Always true for secure-access
		CertValid     bool `json:"cert_valid"`      // TLS cert status
		ClientCAValid bool `json:"client_ca_valid"` // CA cert status
		HTTPSPort     int  `json:"https_port"`      // Port number
	} `json:"access_control_data"`

	// Target metadata
	PodName    string     `json:"pod_name"`
	Namespace  string     `json:"namespace"`
	TargetType TargetType `json:"target_type"`
	TargetName string     `json:"target_name"`
	Timestamp  string     `json:"timestamp"`
}

// Config represents the client configuration
type Config struct {
	Targets        []Target
	CollectorURL   string
	ReportInterval time.Duration
}

// AttestationCollectorClient polls secure-access targets and reports to collector
type AttestationCollectorClient struct {
	config *Config
	client *resty.Client
}

func main() {
	log.Println("Starting Attestation Collector Client (Multi-Target Mode)...")

	config := loadConfig()
	client := NewAttestationCollectorClient(config)

	log.Printf("Configuration:")
	log.Printf("  Collector URL: %s", config.CollectorURL)
	log.Printf("  Report Interval: %v", config.ReportInterval)
	log.Printf("  Targets: %d", len(config.Targets))
	for i, target := range config.Targets {
		log.Printf("    [%d] %s (%s): %s", i+1, target.Name, target.Type, target.URL)
	}

	// Start the polling loop
	log.Println("Starting polling loop...")
	client.StartPolling()
}

// NewAttestationCollectorClient creates a new client
func NewAttestationCollectorClient(config *Config) *AttestationCollectorClient {
	client := resty.New()
	// Skip TLS verification for internal communication (self-signed certs)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(10 * time.Second)

	return &AttestationCollectorClient{
		config: config,
		client: client,
	}
}

// StartPolling starts the polling loop
func (c *AttestationCollectorClient) StartPolling() {
	ticker := time.NewTicker(c.config.ReportInterval)
	defer ticker.Stop()

	// Send initial report immediately
	c.collectAndReportAll()

	// Then send reports at regular intervals
	for range ticker.C {
		c.collectAndReportAll()
	}
}

// collectAndReportAll polls all targets concurrently and reports to collector
func (c *AttestationCollectorClient) collectAndReportAll() {
	var wg sync.WaitGroup
	for _, target := range c.config.Targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			c.collectAndReport(t)
		}(target)
	}
	wg.Wait()
}

// collectAndReport fetches data from a target and reports to collector
func (c *AttestationCollectorClient) collectAndReport(target Target) {
	log.Printf("[%s] Collecting data from %s...", target.Name, target.URL)

	// Fetch status from target /api/status
	status, err := c.fetchTargetStatus(target)
	if err != nil {
		log.Printf("[%s] ERROR: Failed to fetch status: %v", target.Name, err)
		// Report failure to collector
		c.reportFailure(target, err.Error())
		return
	}
	log.Printf("[%s] Status fetched: pod=%s, namespace=%s, attested=%v",
		target.Name, status.PodName, status.Namespace, status.Attested)

	// Fetch attestation details from target /api/attestation
	attestation, err := c.fetchTargetAttestation(target)
	if err != nil {
		log.Printf("[%s] ERROR: Failed to fetch attestation: %v", target.Name, err)
		c.reportFailure(target, err.Error())
		return
	}
	log.Printf("[%s] Attestation fetched: status=%s, timestamp=%s",
		target.Name, attestation.Status, attestation.Timestamp)

	// Transform to enhanced collector format
	report := c.transformToCollectorFormat(target, status, attestation)

	// Report to central collector
	if err := c.reportToCollector(report); err != nil {
		log.Printf("[%s] ERROR: Failed to report to collector: %v", target.Name, err)
		return
	}

	log.Printf("[%s] Successfully reported to collector: pod=%s, status=%s",
		target.Name, report.PodName, report.AttestationData.Status)
}

// reportFailure sends a failure report to the collector when target is unreachable
func (c *AttestationCollectorClient) reportFailure(target Target, errorMsg string) {
	report := &EnhancedSecurityReport{
		PodName:    target.Name,
		Namespace:  target.Namespace,
		TargetType: target.Type,
		TargetName: target.Name,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	report.AttestationData.Status = "unreachable"
	report.AttestationData.Timestamp = time.Now().UTC().Format(time.RFC3339)
	report.AttestationData.Details = errorMsg
	report.AccessControlData.MTLSEnabled = false
	report.AccessControlData.CertValid = false
	report.AccessControlData.ClientCAValid = false
	report.AccessControlData.HTTPSPort = 8443

	if err := c.reportToCollector(report); err != nil {
		log.Printf("[%s] ERROR: Failed to report failure to collector: %v", target.Name, err)
	}
}

// fetchTargetStatus gets status from target /api/status
func (c *AttestationCollectorClient) fetchTargetStatus(target Target) (*SecureAccessStatus, error) {
	resp, err := c.client.R().
		SetResult(&SecureAccessStatus{}).
		Get(target.URL + "/api/status")

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	result := resp.Result().(*SecureAccessStatus)
	return result, nil
}

// fetchTargetAttestation gets attestation from target /api/attestation
func (c *AttestationCollectorClient) fetchTargetAttestation(target Target) (*SecureAccessAttestation, error) {
	resp, err := c.client.R().
		SetResult(&SecureAccessAttestation{}).
		Get(target.URL + "/api/attestation")

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	result := resp.Result().(*SecureAccessAttestation)
	return result, nil
}

// transformToCollectorFormat converts target data to enhanced collector format
func (c *AttestationCollectorClient) transformToCollectorFormat(
	target Target,
	status *SecureAccessStatus,
	attestation *SecureAccessAttestation) *EnhancedSecurityReport {

	report := &EnhancedSecurityReport{
		PodName:    status.PodName,
		Namespace:  status.Namespace,
		TargetType: target.Type,
		TargetName: target.Name,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	// Transform attestation data
	report.AttestationData.Status = attestation.Status
	report.AttestationData.Timestamp = attestation.Timestamp
	report.AttestationData.Details = attestation.Details

	// Add access control data
	report.AccessControlData.MTLSEnabled = true // Always true for secure-access
	report.AccessControlData.CertValid = (attestation.Status == "verified")
	report.AccessControlData.ClientCAValid = (attestation.Status == "verified")
	report.AccessControlData.HTTPSPort = 8443 // Default HTTPS port

	return report
}

// reportToCollector sends the enhanced report to the central collector
func (c *AttestationCollectorClient) reportToCollector(report *EnhancedSecurityReport) error {
	// Convert report to JSON
	jsonData, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	// Send to collector API
	resp, err := c.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(jsonData).
		Post(c.config.CollectorURL + "/api/v1/reports")

	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode(), resp.String())
	}

	return nil
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	config := &Config{
		CollectorURL:   getEnvOrDefault("COLLECTOR_URL", defaultCollectorURL),
		ReportInterval: defaultReportInterval,
	}

	// Parse report interval from environment
	if intervalStr := os.Getenv("REPORT_INTERVAL"); intervalStr != "" {
		if seconds, err := strconv.Atoi(intervalStr); err == nil && seconds > 0 {
			config.ReportInterval = time.Duration(seconds) * time.Second
		} else {
			log.Printf("WARNING: Invalid REPORT_INTERVAL value: %s, using default %v",
				intervalStr, defaultReportInterval)
		}
	}

	// Parse targets from TARGETS environment variable (JSON array)
	if targetsStr := os.Getenv("TARGETS"); targetsStr != "" {
		var targets []Target
		if err := json.Unmarshal([]byte(targetsStr), &targets); err != nil {
			log.Printf("WARNING: Failed to parse TARGETS JSON: %v", err)
		} else {
			config.Targets = targets
		}
	}

	// Fallback to single-target mode using SECURE_ACCESS_URL
	if len(config.Targets) == 0 {
		secureAccessURL := getEnvOrDefault("SECURE_ACCESS_URL", defaultSecureAccessURL)
		config.Targets = []Target{
			{
				Name:      "default",
				URL:       secureAccessURL,
				Type:      TargetTypeCoCo,
				Namespace: "default",
			},
		}
		log.Println("Using single-target mode (SECURE_ACCESS_URL)")
	}

	return config
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
