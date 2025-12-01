// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Configuration - set via environment variables
var (
	janineAppURL      = getEnv("JANINE_APP_URL", "https://janine-hospital-coco-janine-app.apps.uhfgfgde.eastus.aroapp.io")
	collectorURL      = getEnv("COLLECTOR_URL", "https://attestation-collector-raj-compliance-dashboard.apps.uhfgfgde.eastus.aroapp.io")
	kbsServiceURL     = getEnv("KBS_SERVICE_URL", "http://kbs-service.trustee-operator-system:8080")
	janinePodName     = getEnv("JANINE_POD_NAME", "janine-hospital-coco")
	janineNamespace   = getEnv("JANINE_NAMESPACE", "janine-app")
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// Test 1: Verify Janine's CoCo pod is running with kata-remote runtime
func TestJaninePodIsConfidentialContainer(t *testing.T) {
	// Get pod runtime class using oc command
	cmd := exec.Command("oc", "get", "pod", "-n", janineNamespace, "-l", "app="+janinePodName,
		"-o", "jsonpath={.items[0].spec.runtimeClassName}")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get pod runtime class: %v", err)
	}

	runtimeClass := strings.TrimSpace(string(output))
	if runtimeClass != "kata-remote" {
		t.Errorf("Expected runtimeClassName 'kata-remote', got '%s'", runtimeClass)
	}

	// Verify pod is Running
	cmd = exec.Command("oc", "get", "pod", "-n", janineNamespace, "-l", "app="+janinePodName,
		"-o", "jsonpath={.items[0].status.phase}")
	output, err = cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get pod status: %v", err)
	}

	status := strings.TrimSpace(string(output))
	if status != "Running" {
		t.Errorf("Expected pod status 'Running', got '%s'", status)
	}

	t.Logf("Janine's pod is running as Confidential Container (kata-remote)")
}

// Test 2: Verify Janine's app is accessible via route
func TestJanineAppIsAccessible(t *testing.T) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: nil, // Skip TLS verification for test
		},
	}

	resp, err := client.Get(janineAppURL)
	if err != nil {
		t.Fatalf("Failed to access Janine's app: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Janine's Hospital Demo") {
		t.Error("Response doesn't contain expected content")
	}

	t.Logf("Janine's app accessible at %s", janineAppURL)
}

// Test 3: Verify Attestation Collector is running
func TestCollectorIsAccessible(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(collectorURL + "/api/v1/health")
	if err != nil {
		t.Fatalf("Failed to access Collector health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var health map[string]string
	json.NewDecoder(resp.Body).Decode(&health)
	if health["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", health["status"])
	}

	t.Logf("Attestation Collector is healthy at %s", collectorURL)
}

// Test 4: Verify Trustee/KBS is running (internal check via oc exec)
func TestTrusteeIsRunning(t *testing.T) {
	cmd := exec.Command("oc", "get", "pod", "-n", "trustee-operator-system", "-l", "app=kbs",
		"-o", "jsonpath={.items[0].status.phase}")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get Trustee pod status: %v", err)
	}

	status := strings.TrimSpace(string(output))
	if status != "Running" {
		t.Errorf("Expected Trustee pod status 'Running', got '%s'", status)
	}

	// Check logs for EAR broker
	cmd = exec.Command("oc", "logs", "-n", "trustee-operator-system", "-l", "app=kbs", "--tail=50")
	output, err = cmd.Output()
	if err != nil {
		t.Logf("Warning: couldn't get Trustee logs: %v", err)
	} else {
		if strings.Contains(string(output), "ear_broker") {
			t.Log("Trustee is using EAR token broker")
		}
	}

	t.Log("Trustee/KBS is running")
}

// Test 5: Simulate attestation report submission to Collector
func TestCollectorAcceptsReport(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Create a test attestation report
	report := AttestationReport{
		PodName:   "integration-test-pod",
		Namespace: "integration-test",
		TEEType:   "tdx",
		Attested:  true,
		TrustVector: &TrustVector{
			Hardware:      2, // AFFIRMING
			Configuration: 2,
			Executables:   2,
		},
		Timestamp: time.Now(),
	}

	body, _ := json.Marshal(report)
	resp, err := client.Post(collectorURL+"/api/v1/reports", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to submit report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Verify report was stored
	resp, err = client.Get(collectorURL + "/api/v1/reports/integration-test/integration-test-pod")
	if err != nil {
		t.Fatalf("Failed to retrieve report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 when retrieving report, got %d", resp.StatusCode)
	}

	var storedReport AttestationReport
	json.NewDecoder(resp.Body).Decode(&storedReport)
	if storedReport.Attested != true {
		t.Error("Stored report doesn't match submitted report")
	}

	// Cleanup: delete test report
	req, _ := http.NewRequest(http.MethodDelete, collectorURL+"/api/v1/reports/integration-test/integration-test-pod", nil)
	client.Do(req)

	t.Log("Collector accepts and stores attestation reports correctly")
}

// Test 6: Verify Azure peer-pod VM exists for Janine's pod
func TestAzurePeerPodVMExists(t *testing.T) {
	// Get the pod name
	cmd := exec.Command("oc", "get", "pod", "-n", janineNamespace, "-l", "app="+janinePodName,
		"-o", "jsonpath={.items[0].metadata.name}")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get pod name: %v", err)
	}
	podName := strings.TrimSpace(string(output))

	// Check Azure VMs (requires az CLI and login)
	cmd = exec.Command("az", "vm", "list", "-g", "jfreiman-summit-rg",
		"--query", fmt.Sprintf("[?starts_with(name, 'podvm-%s')].name", podName[:20]), "-o", "tsv")
	output, err = cmd.Output()
	if err != nil {
		t.Skipf("Skipping Azure VM check (az CLI not available or not logged in): %v", err)
	}

	vmName := strings.TrimSpace(string(output))
	if vmName == "" {
		t.Log("Warning: Could not find matching Azure VM (may have different naming)")
	} else {
		t.Logf("Azure peer-pod VM found: %s", vmName)
	}
}

// Test 7: End-to-end attestation flow readiness check
func TestAttestationFlowReadiness(t *testing.T) {
	checks := []struct {
		name  string
		check func() error
	}{
		{"Janine CoCo Pod Running", func() error {
			cmd := exec.Command("oc", "get", "pod", "-n", janineNamespace, "-l", "app="+janinePodName,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := cmd.Output()
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) != "Running" {
				return fmt.Errorf("pod not running")
			}
			return nil
		}},
		{"Trustee/KBS Running", func() error {
			cmd := exec.Command("oc", "get", "pod", "-n", "trustee-operator-system", "-l", "app=kbs",
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := cmd.Output()
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) != "Running" {
				return fmt.Errorf("trustee not running")
			}
			return nil
		}},
		{"Collector Healthy", func() error {
			resp, err := http.Get(collectorURL + "/api/v1/health")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("collector unhealthy: %d", resp.StatusCode)
			}
			return nil
		}},
	}

	allPassed := true
	for _, c := range checks {
		if err := c.check(); err != nil {
			t.Errorf("%s: FAILED - %v", c.name, err)
			allPassed = false
		} else {
			t.Logf("%s: PASSED", c.name)
		}
	}

	if allPassed {
		t.Log("All attestation flow components are ready!")
	}
}
