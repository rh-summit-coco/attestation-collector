package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test 1: POST /api/v1/reports - Submit attestation report
func TestPostReport(t *testing.T) {
	// Reset store for clean test
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.history = make(map[string][]AttestationReport)
	store.mu.Unlock()

	report := AttestationReport{
		PodName:   "test-pod",
		Namespace: "test-ns",
		TEEType:   "tdx",
		Attested:  true,
		TrustVector: &TrustVector{
			Hardware:      2,
			Configuration: 2,
			Executables:   2,
		},
	}

	body, _ := json.Marshal(report)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleReports(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", rr.Code)
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["key"] != "test-ns/test-pod" {
		t.Errorf("Expected key 'test-ns/test-pod', got '%s'", resp["key"])
	}
}

// Test 2: GET /api/v1/reports - List all reports
func TestGetReports(t *testing.T) {
	// Setup: add test data
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.reports["ns1/pod1"] = AttestationReport{PodName: "pod1", Namespace: "ns1", Attested: true}
	store.reports["ns2/pod2"] = AttestationReport{PodName: "pod2", Namespace: "ns2", Attested: false}
	store.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports", nil)
	rr := httptest.NewRecorder()

	handleReports(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var reports []AttestationReport
	json.NewDecoder(rr.Body).Decode(&reports)
	if len(reports) != 2 {
		t.Errorf("Expected 2 reports, got %d", len(reports))
	}
}

// Test 3: GET /api/v1/reports/{ns}/{pod} - Get specific report
func TestGetReportByKey(t *testing.T) {
	// Setup
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.reports["hospital/patient-db"] = AttestationReport{
		PodName:   "patient-db",
		Namespace: "hospital",
		Attested:  true,
		TEEType:   "tdx",
		Timestamp: time.Now(),
	}
	store.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/hospital/patient-db", nil)
	rr := httptest.NewRecorder()

	handleReportByKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var report AttestationReport
	json.NewDecoder(rr.Body).Decode(&report)
	if report.PodName != "patient-db" {
		t.Errorf("Expected pod name 'patient-db', got '%s'", report.PodName)
	}
	if report.Attested != true {
		t.Errorf("Expected attested=true")
	}
}

// Test 4: GET /api/v1/reports/{ns}/{pod}/history - Get report history
func TestGetReportHistory(t *testing.T) {
	// Setup: add history entries
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.history = make(map[string][]AttestationReport)
	store.history["hospital/patient-db"] = []AttestationReport{
		{PodName: "patient-db", Namespace: "hospital", Attested: false, Timestamp: time.Now().Add(-1 * time.Hour)},
		{PodName: "patient-db", Namespace: "hospital", Attested: true, Timestamp: time.Now()},
	}
	store.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/hospital/patient-db/history", nil)
	rr := httptest.NewRecorder()

	handleReportByKey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var history []AttestationReport
	json.NewDecoder(rr.Body).Decode(&history)
	if len(history) != 2 {
		t.Errorf("Expected 2 history entries, got %d", len(history))
	}
}

// Test 5: POST with missing required fields should fail
func TestPostReportMissingFields(t *testing.T) {
	// Reset store
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.history = make(map[string][]AttestationReport)
	store.mu.Unlock()

	// Missing namespace
	report := AttestationReport{
		PodName: "test-pod",
		// Namespace missing
	}

	body, _ := json.Marshal(report)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleReports(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing namespace, got %d", rr.Code)
	}
}

// Test 6: CORS headers should be set correctly
func TestCORSHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/reports", nil)
	req.Header.Set("Origin", "https://dashboard.example.com")
	rr := httptest.NewRecorder()

	handler := corsMiddleware(http.HandlerFunc(handleReports))
	handler.ServeHTTP(rr, req)

	// Check CORS headers
	origin := rr.Header().Get("Access-Control-Allow-Origin")
	if origin != "*" {
		t.Errorf("Expected Access-Control-Allow-Origin '*', got '%s'", origin)
	}

	methods := rr.Header().Get("Access-Control-Allow-Methods")
	if methods != "GET, POST, OPTIONS" {
		t.Errorf("Expected Access-Control-Allow-Methods 'GET, POST, OPTIONS', got '%s'", methods)
	}

	// OPTIONS should return 200
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rr.Code)
	}
}

// Test 7: GET non-existent report should return 404
func TestGetNonExistentReport(t *testing.T) {
	// Clear store
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.history = make(map[string][]AttestationReport)
	store.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/nonexistent/pod", nil)
	rr := httptest.NewRecorder()

	handleReportByKey(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

// Test 8: DELETE /api/v1/reports/{ns}/{pod} - Delete a report (TDD: will fail initially)
func TestDeleteReport(t *testing.T) {
	// Setup
	store.mu.Lock()
	store.reports = make(map[string]AttestationReport)
	store.reports["test-ns/test-pod"] = AttestationReport{
		PodName:   "test-pod",
		Namespace: "test-ns",
		Attested:  true,
	}
	store.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/reports/test-ns/test-pod", nil)
	rr := httptest.NewRecorder()

	handleReportByKey(rr, req)

	// Should return 204 No Content on successful delete
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}

	// Verify report is deleted
	store.mu.RLock()
	_, exists := store.reports["test-ns/test-pod"]
	store.mu.RUnlock()

	if exists {
		t.Error("Report should have been deleted")
	}
}
