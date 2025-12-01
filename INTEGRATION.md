# Attestation Collector Integration Guide

## Overview

The Attestation Collector aggregates TEE attestation reports from CoCo pod sidecars
and provides a unified API for Raj's compliance dashboard.

## Components

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CoCo Pods     │     │   Collector     │     │   Dashboard     │
│   (sidecar)     │────▶│   (this)        │────▶│   (Raj's UI)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Collector API

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/reports` | Submit attestation report (from sidecar) |
| GET | `/api/v1/reports` | List all current reports (for dashboard) |
| GET | `/api/v1/reports/{ns}/{pod}` | Get specific pod report |
| GET | `/api/v1/reports/{ns}/{pod}/history` | Get report history |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/ready` | Readiness check |

### Report Format

```json
{
  "pod_name": "patient-records-7b4f9",
  "namespace": "hospital-app",
  "tee_type": "tdx",
  "attested": true,
  "trust_vector": {
    "hardware": 2,
    "configuration": 2,
    "executables": 2,
    "instance_identity": 0,
    "file_system": 0,
    "runtime_opaque": 0,
    "storage_opaque": 0,
    "sourced_data": 0
  },
  "ear_token": "eyJhbGciOiJFUzI1NiIs...",
  "timestamp": "2025-11-30T12:00:00Z",
  "error": ""
}
```

### Trust Vector Values (EAR Trust Tiers)

| Value | Meaning |
|-------|---------|
| 2 | AFFIRMING - Verified and trusted |
| 3 | WARNING - Verified but with caveats |
| 32 | CONTRAINDICATED - Verification failed |
| 33 | UNRECOGNIZED_INSTANCE - Unknown executables |
| 36 | NO_CONFIG - Configuration not available |
| 96 | NO_CLAIM - No claim made |
| 97 | UNRECOGNIZED_HARDWARE - Unknown hardware |

---

## Sidecar Integration

### Required Changes to Pradipta's Sidecar

The sidecar (`cococtl/sidecar`) needs to push reports to the Collector.

#### 1. Add Collector URL Configuration

```go
// pkg/config/config.go
type Config struct {
    // ... existing fields
    CollectorURL string `env:"COLLECTOR_URL" default:"http://attestation-collector.raj-compliance-dashboard:8080"`
}
```

#### 2. Add Report Pusher

```go
// pkg/status/pusher.go
package status

import (
    "bytes"
    "encoding/json"
    "net/http"
    "os"
    "time"
)

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

func PushReport(collectorURL string, status *Status) error {
    report := AttestationReport{
        PodName:   os.Getenv("POD_NAME"),
        Namespace: os.Getenv("POD_NAMESPACE"),
        Attested:  status.Attested,
        Timestamp: time.Now(),
    }

    // If we have the EAR token, include it and parse trust vectors
    if status.Token != "" {
        report.EARToken = status.Token
        report.TrustVector = parseTrustVector(status.Token)
    }

    if status.Error != nil {
        report.Error = status.Error.Error()
    }

    body, _ := json.Marshal(report)
    resp, err := http.Post(
        collectorURL+"/api/v1/reports",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    return nil
}

// Parse trust vector from EAR token (JWT)
func parseTrustVector(token string) *TrustVector {
    // Decode JWT and extract trust vector from claims
    // For now, return a placeholder
    return nil
}
```

#### 3. Add Periodic Push Loop

```go
// In main sidecar loop
go func() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        status := collector.GetStatus()
        if err := PushReport(config.CollectorURL, status); err != nil {
            log.Printf("Failed to push report: %v", err)
        }
    }
}()
```

#### 4. Pod Environment Variables

The sidecar pod needs these environment variables:

```yaml
env:
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: COLLECTOR_URL
  value: "http://attestation-collector.raj-compliance-dashboard:8080"
```

---

## Dashboard Integration

### Fetching Reports

The dashboard should periodically fetch from the Collector:

```javascript
// In dashboard frontend
async function fetchAttestationReports() {
  const response = await fetch(
    'https://attestation-collector-raj-compliance-dashboard.apps.uhfgfgde.eastus.aroapp.io/api/v1/reports'
  );
  return response.json();
}

// Poll every 10 seconds
setInterval(async () => {
  const reports = await fetchAttestationReports();
  updateDashboard(reports);
}, 10000);
```

### Displaying Trust Status

```javascript
function getTrustStatus(trustVector) {
  // Check if all critical values are AFFIRMING (2)
  if (trustVector.hardware === 2 &&
      trustVector.configuration === 2 &&
      trustVector.executables === 2) {
    return { status: 'COMPLIANT', color: 'green' };
  }

  // Check for failures
  if (trustVector.hardware > 30 ||
      trustVector.configuration > 30 ||
      trustVector.executables > 30) {
    return { status: 'FAILED', color: 'red' };
  }

  return { status: 'WARNING', color: 'yellow' };
}
```

---

## Deployment

### Collector URL (Internal)
```
http://attestation-collector.raj-compliance-dashboard:8080
```

### Collector URL (External)
```
https://attestation-collector-raj-compliance-dashboard.apps.uhfgfgde.eastus.aroapp.io
```

---

## Known Shortcuts / Technical Debt

### Trustee Token Signer - EPHEMERAL KEY (Dec 2025)

**Status**: Using ephemeral signer key (auto-generated on pod restart)

**Impact**:
- Tokens are signed but verification key changes on KBS restart
- Dashboard cannot independently verify token signatures
- Old tokens become unverifiable after KBS restart

**Root Cause**:
The KBS config has the signer key path configured correctly:
```toml
[attestation_service.as_config.attestation_token_config.signer]
key_path = "/etc/token-signer/key.pem"
```
But the embedded AS (CoCoASBuiltIn) doesn't read this config section. Log shows:
`No Token Signer key in config file, create an ephemeral key`

**To Fix**:
1. Investigate if embedded AS needs separate config file
2. Or switch to standalone AS deployment (`type = "gRPC"`)
3. Or file issue with Trustee upstream about config parsing

**Workaround Acceptable For**: Demo purposes - trust vectors are still accurate

---

## Phase 2: Rekor Integration

When RHTAS is installed, the Collector will be updated to:

1. Write reports to private Rekor transparency log
2. Include Rekor log entry ID in responses
3. Provide verification endpoint to check Rekor proofs

```go
// Future: Phase 2
type AttestationReport struct {
    // ... existing fields
    RekorLogIndex int64  `json:"rekor_log_index,omitempty"`
    RekorEntryID  string `json:"rekor_entry_id,omitempty"`
}
```
