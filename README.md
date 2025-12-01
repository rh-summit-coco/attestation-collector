# CoCo Beacon - Confidential Container Attestation Monitoring

**CoCo Beacon** is a comprehensive attestation monitoring solution for Confidential Containers, providing real-time visibility into TEE (Trusted Execution Environment) attestation status across your cluster.

## Architecture

```
┌─────────────────────────┐    HTTP POST     ┌─────────────────────────┐
│ CoCo Pod (TEE)          │    every 30s     │ Attestation Collector   │
│ ├─ hospital-app         │ ─────────────────▶│ API Service             │
│ └─ CoCo Beacon Sidecar  │  attestation     │ (In-memory storage)     │
└─────────────────────────┘  reports         └─────────────────────────┘
                                                        │
                                                        │ HTTP GET
                                                        ▼
                                              ┌─────────────────────────┐
                                              │ RAJ Hospital Dashboard  │
                                              │ (Live attestation UI)   │
                                              └─────────────────────────┘
```

## Components

### 1. CoCo Beacon Sidecar (`sidecar/`)
- **Purpose**: Reports attestation status from individual CoCo pods
- **Method**: Checks CDH (Confidential Data Hub) availability as attestation proof
- **Frequency**: Configurable interval (default: 30 seconds)
- **Output**: EAR-compliant trust vectors

### 2. Attestation Collector (`main.go`)
- **Purpose**: Central API service for collecting and serving attestation reports
- **Storage**: In-memory with historical data (last 100 reports per pod)
- **API**: RESTful endpoints for reports, health checks, and individual pod queries
- **Features**: Thread-safe, CORS-enabled for dashboard access

## Quick Start

### Deploy Collector
```bash
# Build and deploy collector
make build
kubectl apply -f deploy/collector.yaml
```

### Add Sidecar to CoCo Pods
```yaml
spec:
  containers:
  - name: coco-beacon-sidecar
    image: quay.io/jensfr/attestation-sidecar:latest
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
      value: "http://attestation-collector:8080"
    - name: TEE_TYPE
      value: "tdx"
    - name: REPORT_INTERVAL
      value: "30"
```

## API Reference

### Collector Endpoints
```
GET  /api/v1/health                           - Health check
GET  /api/v1/ready                            - Readiness check
GET  /api/v1/reports                          - List all current reports
GET  /api/v1/reports/{namespace}/{pod}        - Get specific pod report
GET  /api/v1/reports/{namespace}/{pod}/history - Get historical reports
POST /api/v1/reports                          - Receive report (from sidecar)
```

### Report Format
```json
{
  "pod_name": "janine-hospital-coco-d66bcf556-t587j",
  "namespace": "janine-app",
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
  "timestamp": "2025-12-01T20:43:35Z"
}
```

## Environment Variables

### CoCo Beacon Sidecar
- `COLLECTOR_URL` - Collector endpoint (default: `http://attestation-collector:8080`)
- `POD_NAME` - Pod name (auto-injected via downward API)
- `POD_NAMESPACE` - Pod namespace (auto-injected via downward API)
- `TEE_TYPE` - TEE technology (default: `tdx`)
- `REPORT_INTERVAL` - Report frequency in seconds (default: `30`)

### Attestation Collector
- `PORT` - HTTP port (default: `8080`)

## Trust Vector Explained

CoCo Beacon reports use EAR (Entity Attestation Report) compliant trust vectors:

- **Value 0**: Not claimed/evaluated
- **Value 1**: CONTRAINDICATED - evidence suggests compromise
- **Value 2**: AFFIRMING - evidence supports claim

Current implementation sets AFFIRMING (2) values for:
- **Hardware**: TDX/SEV-SNP hardware verification
- **Configuration**: VM/container configuration integrity
- **Executables**: Code integrity verification

## Integration with RAJ Hospital Dashboard

The CoCo Beacon system integrates with the [RAJ Hospital Dashboard](https://github.com/rh-summit-coco/raj-hospital-dashboard) to provide real-time visualization of confidential computing security posture.

## Development

### Build
```bash
# Build collector
go build -o attestation-collector .

# Build sidecar
cd sidecar
go build -o coco-beacon-sidecar .
```

### Test
```bash
go test ./...
```

### Container Build
```bash
# Collector
podman build -t attestation-collector .

# Sidecar
podman build -f Dockerfile.sidecar -t coco-beacon-sidecar .
```

## Demo Environment

This project is part of the **Red Hat Summit Confidential Computing Demo**, demonstrating:

- Real TEE attestation with Intel TDX and AMD SEV-SNP
- Zero-trust verification of confidential workloads
- Healthcare compliance monitoring
- OpenShift Sandboxed Containers integration

## Security Considerations

⚠️ **Current Implementation**: Demo/PoC level security
- Plain HTTP communication
- No authentication/authorization
- Trust-based report acceptance

🔒 **Production Requirements**:
- mTLS with attestation-based certificates
- Cryptographically signed reports
- Integration with external attestation services (Rekor, etc.)
- Secure storage backends

## License

[MIT License](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

---

**Red Hat Summit 2025 Confidential Computing Demo**
*Lighthouse beacon for your confidential workloads* 🚨