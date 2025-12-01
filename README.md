# CoCo Beacon - Confidential Container Attestation Monitoring

**CoCo Beacon** is a comprehensive attestation monitoring solution for Confidential Containers, providing real-time visibility into TEE (Trusted Execution Environment) attestation status across your cluster.

## Architecture

```
┌─────────────────────────┐  mTLS + JWT      ┌─────────────────────────┐
│ CoCo Pod (TEE)          │  signed reports  │ Attestation Collector   │
│ ├─ hospital-app         │ ─────────────────▶│ API Service             │
│ └─ CoCo Beacon Sidecar  │  every 30s       │ (Secure verification)   │
└─────────────────────────┘  port 8443       └─────────────────────────┘
                                                        │
                                                        │ HTTPS GET
                                                        ▼
                                              ┌─────────────────────────┐
                                              │ RAJ Hospital Dashboard  │
                                              │ (Live attestation UI)   │
                                              └─────────────────────────┘
```

## Components

### 1. CoCo Beacon Sidecar (`sidecar/`)
- **Purpose**: Reports attestation status from individual CoCo pods
- **Method**: Verifies KBS JWT tokens from Trustee for cryptographic attestation proof
- **Security**: RSA-signed attestation reports + mTLS client authentication
- **Frequency**: Configurable interval (default: 30 seconds)
- **Output**: JWT-signed EAR-compliant trust vectors

### 2. Attestation Collector (`main.go`)
- **Purpose**: Central API service for collecting and verifying attestation reports
- **Security**: mTLS server with client certificate verification + RSA signature verification
- **Storage**: In-memory with historical data (last 100 reports per pod)
- **API**: RESTful endpoints for reports, health checks, and individual pod queries
- **Features**: Thread-safe, CORS-enabled, backward compatible with unsigned reports

## Quick Start

### Deploy Collector (S2I Build)
```bash
# Create BuildConfig for automatic deployment from Git
oc apply -f deploy/buildconfig-collector.yaml

# Or trigger manual build
oc start-build attestation-collector-secure -n raj-compliance-dashboard
```

### Add Sidecar to CoCo Pods
```yaml
spec:
  containers:
  - name: coco-beacon-sidecar
    image: quay.io/jensfr/attestation-sidecar:secure
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
      value: "https://attestation-collector:8443"
    - name: TEE_TYPE
      value: "tdx"
    - name: REPORT_INTERVAL
      value: "30"
    - name: CLIENT_CERT_FILE
      value: "/etc/certs/client.crt"
    - name: CLIENT_KEY_FILE
      value: "/etc/certs/client.key"
    - name: CA_CERT_FILE
      value: "/etc/certs/ca.crt"
    volumeMounts:
    - name: client-certs
      mountPath: /etc/certs
      readOnly: true
  volumes:
  - name: client-certs
    secret:
      secretName: attestation-client-certs
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

✅ **Current Implementation**: Production-grade security
- **mTLS communication** with client certificate authentication
- **RSA-signed attestation reports** with cryptographic verification
- **KBS JWT token validation** for real attestation proof
- **Backward compatibility** for gradual migration from unsigned reports

🔒 **Security Features**:
- **Transport Security**: Mutual TLS (mTLS) on port 8443
- **Message Integrity**: RSA-PKCS1v15 signatures with SHA256 hashing
- **Attestation Verification**: Trustee KBS JWT token validation
- **Defense in Depth**: Both transport and application layer security
- **Enterprise Ready**: Supports certificate management and key rotation

## License

[MIT License](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

---

**Red Hat Summit 2025 Confidential Computing Demo**
*Lighthouse beacon for your confidential workloads* 🚨