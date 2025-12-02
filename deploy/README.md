# Secure CoCo Beacon Deployment Guide

This directory contains the deployment manifests and scripts for the **secure** CoCo Beacon implementation with mTLS + JWT-signed attestation reports.

## 🔒 Security Features

- **Mutual TLS (mTLS)**: Client certificate authentication on port 8443
- **JWT-Signed Reports**: RSA-PKCS1v15 signatures with SHA256 hashing
- **KBS Token Verification**: Real cryptographic attestation via Trustee KBS
- **Defense in Depth**: Both transport and application layer security
- **Backward Compatibility**: Accepts unsigned reports with warnings

## 🚀 Quick Deployment

### Prerequisites

- OpenShift cluster with `raj-compliance-dashboard` namespace
- `oc` CLI configured and logged in
- OpenSSL for certificate generation

### Step 1: Set Up Git Repository

The BuildConfigs expect a Git repository at `https://github.com/rh-summit-coco/attestation-collector.git`.

```bash
# If repository doesn't exist, create it and push this code:
git remote add origin https://github.com/rh-summit-coco/attestation-collector.git
git push -u origin main
```

### Step 2: Generate mTLS Certificates

```bash
# Generate CA, server, and client certificates
./setup-certificates.sh
```

This creates two OpenShift secrets:
- `attestation-server-certs` - for the collector deployment
- `attestation-client-certs` - for sidecar pods

### Step 3: Deploy S2I BuildConfigs

```bash
# Create BuildConfigs and ImageStreams
oc apply -f buildconfig-collector.yaml
oc apply -f buildconfig-sidecar.yaml

# Trigger initial builds
oc start-build attestation-collector-secure
oc start-build attestation-sidecar-secure

# Monitor build progress
oc logs -f bc/attestation-collector-secure
oc logs -f bc/attestation-sidecar-secure
```

### Step 4: Deploy Secure Collector

```bash
# Deploy the secure collector with mTLS support
oc apply -f deployment-secure.yaml

# Monitor deployment
oc get pods -l app=attestation-collector-secure
oc logs -f deployment/attestation-collector-secure
```

### Step 5: Update CoCo Pod Sidecars

Add the secure sidecar to your CoCo pods:

```yaml
spec:
  containers:
  - name: coco-beacon-sidecar
    image: image-registry.openshift-image-registry.svc:5000/raj-compliance-dashboard/attestation-sidecar-secure:latest
    env:
    - name: COLLECTOR_URL
      value: "https://attestation-collector-secure:8443"
    - name: CLIENT_CERT_FILE
      value: "/etc/certs/client.crt"
    - name: CLIENT_KEY_FILE
      value: "/etc/certs/client.key"
    - name: CA_CERT_FILE
      value: "/etc/certs/ca.crt"
    # ... other env vars
    volumeMounts:
    - name: client-certs
      mountPath: /etc/certs
      readOnly: true
  volumes:
  - name: client-certs
    secret:
      secretName: attestation-client-certs
```

## 📊 Verification

### Test Secure API

```bash
# Get collector route
COLLECTOR_URL=$(oc get route attestation-collector-secure -o jsonpath='{.spec.host}')

# Test health endpoint (HTTP - no cert required)
curl https://$COLLECTOR_URL/api/v1/health

# Test reports endpoint (HTTPS with client cert)
oc run test-client --rm -i --tty --image=registry.access.redhat.com/ubi9/ubi:latest -- bash
# Inside container:
curl -k --cert /etc/certs/client.crt --key /etc/certs/client.key \
  https://attestation-collector-secure.raj-compliance-dashboard.svc:8443/api/v1/reports
```

### Check Logs

```bash
# Collector logs - should show signature verification
oc logs -f deployment/attestation-collector-secure

# Look for messages like:
# "Signature verified for janine-app/hospital-pod"
# "Warning: Received unsigned report from default/test-pod"
```

### Monitor Dashboard

The RAJ Hospital Dashboard should show attestation status:
- **Green**: Signed and verified reports
- **Yellow**: Unsigned reports (backward compatibility)
- **Red**: Failed signature verification

## 🔧 Troubleshooting

### Build Issues

```bash
# Check build logs
oc logs -f bc/attestation-collector-secure

# Common issues:
# - Git repository not accessible
# - Go dependencies not resolved
# - Dockerfile syntax errors
```

### Certificate Issues

```bash
# Verify certificates exist
oc get secrets attestation-server-certs attestation-client-certs

# Check certificate content
oc get secret attestation-server-certs -o jsonpath='{.data.server\.crt}' | base64 -d | openssl x509 -text -noout

# Recreate certificates if needed
./setup-certificates.sh
```

### TLS Connection Issues

```bash
# Test with curl verbose output
curl -v -k --cert client.crt --key client.key https://collector:8443/api/v1/health

# Check if mTLS server is running
oc get pods -l app=attestation-collector-secure
oc port-forward deployment/attestation-collector-secure 8443:8443
```

## 🔄 Automated Deployment Pipeline

For GitOps-style deployment, the BuildConfigs include webhook triggers:

```bash
# GitHub webhook URL (configure in your Git repository settings):
https://api.CLUSTER_DOMAIN/apis/build.openshift.io/v1/namespaces/raj-compliance-dashboard/buildconfigs/attestation-collector-secure/webhooks/secure-collector-webhook-secret/github

# When code is pushed to main branch:
# 1. GitHub webhook triggers BuildConfig
# 2. OpenShift builds new image from Git
# 3. Deployment automatically pulls new image (if configured)
# 4. Pods restart with updated secure implementation
```

## 📝 Files Description

- `buildconfig-collector.yaml` - S2I BuildConfig for secure collector
- `buildconfig-sidecar.yaml` - S2I BuildConfig for secure sidecar
- `deployment-secure.yaml` - Deployment, Service, and Route for secure collector
- `setup-certificates.sh` - Script to generate mTLS certificates
- `../Dockerfile.collector` - Multi-stage Docker build for collector
- `../Dockerfile.sidecar` - Multi-stage Docker build for sidecar

## 🔗 Related Documentation

- [Main README](../README.md) - CoCo Beacon overview and API reference
- [Integration Guide](../INTEGRATION.md) - Integration with hospital applications
- [Security Architecture](../SECURITY.md) - Detailed security implementation