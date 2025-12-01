#!/bin/bash
set -e

echo "🔒 Deploying Secure CoCo Beacon (mTLS + JWT-signed reports)"
echo "============================================================"

# Step 1: Build the new secure collector image
echo "📦 Building secure collector image..."
cd /Users/jfreiman/code/summit-demo/attestation-collector
podman build -t attestation-collector:secure -f - . << 'EOF'
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
WORKDIR /app
COPY main.go .
RUN microdnf install -y golang && \
    go mod init attestation-collector && \
    go get && \
    go build -o attestation-collector . && \
    microdnf clean all
EXPOSE 8080 8443
ENTRYPOINT ["./attestation-collector"]
EOF

# Step 2: Tag for OpenShift registry
echo "🏷️  Tagging image for OpenShift registry..."
podman tag attestation-collector:secure image-registry.openshift-image-registry.svc:5000/raj-compliance-dashboard/attestation-collector:secure

# Step 3: Push to OpenShift
echo "📤 Pushing to OpenShift registry..."
podman login -u $(oc whoami) -p $(oc whoami -t) image-registry.openshift-image-registry.svc:5000
podman push image-registry.openshift-image-registry.svc:5000/raj-compliance-dashboard/attestation-collector:secure

# Step 4: Update deployment
echo "🔄 Updating deployment to use secure image..."
oc patch deployment attestation-collector -n raj-compliance-dashboard \
  --type='merge' \
  -p='{"spec":{"template":{"spec":{"containers":[{"name":"attestation-collector","image":"image-registry.openshift-image-registry.svc:5000/raj-compliance-dashboard/attestation-collector:secure"}]}}}}'

# Step 5: Wait for rollout
echo "⏳ Waiting for deployment to complete..."
oc rollout status deployment/attestation-collector -n raj-compliance-dashboard

echo ""
echo "✅ Secure CoCo Beacon deployed successfully!"
echo ""
echo "🔍 Testing the secure collector:"
echo "  Current collector API: $(oc get route attestation-collector -n raj-compliance-dashboard -o jsonpath='{.spec.host}')"
echo ""
echo "🔒 Security features now active:"
echo "  ✅ mTLS server (requires client certificates)"
echo "  ✅ JWT-signed report verification"
echo "  ✅ KBS token-based attestation"
echo "  ✅ Backward compatibility (accepts unsigned reports with warnings)"
echo ""
echo "📊 Monitor via dashboard: https://raj-hospital-dashboard-raj-compliance-dashboard.apps.uhfgfgde.eastus.aroapp.io"