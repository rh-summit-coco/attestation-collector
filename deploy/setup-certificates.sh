#!/bin/bash
set -e

echo "🔐 Setting up mTLS certificates for CoCo Beacon secure deployment"
echo "================================================================="

NAMESPACE=${NAMESPACE:-raj-compliance-dashboard}
CA_NAME="coco-beacon-ca"
SERVER_NAME="attestation-collector"
CLIENT_NAME="attestation-sidecar"

# Create temporary directory for certificate generation
CERT_DIR=$(mktemp -d)
echo "📁 Working in: $CERT_DIR"

cd $CERT_DIR

# Generate CA private key
echo "🔑 Generating CA private key..."
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
echo "🏛️  Generating CA certificate..."
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem -subj "/C=US/ST=MA/L=Boston/O=Red Hat/OU=CoCo Beacon/CN=CoCo Beacon CA"

# Generate server private key
echo "🔑 Generating server private key..."
openssl genrsa -out server-key.pem 4096

# Generate server certificate signing request
echo "📋 Generating server certificate request..."
openssl req -subj "/C=US/ST=MA/L=Boston/O=Red Hat/OU=CoCo Beacon/CN=attestation-collector" -sha256 -new -key server-key.pem -out server.csr

# Create server certificate extensions
echo "📝 Creating server certificate extensions..."
cat > server-extfile.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = attestation-collector
DNS.2 = attestation-collector.raj-compliance-dashboard
DNS.3 = attestation-collector.raj-compliance-dashboard.svc
DNS.4 = attestation-collector.raj-compliance-dashboard.svc.cluster.local
DNS.5 = attestation-collector-secure
DNS.6 = attestation-collector-secure.raj-compliance-dashboard
DNS.7 = attestation-collector-secure.raj-compliance-dashboard.svc
DNS.8 = attestation-collector-secure.raj-compliance-dashboard.svc.cluster.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server certificate
echo "🏆 Generating server certificate..."
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem -extfile server-extfile.cnf -CAcreateserial

# Generate client private key
echo "🔑 Generating client private key..."
openssl genrsa -out client-key.pem 4096

# Generate client certificate signing request
echo "📋 Generating client certificate request..."
openssl req -subj "/C=US/ST=MA/L=Boston/O=Red Hat/OU=CoCo Beacon/CN=attestation-sidecar" -new -key client-key.pem -out client.csr

# Create client certificate extensions
echo "📝 Creating client certificate extensions..."
cat > client-extfile.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

# Generate client certificate
echo "🏆 Generating client certificate..."
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem -out client-cert.pem -extfile client-extfile.cnf -CAcreateserial

# Create OpenShift secrets
echo "☸️  Creating OpenShift secrets..."

# Server certificates secret
oc create secret generic attestation-server-certs \
  --from-file=ca.crt=ca.pem \
  --from-file=server.crt=server-cert.pem \
  --from-file=server.key=server-key.pem \
  --namespace=$NAMESPACE \
  --dry-run=client -o yaml | oc apply -f -

# Client certificates secret
oc create secret generic attestation-client-certs \
  --from-file=ca.crt=ca.pem \
  --from-file=client.crt=client-cert.pem \
  --from-file=client.key=client-key.pem \
  --namespace=$NAMESPACE \
  --dry-run=client -o yaml | oc apply -f -

# Clean up
echo "🧹 Cleaning up temporary files..."
cd /
rm -rf $CERT_DIR

echo "✅ Certificate setup complete!"
echo ""
echo "📋 Created secrets:"
echo "  - attestation-server-certs (for collector deployment)"
echo "  - attestation-client-certs (for sidecar pods)"
echo ""
echo "🚀 Ready to deploy secure CoCo Beacon!"
echo ""
echo "Next steps:"
echo "1. Deploy BuildConfigs: oc apply -f deploy/buildconfig-*.yaml"
echo "2. Start builds: oc start-build attestation-collector-secure && oc start-build attestation-sidecar-secure"
echo "3. Deploy secure collector: oc apply -f deploy/deployment-secure.yaml"
echo "4. Update CoCo pods with secure sidecar configuration"