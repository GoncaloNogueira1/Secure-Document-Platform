#!/usr/bin/env bash
# Generates the self-signed TLS material used by the local stack.
# Run once from the repository root: ./scripts/generate_certs.sh
set -euo pipefail
CERTS=infra/certs

leaf() {  # name, SAN
  local dir="$CERTS/$1"
  mkdir -p "$dir"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$dir/tls.key" -out "$dir/tls.crt" \
    -subj "/CN=$1" -addext "subjectAltName=$2"
}

leaf lb     "DNS:localhost,DNS:lb,IP:127.0.0.1"
leaf proxy1 "DNS:proxy1"
leaf proxy2 "DNS:proxy2"

# Elasticsearch / Kibana: local CA + server certificates
E="$CERTS/elastic"
mkdir -p "$E"
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout "$E/ca.key" -out "$E/ca.crt" -subj "/CN=ss-proj-local-ca"
for svc in elasticsearch kibana; do
  openssl req -newkey rsa:2048 -nodes -keyout "$E/$svc.key" -out "$E/$svc.csr" -subj "/CN=$svc"
  openssl x509 -req -in "$E/$svc.csr" -CA "$E/ca.crt" -CAkey "$E/ca.key" -CAcreateserial \
    -days 365 -out "$E/$svc.crt" -extfile "$E/$svc.ext"
done
chmod 600 "$CERTS"/*/*.key
echo "Certificates written to $CERTS"
