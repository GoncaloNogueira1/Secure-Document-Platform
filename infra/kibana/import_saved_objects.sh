#!/bin/sh
set -eu

echo "Waiting for Kibana at ${KIBANA_URL}..."

until curl -fsS --cacert /certs/ca.crt \
  -u "elastic:${ELASTIC_PASSWORD}" \
  "${KIBANA_URL}/login" >/dev/null; do
  echo "Kibana not ready yet..."
  sleep 5
done

for f in /saved_objects/*.ndjson; do
  [ -f "$f" ] || continue

  echo "Importing $f"

  curl -fsS --cacert /certs/ca.crt \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -H "kbn-xsrf: true" \
    --form file=@"$f" \
    "${KIBANA_URL}/api/saved_objects/_import?overwrite=true"
done

echo "Saved object import complete."