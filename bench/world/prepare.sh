#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)

if [ ! -f "$here/.env" ]; then
  secret=$(openssl rand -base64 32)
  printf 'DASHBOARD_PASSWORD=%s\n' "$secret" > "$here/.env"
  chmod 600 "$here/.env"
  echo "wrote a fresh operator password to $here/.env"
else
  echo "keeping the operator password already in $here/.env"
fi

if [ ! -f "$here/tls/cert.pem" ]; then
  mkdir -p "$here/tls"
  openssl req -x509 -newkey rsa:2048 -keyout "$here/tls/key.pem" -out "$here/tls/cert.pem" \
    -days 30 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:world-proxy,IP:127.0.0.1" 2>/dev/null
  chmod 644 "$here/tls/key.pem"
  echo "wrote a self-signed certificate to $here/tls"
else
  echo "keeping the certificate already in $here/tls"
fi

echo
echo "neither is committed: both are ignored by git."
echo "sign in with:"
sed -n 's/^DASHBOARD_PASSWORD=/  /p' "$here/.env"
