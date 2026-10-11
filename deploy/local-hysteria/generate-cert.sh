#!/bin/sh
set -eu

cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout certs/localhost.key \
  -out certs/localhost.crt \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'
chmod 600 certs/localhost.key
echo "Created certs/localhost.crt and certs/localhost.key"
