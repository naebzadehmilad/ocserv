#!/bin/bash

CERT_DIR="/etc/ocserv/certs"
SERVER_CERT="$CERT_DIR/server-cert.pem"
SERVER_KEY="$CERT_DIR/server-key.pem"
DOMAIN="mn.test"
DAYS=3650

mkdir -p "$CERT_DIR"

openssl genpkey -algorithm RSA -out "$SERVER_KEY" -pkeyopt rsa_keygen_bits:2048

openssl req -new -key "$SERVER_KEY" -out "$CERT_DIR/server.csr" -subj "/CN=$DOMAIN"

openssl x509 -req -in "$CERT_DIR/server.csr" -signkey "$SERVER_KEY" -out "$SERVER_CERT" -days $DAYS

rm "$CERT_DIR/server.csr"

echo "Certificates generated at $SERVER_CERT and $SERVER_KEY"
