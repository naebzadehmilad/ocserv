#!/bin/bash

CERT_DIR="/etc/ocserv/certs"
SERVER_CERT="$CERT_DIR/server-cert.pem"
SERVER_KEY="$CERT_DIR/server-key.pem"
DOMAIN="mn.test"
DAYS=3650
OCSERV_CONFIG="/etc/ocserv/ocserv.conf"
OCSERV_CONFIG_SRC="./ocserv.conf"
PAM_CONFIG="/etc/pam.d/ocserv"
GOOGLE_AUTH_SCRIPT="./ocserv"

sudo apt update && sudo apt install -y ocserv libpam-google-authenticator


if [ -f "$OCSERV_CONFIG_SRC" ]; then
    sudo cp  "$OCSERV_CONFIG_SRC" "$OCSERV_CONFIG"
else
    echo "ocserv.conf Not found ..."
    exit 1
fi

if [ -f "$GOOGLE_AUTH_SCRIPT" ]; then
    sudo cp  "$GOOGLE_AUTH_SCRIPT" "$PAM_CONFIG"
else
    echo "ocserv Not found ..."
    exit 1
fi

mkdir -p "$CERT_DIR"

openssl genpkey -algorithm RSA -out "$SERVER_KEY" -pkeyopt rsa_keygen_bits:2048

openssl req -new -key "$SERVER_KEY" -out "$CERT_DIR/server.csr" -subj "/CN=$DOMAIN"

openssl x509 -req -in "$CERT_DIR/server.csr" -signkey "$SERVER_KEY" -out "$SERVER_CERT" -days $DAYS

rm "$CERT_DIR/server.csr"

echo "Certificates generated at $SERVER_CERT and $SERVER_KEY"

systemctl enable ocserv &&  systemctl restart ocserv

#sudo firewall-cmd --zone=public --add-interface=eth0 --permanent
#sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.8.0.0/16" masquerade'

