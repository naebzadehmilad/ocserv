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
SYSCTL_CONF="/etc/sysctl.conf"
HOST_NAME="OC1"
ZONE="Asia/Tehran"


sudo apt update && sudo apt install -y ocserv libpam-google-authenticator nload iotop  prometheus-node-exporter python3-pip net-tools oathtool certbot nftables

cp pam.sh /opt/pam.sh && chmod +x /opt/pam.sh  
cp nftables.conf /etc/nftables.conf

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


cat <<EOL >> $SYSCTL_CONF
###########
###########
###########

#net.ipv4.tcp_syncookies = 1

fs.file-max = 1000000

net.core.somaxconn = 32000
net.ipv4.tcp_max_syn_backlog = 2048

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 65536 4194304

net.core.netdev_max_backlog = 5000

net.ipv4.ip_default_ttl = 64

net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1

net.ipv4.tcp_tw_reuse = 1

net.ipv4.tcp_mem = 65536 131072 262144

net.ipv4.conf.default.rp_filter = 2
############
############
############
EOL

sysctl -p && sysctl --system 




mkdir -p "$CERT_DIR"

openssl genpkey -algorithm RSA -out "$SERVER_KEY" -pkeyopt rsa_keygen_bits:2048

openssl req -new -key "$SERVER_KEY" -out "$CERT_DIR/server.csr" -subj "/CN=$DOMAIN"

openssl x509 -req -in "$CERT_DIR/server.csr" -signkey "$SERVER_KEY" -out "$SERVER_CERT" -days $DAYS

rm "$CERT_DIR/server.csr"

echo "Certificates generated at $SERVER_CERT and $SERVER_KEY"

timedatectl set-timezone $ZONE
hostnamectl set-hostname $HOST_NAME

systemctl enable  prometheus-node-exporter
systemctl start  prometheus-node-exporter
systemctl enable ocserv &&  systemctl restart ocserv
#systemctl enable nftables && systemctl start nftables

#sudo firewall-cmd --zone=public --add-interface=eth0 --permanent
#sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.8.0.0/16" masquerade'

