#!/bin/bash
if [ ! -d "/opt/manage-2fa" ]; then
    mkdir -p /opt/manage-2fa
fi
if [ ! -d "/opt/curls" ]; then
    mkdir -p /opt/curls
fi
cp main.py /opt/manage-2fa/main.py  && cp curl-*.sh /opt/curls/ && chmod +x /opt/curls/*.sh && pip3 install flask
cat <<EOF | sudo tee /etc/systemd/system/manage-2fa.service
[Unit]
Description=Manage 2FA Script
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/manage-2fa/main.py
WorkingDirectory=/opt/manage-2fa
Restart=always
User=root
Group=root
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable manage-2fa.service && systemctl start manage-2fa.service
