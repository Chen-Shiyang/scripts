#!/bin/bash
wget https://raw.githubusercontent.com/Chen-Shiyang/scripts/main/lightsocks.go
wget https://golang.org/dl/go1.16.7.linux-amd64.tar.gz
tar -zxvf go1.16.7.linux-amd64.tar.gz

cat >/etc/systemd/system/lightsocks.service<<-EOF
[Unit]
Description=lightsocks Service
After=network.target nss-lookup.target

[Service]
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/root/go/bin/go run /root/lightsocks.go
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lightsocks.service
systemctl restart lightsocks.service
