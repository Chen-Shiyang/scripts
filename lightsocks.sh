#!/bin/bash
wget https://raw.githubusercontent.com/Chen-Shiyang/scripts/main/lightsocks.go
wget https://golang.org/dl/go1.16.7.linux-amd64.tar.gz
tar -zxvf go1.16.7.linux-amd64.tar.gz
./go/bin/go run 
cat > /etc/systemd/system/lightsocks.service <<EOF
[Unit]
Description=lightsocks
After=network.target

[Service]
Type=simple
ExecStart=/root/go/bin/go run /root/lightsocks.go
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl start lightsocks
systemctl enable lightsocks
systemctl restart lightsocks
