#!/bin/bash
set -euo pipefail

export HOME=/root/
export GOCACHE=/root/.cache/go-build
export GOPATH=/root/go
dnf update -y
dnf install -y git golang nodejs 

# Docker on AL2023
dnf install -y docker
systemctl enable docker
systemctl start docker

#pulling repo
git clone https://github.com/StudentOsowle/go_pre_pipeline.git /opt/app
cd /opt/app/go

#Building and testing
go build ./... || { echo "BUILD FAILED"; exit 1;}
go test ./...  || { echo "TESTS FAILED"; exit 1; }

# Build the actual WAF binary and place it where the systemd service expects it
go build -o /usr/local/bin/waf . || { echo "WAF BINARY BUILD FAILED"; exit 1; }

cat > /etc/systemd/system/waf.service <<'EOF'
[Unit]
Description=Go WAF reverse proxy
After=network.target

[Service]
WorkingDirectory=/opt/app/go
ExecStart=/usr/local/bin/waf
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable waf
systemctl start waf