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
cd /opt/app

#Buillding and testing
go build ./... || { echo "BUILD FAILED"; exit 1;}
go test ./...  || { echo "TESTS FAIED"; exit 1; }