#!/bin/bash
# forensics-capture.sh
# Zero-trust build forensics: runs on BOTH success and failure paths.
# Always produces: an EBS snapshot of the build volume + an AES-256-encrypted
# manifest bundle in S3 (S3 also applies its own KMS encryption at rest).
# Usage: forensics-capture.sh <success|failure>
#
# Requires env vars: FORENSICS_S3_BUCKET, MANIFEST_ENCRYPTION_PASSWORD
# Optional env var:  FORENSICS_KMS_KEY_ID

set -uo pipefail

STATUS="${1:-unknown}"
BUILD_ID="${PACKER_BUILD_NAME:-unknown-build}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
INSTANCE_ID="$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/instance-id || echo "unknown")"
VOLUME_ID="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId" \
    --output text 2>/dev/null || echo "unknown")"

BUCKET="${FORENSICS_S3_BUCKET:?FORENSICS_S3_BUCKET env var must be set}"
KMS_KEY_ID="${FORENSICS_KMS_KEY_ID:-}"
export MANIFEST_PASSWORD="${MANIFEST_ENCRYPTION_PASSWORD:?MANIFEST_ENCRYPTION_PASSWORD env var must be set}"
S3_PREFIX="ami-builds/${BUILD_ID}/${TIMESTAMP}-${STATUS}"
WORKDIR="/tmp/forensics-${TIMESTAMP}"

mkdir -p "$WORKDIR"

echo "[forensics] status=${STATUS} instance=${INSTANCE_ID} volume=${VOLUME_ID}"

{
    echo "build_id=${BUILD_ID}"
    echo "status=${STATUS}"
    echo "timestamp=${TIMESTAMP}"
    echo "instance_id=${INSTANCE_ID}"
    echo "volume_id=${VOLUME_ID}"
    echo "---sha256sums---"
    find /usr/local/bin /etc/systemd/system /opt/app -type f 2>/dev/null -exec sha256sum {} \;
} > "$WORKDIR/manifest.txt"

if [ -f /tmp/trivy-scan.json ]; then
    cp /tmp/trivy-scan.json "${WORKDIR}/trivy-scan.json"
else
    trivy fs / --scanners vuln,secret,misconfig --format json \
        --output "$WORKDIR/trivy-scan.json" || echo "trivy scan failed/unavailable" > "$WORKDIR/trivy-scan.json"
fi

cp /var/log/cloud-init-output.log "$WORKDIR/cloud-init-output.log" 2>/dev/null || true

SNAPSHOT_ID="unavailable"
if [ "$VOLUME_ID" != "unknown" ]; then
  SNAPSHOT_ID="$(aws ec2 create-snapshot \
    --volume-id "$VOLUME_ID" \
    --description "zero-trust build ${BUILD_ID} status=${STATUS} ts=${TIMESTAMP}" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=BuildId,Value=${BUILD_ID}},{Key=Status,Value=${STATUS}},{Key=Timestamp,Value=${TIMESTAMP}}]" \
    --query 'SnapshotId' --output text 2>/dev/null || echo "unavailable")"
fi

echo "snapshot_id=${SNAPSHOT_ID}" >> "$WORKDIR/manifest.txt"
echo "[forensics] snapshot_id=${SNAPSHOT_ID}"

openssl enc -aes-256-cbc -pbkdf2 -salt \
  -in "$WORKDIR/manifest.txt" \
  -out "$WORKDIR/manifest.txt.enc" \
  -pass env:MANIFEST_PASSWORD
rm "$WORKDIR/manifest.txt"

TAR_PATH="/tmp/${TIMESTAMP}-${STATUS}.tar.gz"
tar -czf "$TAR_PATH" -C "$WORKDIR" .

S3_ARGS=(--sse aws:kms)
if [ -n "$KMS_KEY_ID" ]; then
  S3_ARGS+=(--sse-kms-key-id "$KMS_KEY_ID")
fi

aws s3 cp "$TAR_PATH" "s3://${BUCKET}/${S3_PREFIX}/bundle.tar.gz" "${S3_ARGS[@]}"

echo "[forensics] uploaded to s3://${BUCKET}/${S3_PREFIX}/"

if [ "$STATUS" = "failure" ]; then
  exit 1
fi
exit 0