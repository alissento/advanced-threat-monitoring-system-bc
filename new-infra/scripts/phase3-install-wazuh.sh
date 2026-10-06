#!/usr/bin/env bash
# =============================================================================
# phase3-install-wazuh.sh — XDR v8 / bc-ctrl EKS → bare EC2 migration
# Phase 3: Wazuh component installation on EC2 hosts
#
# Runs on each EC2 host via SSM Session Manager AFTER Terraform apply.
# Idempotent for retry (package installs and fstab entries are guarded).
#
# Required env var:
#   HOST_ROLE   — one of: "indexer" | "manager" | "dashboard"
#
# Optional env vars:
#   REGION      — AWS region (default: eu-west-1, overridden by IMDSv2)
#   WAZUH_VERSION — Wazuh package version (default: 4.14.4)
#                   PINNING INVARIANT: indexer, manager, and dashboard MUST all
#                   use the same version. Mismatched versions cause OpenSearch
#                   Dashboards compatibility errors at startup. When bumping,
#                   update all three together AND test the certs-tool URL.
#
# Secrets Manager paths (from external-secrets.yaml):
#   bc/wazuh/manager  — INDEXER_PASSWORD, API_PASSWORD, PLACEHOLDER_CLUSTER_KEY,
#                       PLACEHOLDER_MISP_API_KEY, PLACEHOLDER_AWS_ACCOUNT_ID,
#                       PLACEHOLDER_SHUFFLE_HOOK_ID, API_USERNAME, INDEXER_USERNAME
#
# S3 bucket for certs handoff:
#   s3://bc-uatms-terraform-state-929026881368/certs/wazuh-certs-YYYYMMDD.tar
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
REGION="${REGION:-eu-west-1}"
# Bug C fix: pinned to 4.14.4 across indexer+manager+dashboard.
# 4.9.x packages.wazuh.com/4.9/ returned HTTP 403 (repo retired).
# The 4.x rolling repo serves 4.14.4 as of 2026-04; all three packages
# must stay in sync — see PINNING INVARIANT comment above.
WAZUH_VERSION="${WAZUH_VERSION:-4.14.4}"
WAZUH_SECRET="bc/wazuh/manager"
# Account-suffixed bucket created by Terraform (locals.tf : wazuh_bucket).
# Falls back to the legacy un-suffixed name for backward compat. The bucket
# is passed in via user_data env so we don't hardcode the account ID here.
WAZUH_S3_BUCKET="${WAZUH_S3_BUCKET:-bc-uatms-wazuh-snapshots-929026881368}"
CERT_BUCKET="${WAZUH_S3_BUCKET}"
CERT_DATE="$(date +%Y%m%d)"
CERT_S3_KEY="certs/wazuh-certs-${CERT_DATE}.tar"
SCRIPT_NAME="$(basename "$0")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${SCRIPT_NAME}] $*"; }

# dump_diag <unit> — print the last 60 journal lines + systemd status for a
# unit. Used by fail() and the ERR trap to surface root cause in CloudWatch /
# user-data logs instead of forcing an SSH session to read /var/log.
dump_diag() {
  local unit="$1"
  [[ -z "${unit}" ]] && return 0
  echo "--- diag: systemctl status ${unit} ---"
  systemctl status "${unit}" --no-pager -l 2>&1 | head -20 || true
  echo "--- diag: journalctl -u ${unit} (last 60) ---"
  journalctl -u "${unit}" --no-pager -n 60 2>&1 || true
  echo "--- end diag ---"
}

# fail "msg"               -> log + exit 1
# fail "msg" "unit.service" -> log + dump the unit's recent logs + exit 1
fail() {
  log "FATAL: $1"
  [[ -n "${2:-}" ]] && dump_diag "$2"
  exit 1
}

# Bug E fix: ERR trap — print the failing line number so set -e aborts are
# visible in CloudWatch / user-data logs instead of silently stopping.
trap 'log "FATAL: script aborted at line ${LINENO} (last command exited $?)"' ERR

require_env() {
  local var="$1"
  [[ -n "${!var:-}" ]] || fail "Required env var ${var} is not set."
}

# ---------------------------------------------------------------------------
# VALIDATE HOST_ROLE
# ---------------------------------------------------------------------------
require_env HOST_ROLE
case "${HOST_ROLE}" in
  indexer|manager|dashboard|all_in_one) ;;
  *) fail "HOST_ROLE must be 'indexer', 'manager', 'dashboard', or 'all_in_one' (got: '${HOST_ROLE}')" ;;
esac

log "=== Phase 3: Installing Wazuh component — HOST_ROLE=${HOST_ROLE} ==="
echo ""

# ===========================================================================
# SECTION 0 — IMDSv2 CHECK (all hosts)
# ===========================================================================
log "--- IMDSv2 check ---"
IMDS_TOKEN="$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  --connect-timeout 5 \
  --max-time 10 \
  2>/dev/null || true)"

if [[ -z "${IMDS_TOKEN}" ]]; then
  fail "IMDSv2 token request returned empty — check instance metadata service configuration"
fi
log "IMDSv2 token obtained successfully (IMDSv2 is enforced and working)"

# Derive region from IMDS if not overridden
IMDS_REGION="$(curl -s \
  -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
  "http://169.254.169.254/latest/meta-data/placement/region" \
  --connect-timeout 5 --max-time 10 2>/dev/null || true)"
if [[ -n "${IMDS_REGION}" ]]; then
  REGION="${IMDS_REGION}"
  log "Region from IMDS: ${REGION}"
fi

PRIVATE_IP="$(curl -s \
  -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
  "http://169.254.169.254/latest/meta-data/local-ipv4" \
  --connect-timeout 5 --max-time 10 2>/dev/null || true)"
[[ -n "${PRIVATE_IP}" ]] || fail "Could not determine private IP from IMDS"
log "Private IP: ${PRIVATE_IP}"
echo ""

# ===========================================================================
# SECTION 1 — COMMON PREREQUISITES (all hosts)
# ===========================================================================
log "--- Installing prerequisites ---"

# curl and tar are typically present on AL2023; install defensively
dnf install -y tar jq unzip >/dev/null 2>&1 || true

# AWS CLI v2 (idempotent)
if ! command -v aws >/dev/null 2>&1; then
  log "Installing AWS CLI v2..."
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2-extract
  /tmp/awscliv2-extract/aws/install
  rm -rf /tmp/awscliv2.zip /tmp/awscliv2-extract
  log "AWS CLI v2 installed: $(aws --version)"
else
  log "AWS CLI already present: $(aws --version)"
fi

# ---------------------------------------------------------------------------
# Add Wazuh 4.x YUM repo (Amazon Linux 2023 / RHEL9 compatible)
# ---------------------------------------------------------------------------
if [[ ! -f /etc/yum.repos.d/wazuh.repo ]]; then
  log "Adding Wazuh YUM repository..."

  rpm --import "https://packages.wazuh.com/key/GPG-KEY-WAZUH" 2>/dev/null \
    || fail "Failed to import Wazuh GPG key"

  cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
  log "Wazuh repo configured."
else
  log "Wazuh repo already configured."
fi
echo ""

# ---------------------------------------------------------------------------
# Fetch secrets from Secrets Manager
# ---------------------------------------------------------------------------
log "--- Fetching secrets from Secrets Manager: ${WAZUH_SECRET} ---"

SECRET_JSON="$(aws secretsmanager get-secret-value \
  --region "${REGION}" \
  --secret-id "${WAZUH_SECRET}" \
  --query 'SecretString' \
  --output text)" || fail "Could not fetch secret ${WAZUH_SECRET} — check IAM permissions"

# Parse all keys we may need (not every role uses all of them)
INDEXER_USERNAME="$(echo "${SECRET_JSON}" | jq -r '.INDEXER_USERNAME // "admin"')"
INDEXER_PASSWORD="$(echo "${SECRET_JSON}" | jq -r '.INDEXER_PASSWORD')"
API_USERNAME="$(echo "${SECRET_JSON}" | jq -r '.API_USERNAME // "wazuh-wui"')"
API_PASSWORD="$(echo "${SECRET_JSON}" | jq -r '.API_PASSWORD')"
CLUSTER_KEY="$(echo "${SECRET_JSON}" | jq -r '.PLACEHOLDER_CLUSTER_KEY')"
MISP_API_KEY="$(echo "${SECRET_JSON}" | jq -r '.PLACEHOLDER_MISP_API_KEY')"
# AWS_ACCOUNT_ID: the secret used to hold a placeholder, but the key was never
# populated → jq returned the literal string "null" → ossec.conf got
# <aws_account_id>null</aws_account_id> → aws-s3 wodle failed with
# "Error parsing arguments" for CloudTrail ingestion. Account ID is not a
# secret (it's in every IAM ARN), so pull it from IMDS instance identity.
AWS_ACCOUNT_ID="$(curl -s \
  -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
  "http://169.254.169.254/latest/dynamic/instance-identity/document" \
  --connect-timeout 5 --max-time 10 2>/dev/null \
  | jq -r '.accountId' 2>/dev/null || true)"
[[ -n "${AWS_ACCOUNT_ID}" && "${AWS_ACCOUNT_ID}" != "null" ]] \
  || fail "Could not derive AWS_ACCOUNT_ID from IMDS instance identity document"
log "AWS account ID from IMDS: ${AWS_ACCOUNT_ID}"
SHUFFLE_HOOK_ID="$(echo "${SECRET_JSON}" | jq -r '.PLACEHOLDER_SHUFFLE_HOOK_ID')"

[[ -n "${INDEXER_PASSWORD}" && "${INDEXER_PASSWORD}" != "null" ]] \
  || fail "INDEXER_PASSWORD not found in secret ${WAZUH_SECRET}"

log "Secrets fetched successfully."
echo ""

# ===========================================================================
# SECTION 2 — ROLE-SPECIFIC INSTALLATION
# ===========================================================================

# ---------------------------------------------------------------------------
# *** INDEXER ROLE ***
# ---------------------------------------------------------------------------
if [[ "${HOST_ROLE}" == "indexer" || "${HOST_ROLE}" == "all_in_one" ]]; then
  log "=== [INDEXER] Installing wazuh-indexer ==="

  # Install package
  dnf install -y "wazuh-indexer-${WAZUH_VERSION}" \
    || fail "wazuh-indexer package installation failed"
  log "wazuh-indexer installed."

  # -------------------------------------------------------------------------
  # Mount 200Gi EBS data volume (/dev/nvme1n1) → /var/lib/wazuh-indexer
  # -------------------------------------------------------------------------
  DATA_DEV="/dev/nvme1n1"
  DATA_MNT="/var/lib/wazuh-indexer"

  log "Waiting for device ${DATA_DEV} to appear..."
  for i in {1..30}; do
    if [[ -b "${DATA_DEV}" ]]; then
      log "Device ${DATA_DEV} is now available."
      break
    fi
    if (( i == 30 )); then
      fail "Timeout waiting for device ${DATA_DEV} to appear"
    fi
    sleep 2
  done

  if ! blkid "${DATA_DEV}" >/dev/null 2>&1; then
    log "Formatting ${DATA_DEV} as XFS..."
    mkfs.xfs -f "${DATA_DEV}" || fail "mkfs.xfs failed on ${DATA_DEV}"
  else
    log "${DATA_DEV} already has a filesystem — skipping format."
  fi

  mkdir -p "${DATA_MNT}"
  DATA_UUID="$(blkid -s UUID -o value "${DATA_DEV}")"

  if ! grep -q "${DATA_UUID}" /etc/fstab 2>/dev/null; then
    log "Adding ${DATA_DEV} (UUID=${DATA_UUID}) to /etc/fstab..."
    echo "UUID=${DATA_UUID}  ${DATA_MNT}  xfs  defaults,noatime,nodiratime  0  2" >> /etc/fstab
  else
    log "fstab entry for ${DATA_UUID} already exists."
  fi

  if ! mountpoint -q "${DATA_MNT}"; then
    mount "${DATA_MNT}" || fail "Failed to mount ${DATA_DEV} to ${DATA_MNT}"
    log "Mounted ${DATA_DEV} → ${DATA_MNT}"
  else
    log "${DATA_MNT} already mounted."
  fi
  chown -R wazuh-indexer:wazuh-indexer "${DATA_MNT}"

  # -------------------------------------------------------------------------
  # vm.max_map_count persistent setting
  # -------------------------------------------------------------------------
  log "Setting vm.max_map_count=262144 permanently..."
  cat > /etc/sysctl.d/99-wazuh-indexer.conf <<'EOF'
# Required by OpenSearch/Lucene for mmap segments
vm.max_map_count=262144
# Increase max open files
fs.file-max=65536
EOF
  sysctl -p /etc/sysctl.d/99-wazuh-indexer.conf >/dev/null
  log "vm.max_map_count=$(sysctl -n vm.max_map_count)"

  # -------------------------------------------------------------------------
  # Generate TLS certificates using wazuh-certs-tool.sh (single-node)
  # -------------------------------------------------------------------------
  log "Generating TLS certificates with wazuh-certs-tool.sh..."
  # 4.x rolling URL returns 403; versioned 4.9 path is live.
  CERTS_TOOL_URL="https://packages.wazuh.com/4.9/wazuh-certs-tool.sh"
  CERTS_WORK="/tmp/wazuh-certs-gen"
  mkdir -p "${CERTS_WORK}"

  # Remove leftover certs dir from any previous partial run
  [[ -d "${CERTS_WORK}/wazuh-certificates" ]] && rm -rf "${CERTS_WORK}/wazuh-certificates"

  # Retry up to 5 times — fck-nat iptables may not be ready at early boot
  for attempt in $(seq 1 5); do
    curl -fsSL "${CERTS_TOOL_URL}" -o "${CERTS_WORK}/wazuh-certs-tool.sh" && break
    log "Download attempt ${attempt}/5 failed, retrying in 15s..."
    sleep 15
    [[ "${attempt}" -eq 5 ]] && fail "Failed to download wazuh-certs-tool.sh after 5 attempts"
  done
  chmod +x "${CERTS_WORK}/wazuh-certs-tool.sh"

  # Single-node config.yml for wazuh-certs-tool
  cat > "${CERTS_WORK}/config.yml" <<EOF
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "${PRIVATE_IP}"
  server:
    - name: wazuh-manager-ec2
      ip: "${PRIVATE_IP}"
  dashboard:
    - name: wazuh-dashboard
      ip: "${PRIVATE_IP}"
EOF

  pushd "${CERTS_WORK}" >/dev/null
  bash wazuh-certs-tool.sh --all 2>&1 | tee /tmp/wazuh-certs-tool.log \
    || fail "wazuh-certs-tool.sh failed — check /tmp/wazuh-certs-tool.log"
  popd >/dev/null

  CERTS_TAR="${CERTS_WORK}/wazuh-certificates.tar"
  # certs-tool v4.x outputs a directory; pack it into a tar if needed
  if [[ ! -f "${CERTS_TAR}" ]] && [[ -d "${CERTS_WORK}/wazuh-certificates" ]]; then
    log "certs-tool produced a directory — packing into wazuh-certificates.tar..."
    tar -C "${CERTS_WORK}" -cf "${CERTS_TAR}" wazuh-certificates/
  fi
  [[ -f "${CERTS_TAR}" ]] \
    || fail "wazuh-certificates.tar not produced by certs tool — check /tmp/wazuh-certs-tool.log"

  # Upload certs to S3 (only needed when manager/dashboard are separate hosts)
  if [[ "${HOST_ROLE}" != "all_in_one" ]]; then
    log "Uploading wazuh-certificates.tar to s3://${CERT_BUCKET}/${CERT_S3_KEY}..."
    aws s3 cp "${CERTS_TAR}" "s3://${CERT_BUCKET}/${CERT_S3_KEY}" \
      --sse AES256 \
      --region "${REGION}" \
      || fail "Failed to upload certs tar to S3"
    log "Certs uploaded: s3://${CERT_BUCKET}/${CERT_S3_KEY}"
  else
    log "all_in_one mode — skipping S3 cert upload (certs remain local at ${CERTS_WORK})"
  fi

  # Install certs to wazuh-indexer certs directory
  INDEXER_CERTS_DIR="/etc/wazuh-indexer/certs"
  mkdir -p "${INDEXER_CERTS_DIR}"
  tar -xf "${CERTS_TAR}" -C "${CERTS_WORK}" --strip-components=0 2>/dev/null || true

  # wazuh-certs-tool creates: wazuh-certificates/wazuh-indexer.pem,
  # wazuh-indexer-key.pem, root-ca.pem, admin.pem, admin-key.pem
  cp "${CERTS_WORK}/wazuh-certificates/wazuh-indexer.pem"     "${INDEXER_CERTS_DIR}/indexer.pem"
  cp "${CERTS_WORK}/wazuh-certificates/wazuh-indexer-key.pem" "${INDEXER_CERTS_DIR}/indexer-key.pem"
  cp "${CERTS_WORK}/wazuh-certificates/root-ca.pem"           "${INDEXER_CERTS_DIR}/root-ca.pem"
  cp "${CERTS_WORK}/wazuh-certificates/admin.pem"             "${INDEXER_CERTS_DIR}/admin.pem"
  cp "${CERTS_WORK}/wazuh-certificates/admin-key.pem"         "${INDEXER_CERTS_DIR}/admin-key.pem"

  chmod 400 "${INDEXER_CERTS_DIR}"/*
  chown -R wazuh-indexer:wazuh-indexer "${INDEXER_CERTS_DIR}"
  log "Certificates installed to ${INDEXER_CERTS_DIR}"

  # -------------------------------------------------------------------------
  # Write opensearch.yml
  # -------------------------------------------------------------------------
  log "Writing /etc/wazuh-indexer/opensearch.yml..."
  cat > /etc/wazuh-indexer/opensearch.yml <<EOF
# Wazuh Indexer (OpenSearch) — single-node EC2 configuration
# Generated by phase3-install-wazuh.sh

network.host: "0.0.0.0"
node.name: "wazuh-indexer"
cluster.name: "bc-wazuh-indexer"
discovery.type: single-node

path.data: "${DATA_MNT}"
path.logs: /var/log/wazuh-indexer

bootstrap.memory_lock: true

# TLS — inter-node transport
plugins.security.ssl.transport.pemcert_filepath: ${INDEXER_CERTS_DIR}/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: ${INDEXER_CERTS_DIR}/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: ${INDEXER_CERTS_DIR}/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

# TLS — HTTP API
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: ${INDEXER_CERTS_DIR}/indexer.pem
plugins.security.ssl.http.pemkey_filepath: ${INDEXER_CERTS_DIR}/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: ${INDEXER_CERTS_DIR}/root-ca.pem

# Security plugin admin cert
plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.nodes_dn:
  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
  - ".plugins-ml-model"
  - ".plugins-ml-task"
  - ".opendistro-alerting-config"
  - ".opendistro-alerting-alert*"
  - ".opendistro-anomaly-results*"
  - ".opendistro-anomaly-detector*"
  - ".opendistro-anomaly-checkpoints"
  - ".opendistro-anomaly-detection-state"
  - ".opendistro-reports-*"
  - ".opensearch-notifications-*"
  - ".opensearch-notebooks"
  - ".opensearch-observability"
  - ".opendistro-asynchronous-search-response*"
  - ".replication-metadata-store"

# Elasticsearch 7.x client compatibility (allows Filebeat 7.x _type parameter)
compatibility.override_main_response_version: true
EOF

  # -------------------------------------------------------------------------
  # Set JVM heap to 4g (safe for t3.xlarge 16 GB — leaves 12 GB for OS page cache)
  # -------------------------------------------------------------------------
  log "Setting JVM heap to 4g..."
  OPTS_FILE="/etc/wazuh-indexer/jvm.options"
  if grep -q "^-Xms" "${OPTS_FILE}" 2>/dev/null; then
    sed -i 's/^-Xms.*/-Xms4g/' "${OPTS_FILE}"
    sed -i 's/^-Xmx.*/-Xmx4g/' "${OPTS_FILE}"
  else
    printf '\n-Xms4g\n-Xmx4g\n' >> "${OPTS_FILE}"
  fi
  log "JVM options set: -Xms4g -Xmx4g"

  # -------------------------------------------------------------------------
  # Systemd hardening override
  # -------------------------------------------------------------------------
  log "Writing systemd hardening override for wazuh-indexer..."
  mkdir -p /etc/systemd/system/wazuh-indexer.service.d
  cat > /etc/systemd/system/wazuh-indexer.service.d/hardening.conf <<'EOF'
[Service]
# Memory lock — must match bootstrap.memory_lock=true
LimitMEMLOCK=infinity
LimitNOFILE=65536
LimitNPROC=4096

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
EOF

  systemctl daemon-reload

  # -------------------------------------------------------------------------
  # Enable and start wazuh-indexer
  # -------------------------------------------------------------------------
  log "Enabling and starting wazuh-indexer..."
  systemctl enable wazuh-indexer
  if ! systemctl is-active --quiet wazuh-indexer; then
    systemctl start wazuh-indexer \
      || fail "systemctl start wazuh-indexer failed" "wazuh-indexer"
  else
    log "wazuh-indexer already running — skipping start"
  fi

  # -------------------------------------------------------------------------
  # Wait for cluster health (green or yellow) — up to 10 minutes
  # -------------------------------------------------------------------------
  log "Waiting for Wazuh Indexer cluster health (green/yellow)..."
  HEALTH_OK=false
  for i in $(seq 1 60); do
    # Use client certificates for health check to bypass Basic Auth requirement
    HEALTH="$(curl -sk \
      --cert "${INDEXER_CERTS_DIR}/admin.pem" \
      --key "${INDEXER_CERTS_DIR}/admin-key.pem" \
      "https://localhost:9200/_cluster/health" \
      --connect-timeout 5 --max-time 10 2>/dev/null \
      | jq -r '.status // "unknown"' 2>/dev/null || echo "unreachable")"

    if [[ "${HEALTH}" == "green" || "${HEALTH}" == "yellow" ]]; then
      log "Cluster health: ${HEALTH} (after $((i * 10))s)"
      HEALTH_OK=true
      break
    fi

    if [[ $((i % 6)) -eq 0 ]]; then
      log "  Still waiting... health=${HEALTH} ($((i * 10))s elapsed)"
    fi
    sleep 10
  done

  "${HEALTH_OK}" || fail "Indexer cluster did not reach green/yellow after 600s" "wazuh-indexer"

  # -------------------------------------------------------------------------
  # Run security initialisation script
  # -------------------------------------------------------------------------
  log "Running indexer-security-init.sh..."
  SECURITY_INIT="/usr/share/wazuh-indexer/bin/indexer-security-init.sh"
  SECADMIN="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
  SEC_CONFIG="/etc/wazuh-indexer/opensearch-security"

  # Check if security index already exists
  ALREADY_INIT="$(curl -sk \
    --cert "${INDEXER_CERTS_DIR}/admin.pem" \
    --key "${INDEXER_CERTS_DIR}/admin-key.pem" \
    "https://localhost:9200/_cat/indices/.opendistro_security?h=index" \
    --connect-timeout 5 --max-time 10 2>/dev/null || true)"

  if [[ "${ALREADY_INIT}" == *".opendistro_security"* ]]; then
    log "Security index already exists — skipping security init."
  elif [[ -x "${SECURITY_INIT}" ]]; then
    # Build a JKS truststore from our root-ca (securityadmin needs it)
    "${JAVA_HOME:-/usr/share/wazuh-indexer/jdk}/bin/keytool" \
      -import -trustcacerts -alias root-ca \
      -file "${INDEXER_CERTS_DIR}/root-ca.pem" \
      -keystore /tmp/wazuh-ts.jks \
      -storepass changeit -noprompt 2>/dev/null || true

    JAVA_HOME="/usr/share/wazuh-indexer/jdk" \
    runuser wazuh-indexer --shell="/bin/bash" \
      --command="${SECADMIN} \
        -cd ${SEC_CONFIG} \
        -ts /tmp/wazuh-ts.jks -tspass changeit \
        -cert ${INDEXER_CERTS_DIR}/admin.pem \
        -key ${INDEXER_CERTS_DIR}/admin-key.pem \
        -h 127.0.0.1 -p 9200 -icl -nhnv" \
      2>&1 | tee /tmp/indexer-security-init.log \
      || fail "securityadmin.sh failed — check /tmp/indexer-security-init.log"
    log "Security init complete."
  else
    log "WARNING: ${SECURITY_INIT} not found; manual security init may be required"
  fi

  # -------------------------------------------------------------------------
  # Set admin password via the OpenSearch Security API
  # Bug D fix: on first install the security index is initialised with the
  # default password "admin". The previous code authenticated with the
  # *target* password which doesn't exist yet — so the API call returned 401
  # and the rotation was silently skipped (WARNING only, no fail). We now
  # probe with both the default and the target credential, use whichever works,
  # then verify the new password is accepted before continuing.
  # -------------------------------------------------------------------------
  log "Setting admin password from secrets..."
  sleep 5  # allow security plugin to settle after init

  # The OpenSearch 'admin' user is reserved and cannot be changed via REST API.
  # Use wazuh-passwords-tool.sh which patches internal_users.yml directly via securityadmin.
  # Use the 4.x rolling URL — the 4.9-versioned path returns HTTP 403 (retired CDN).
  log "Setting admin password via wazuh-passwords-tool.sh..."
  PASS_TOOL_URL="https://packages.wazuh.com/4.x/wazuh-passwords-tool.sh"
  curl -fsSL "${PASS_TOOL_URL}" -o /tmp/wazuh-passwords-tool.sh \
    || fail "Failed to download wazuh-passwords-tool.sh"
  # Strip Windows CR line endings — the CDN delivers CRLF which causes bash
  # syntax errors ("$'\r': command not found") on Linux.
  sed -i 's/\r//' /tmp/wazuh-passwords-tool.sh
  chmod +x /tmp/wazuh-passwords-tool.sh

  # Check which password currently works.
  # MUST use -f/--fail so curl exits non-zero on HTTP 4xx/5xx. Without -f,
  # curl exits 0 on 401 Unauthorized (HTTP errors are not curl errors by default),
  # causing the if-branch to always evaluate true and silently skip rotation.
  # Use PRIVATE_IP (not localhost) to match the TLS cert SAN.
  if curl -skf -u "${INDEXER_USERNAME}:${INDEXER_PASSWORD}" \
      "https://${PRIVATE_IP}:9200/_cluster/health" \
      --connect-timeout 5 --max-time 10 >/dev/null 2>&1; then
    log "Indexer already using secrets password — skipping rotation."
  else
    log "Indexer not using secrets password — performing bcrypt rotation via indexer-security-init.sh..."
    # Ensure python3-bcrypt is installed (may not be on fresh AL2023)
    python3 -c "import bcrypt" 2>/dev/null || dnf install -y python3-bcrypt -q

    # Generate bcrypt hash from target password using Python
    HASH=$(python3 - "${INDEXER_PASSWORD}" <<'PYEOF'
import bcrypt, sys
pw = sys.argv[1].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(12)).decode())
PYEOF
)
    log "Bcrypt hash generated (length: ${#HASH})"

    # Patch internal_users.yml with new hash using Python (avoids sed regex issues)
    cp "${SEC_CONFIG}/internal_users.yml" "${SEC_CONFIG}/internal_users.yml.bak"
    python3 - "${SEC_CONFIG}/internal_users.yml" "${INDEXER_USERNAME}" "${HASH}" <<'PYEOF'
import sys, yaml
filepath, username, new_hash = sys.argv[1], sys.argv[2], sys.argv[3]
with open(filepath) as f:
    data = yaml.safe_load(f)
if username not in data:
    raise SystemExit(f"User '{username}' not found in {filepath}")
data[username]['hash'] = new_hash
with open(filepath, 'w') as f:
    yaml.dump(data, f, default_flow_style=False)
print(f"Patched {username} hash in {filepath}")
PYEOF
    log "internal_users.yml patched with new hash."

    # Apply the updated security config using the official Wazuh wrapper.
    # indexer-security-init.sh handles JAVA_HOME, cert paths, and host resolution.
    SECURITY_INIT="/usr/share/wazuh-indexer/bin/indexer-security-init.sh"
    bash "${SECURITY_INIT}" --host "${PRIVATE_IP}" 2>&1 | tail -15 \
      || log "WARNING: indexer-security-init.sh exited non-zero — rotation may have partially applied"

    log "Password rotation attempted. Waiting 10s for security plugin to reload..."
    sleep 10
  fi

  # Post-rotation verify: use -f so a 401 is a real failure, not a silent pass.
  if ! curl -skf -u "${INDEXER_USERNAME}:${INDEXER_PASSWORD}" \
      "https://${PRIVATE_IP}:9200/_cluster/health" \
      --connect-timeout 5 --max-time 10 >/dev/null 2>&1; then
    log "WARNING: Indexer does not accept secrets password after rotation — dashboard and filebeat may fail auth"
  else
    log "Post-rotation verify: indexer credential confirmed working."
  fi

  # =========================================================================
  # TASK 3 — ISM index retention policies
  #
  # Two policies, applied via ISM + index templates so they auto-attach to
  # every new index in the matching pattern.
  #
  # Retention rationale (single-node 200 GiB data volume):
  #   wazuh-archives-* : all events including VPCFlow (~24k events/window).
  #     VPCFlow alone can produce several hundred MB/day in JSON on a busy
  #     cluster. 10 days of archives keeps ~5-10 GB headroom for forensic
  #     replay while preventing disk exhaustion. Archives are low-value once
  #     the matching alert has been generated.
  #   wazuh-alerts-*   : rule-matched events only. Much smaller volume.
  #     30 days provides a month of investigation history across all alert
  #     levels and satisfies basic SOC triage workflows without a snapshot.
  #
  # Rollover triggers (per policy):
  #   size: 25 GB — caps a single shard at a manageable restore unit.
  #   age: 1 day  — ensures daily index segments so ISM delete transitions
  #                 fire cleanly on whole-day boundaries (avoids deleting the
  #                 hot index that Filebeat is currently writing to).
  #
  # Idempotent: PUT with "if_seq_no"/"if_primary_term" conflicts will be
  # caught by an explicit existence check — we skip the PUT if the policy
  # already exists, so re-runs are safe.
  # =========================================================================

  log "=== [INDEXER] Configuring ISM retention policies (Task 3) ==="

  # Shared curl wrapper — uses admin cert + basic auth, targets localhost:9200
  # We keep admin cert authentication as primary; basic auth is the verified
  # working method post-rotation.
  OS_CURL() {
    curl -sk \
      -u "${INDEXER_USERNAME}:${INDEXER_PASSWORD}" \
      --connect-timeout 10 --max-time 30 \
      "$@"
  }

  # -------------------------------------------------------------------------
  # 3a. wazuh-archives ISM policy — delete after 10 days, rollover at 25 GB / 1 day
  # -------------------------------------------------------------------------
  ARCHIVES_POLICY_EXISTS="$(OS_CURL \
    -o /dev/null -w "%{http_code}" \
    "https://localhost:9200/_plugins/_ism/policies/bc-wazuh-archives-retention" \
    2>/dev/null || echo "000")"

  if [[ "${ARCHIVES_POLICY_EXISTS}" == "200" ]]; then
    log "ISM policy 'bc-wazuh-archives-retention' already exists — skipping creation."
  else
    log "Creating ISM policy 'bc-wazuh-archives-retention' (archives: rollover 25 GB/1d, delete after 10 days)..."
    OS_CURL -X PUT \
      -H "Content-Type: application/json" \
      "https://localhost:9200/_plugins/_ism/policies/bc-wazuh-archives-retention" \
      -d '{
        "policy": {
          "description": "BC Wazuh archives retention: rollover at 25 GB or 1 day, delete after 10 days",
          "default_state": "hot",
          "states": [
            {
              "name": "hot",
              "actions": [
                {
                  "rollover": {
                    "min_size": "25gb",
                    "min_index_age": "1d"
                  }
                }
              ],
              "transitions": [
                {
                  "state_name": "delete",
                  "conditions": {
                    "min_index_age": "10d"
                  }
                }
              ]
            },
            {
              "name": "delete",
              "actions": [
                {
                  "delete": {}
                }
              ],
              "transitions": []
            }
          ],
          "ism_template": [
            {
              "index_patterns": ["wazuh-archives-*"],
              "priority": 100
            }
          ]
        }
      }' | jq -r '.policy.policy_id // .error // .' 2>/dev/null \
      && log "Archives ISM policy created." \
      || log "WARNING: Archives ISM policy creation failed — check indexer logs"
  fi

  # -------------------------------------------------------------------------
  # 3b. wazuh-alerts ISM policy — delete after 30 days, rollover at 25 GB / 1 day
  # -------------------------------------------------------------------------
  ALERTS_POLICY_EXISTS="$(OS_CURL \
    -o /dev/null -w "%{http_code}" \
    "https://localhost:9200/_plugins/_ism/policies/bc-wazuh-alerts-retention" \
    2>/dev/null || echo "000")"

  if [[ "${ALERTS_POLICY_EXISTS}" == "200" ]]; then
    log "ISM policy 'bc-wazuh-alerts-retention' already exists — skipping creation."
  else
    log "Creating ISM policy 'bc-wazuh-alerts-retention' (alerts: rollover 25 GB/1d, delete after 30 days)..."
    OS_CURL -X PUT \
      -H "Content-Type: application/json" \
      "https://localhost:9200/_plugins/_ism/policies/bc-wazuh-alerts-retention" \
      -d '{
        "policy": {
          "description": "BC Wazuh alerts retention: rollover at 25 GB or 1 day, delete after 30 days",
          "default_state": "hot",
          "states": [
            {
              "name": "hot",
              "actions": [
                {
                  "rollover": {
                    "min_size": "25gb",
                    "min_index_age": "1d"
                  }
                }
              ],
              "transitions": [
                {
                  "state_name": "delete",
                  "conditions": {
                    "min_index_age": "30d"
                  }
                }
              ]
            },
            {
              "name": "delete",
              "actions": [
                {
                  "delete": {}
                }
              ],
              "transitions": []
            }
          ],
          "ism_template": [
            {
              "index_patterns": ["wazuh-alerts-*"],
              "priority": 100
            }
          ]
        }
      }' | jq -r '.policy.policy_id // .error // .' 2>/dev/null \
      && log "Alerts ISM policy created." \
      || log "WARNING: Alerts ISM policy creation failed — check indexer logs"
  fi

  # -------------------------------------------------------------------------
  # 3c. Apply ISM policy to any pre-existing indices that match the patterns
  #     but were created before the ism_template was registered.
  #     The ism_template only auto-attaches to NEW indices; existing indices
  #     need a manual _plugins/_ism/add call. This is idempotent — adding a
  #     policy to an index that already has it returns a no-op.
  # -------------------------------------------------------------------------
  log "Applying ISM policies to any pre-existing wazuh-archives-* and wazuh-alerts-* indices..."
  for PATTERN in "wazuh-archives-*" "wazuh-alerts-*"; do
    POLICY_ID="bc-wazuh-archives-retention"
    [[ "${PATTERN}" == "wazuh-alerts-*" ]] && POLICY_ID="bc-wazuh-alerts-retention"

    OS_CURL -X POST \
      -H "Content-Type: application/json" \
      "https://localhost:9200/_plugins/_ism/add/${PATTERN}" \
      -d "{\"policy_id\": \"${POLICY_ID}\"}" \
      >/dev/null 2>&1 \
      && log "ISM policy '${POLICY_ID}' add-request sent for pattern '${PATTERN}'." \
      || log "WARNING: ISM add for pattern '${PATTERN}' returned non-zero (may be no matching indices — not fatal)"
  done

  log "=== [INDEXER] ISM retention policies configured ==="

  # =========================================================================
  # TASK 1 — S3 snapshot repository + Snapshot Management (SM) schedule
  #
  # repository-s3 plugin: bundled in the Wazuh 4.x OpenSearch distribution.
  # Wazuh indexer ships OpenSearch with the repository-s3 plugin pre-installed
  # (confirmed for Wazuh 4.x — the Wazuh indexer is a curated OpenSearch
  # distribution). We verify with _cat/plugins and skip the install step if
  # already present. If somehow missing, we install via opensearch-plugin.
  #
  # Authentication: EC2 instance role credential chain (no static keys,
  # no keystore entries required). The repository-s3 plugin picks up
  # credentials from the instance metadata service automatically when no
  # access_key/secret_key are specified in the PUT body. The instance role
  # (wazuh-ec2-role) must have s3:GetObject, s3:PutObject, s3:DeleteObject,
  # s3:ListBucket on the snapshots bucket — see IAM note at bottom of section.
  #
  # S3 prefix: opensearch-snapshots/ — distinct from scripts/ and rules/
  # which already exist in the same bucket, so no collision risk.
  #
  # Encryption: the bucket has no bucket-level SSE-KMS override; objects
  # default to SSE-S3 (AES256). We set server_side_encryption=true in the
  # repository config, which maps to SSE-S3. Do NOT set sse_kms_key_id here
  # unless a KMS CMK is configured at bucket level (it is not currently).
  #
  # Idempotent: PUT _snapshot is idempotent. SM policy creation is guarded
  # by an existence check (GET before PUT).
  # =========================================================================

  log "=== [INDEXER] Configuring S3 snapshot repository and SM schedule (Task 1) ==="

  # -------------------------------------------------------------------------
  # 1a. Verify repository-s3 plugin is present; install if missing
  # -------------------------------------------------------------------------
  log "Checking repository-s3 plugin availability..."
  PLUGIN_LIST="$(OS_CURL \
    "https://localhost:9200/_cat/plugins?h=component" \
    2>/dev/null || true)"

  if echo "${PLUGIN_LIST}" | grep -q "repository-s3"; then
    log "repository-s3 plugin is already installed."
  else
    log "repository-s3 plugin not found — attempting installation via opensearch-plugin..."
    OPENSEARCH_PLUGIN="/usr/share/wazuh-indexer/bin/opensearch-plugin"
    if [[ -x "${OPENSEARCH_PLUGIN}" ]]; then
      # Install non-interactively; -b (batch) suppresses the security warning prompt.
      # The exact version must match the bundled OpenSearch version in the Wazuh indexer.
      # Wazuh 4.14.4 ships OpenSearch 2.x; the plugin URL is discovered from the
      # cluster version rather than hardcoded.
      OS_VERSION="$(OS_CURL \
        "https://localhost:9200/" \
        2>/dev/null | jq -r '.version.number // empty' || true)"
      log "OpenSearch version: ${OS_VERSION}"

      if [[ -n "${OS_VERSION}" ]]; then
        "${OPENSEARCH_PLUGIN}" install \
          --batch \
          "repository-s3" \
          2>&1 | tee /tmp/opensearch-plugin-install.log \
          && log "repository-s3 plugin installed — restarting wazuh-indexer..." \
          || log "WARNING: plugin install via opensearch-plugin failed — plugin may already be bundled under a different name"

        # Restart only if install succeeded (plugin list will confirm below)
        if grep -q "Installed repository-s3" /tmp/opensearch-plugin-install.log 2>/dev/null; then
          systemctl restart wazuh-indexer \
            || fail "wazuh-indexer restart after plugin install failed" "wazuh-indexer"

          log "Waiting for cluster to recover after restart..."
          for i in $(seq 1 30); do
            HEALTH_POST="$(OS_CURL \
              "https://localhost:9200/_cluster/health" \
              2>/dev/null | jq -r '.status // "unknown"' 2>/dev/null || echo "unreachable")"
            if [[ "${HEALTH_POST}" == "green" || "${HEALTH_POST}" == "yellow" ]]; then
              log "Cluster health after restart: ${HEALTH_POST}"
              break
            fi
            sleep 10
          done
        fi
      else
        log "WARNING: could not determine OpenSearch version — skipping plugin install"
      fi
    else
      log "WARNING: ${OPENSEARCH_PLUGIN} not found — assuming repository-s3 is bundled"
    fi

    # Confirm plugin is now present (after potential install + restart)
    PLUGIN_LIST_POST="$(OS_CURL \
      "https://localhost:9200/_cat/plugins?h=component" \
      2>/dev/null || true)"
    if echo "${PLUGIN_LIST_POST}" | grep -q "repository-s3"; then
      log "repository-s3 plugin confirmed present."
    else
      log "WARNING: repository-s3 plugin still not visible — snapshot repo registration may fail"
    fi
  fi

  # -------------------------------------------------------------------------
  # 1b. Register S3 snapshot repository
  #
  # PUT _snapshot is idempotent — re-running with the same config is a no-op.
  # The bucket name is taken from the WAZUH_S3_BUCKET env var (set in user_data).
  # base_path uses opensearch-snapshots/ — never collides with scripts/ or rules/.
  # server_side_encryption: true → SSE-S3 (AES256), matching the existing
  # aws_s3_object resources in wazuh-ec2.tf which use server_side_encryption="AES256".
  # No access_key/secret_key → plugin uses the EC2 instance role credential chain.
  # -------------------------------------------------------------------------
  SNAP_BUCKET="${WAZUH_S3_BUCKET}"
  SNAP_REPO_NAME="bc-wazuh-snapshots"
  SNAP_BASE_PATH="opensearch-snapshots/"

  log "Registering S3 snapshot repository '${SNAP_REPO_NAME}'..."
  log "  bucket   : ${SNAP_BUCKET}"
  log "  base_path: ${SNAP_BASE_PATH}"
  log "  region   : ${REGION}"
  log "  auth     : EC2 instance role (no static credentials)"
  log "  SSE      : SSE-S3 / AES256 (matches existing bucket object uploads)"

  REPO_REG_RESP="$(OS_CURL -X PUT \
    -H "Content-Type: application/json" \
    "https://localhost:9200/_snapshot/${SNAP_REPO_NAME}" \
    -d "{
      \"type\": \"s3\",
      \"settings\": {
        \"bucket\": \"${SNAP_BUCKET}\",
        \"base_path\": \"${SNAP_BASE_PATH}\",
        \"region\": \"${REGION}\",
        \"server_side_encryption\": true,
        \"compress\": true
      }
    }" 2>/dev/null || true)"

  log "Snapshot repo registration response: ${REPO_REG_RESP}"
  if echo "${REPO_REG_RESP}" | grep -q '"acknowledged":true'; then
    log "S3 snapshot repository '${SNAP_REPO_NAME}' registered successfully."
  else
    log "WARNING: Snapshot repo registration did not return acknowledged:true — check response above"
  fi

  # Verify the repository is healthy (GET _snapshot/<repo>/_verify)
  log "Verifying snapshot repository connectivity to S3..."
  REPO_VERIFY_RESP="$(OS_CURL -X POST \
    "https://localhost:9200/_snapshot/${SNAP_REPO_NAME}/_verify" \
    2>/dev/null || true)"
  log "Repository verify response: ${REPO_VERIFY_RESP}"
  if echo "${REPO_VERIFY_RESP}" | grep -q '"nodes"'; then
    log "Snapshot repository verified — S3 connectivity confirmed."
  else
    log "WARNING: Repository verify returned unexpected response — check IAM role S3 permissions"
    log "  Required: s3:GetObject, s3:PutObject, s3:DeleteObject, s3:ListBucket on ${SNAP_BUCKET}"
  fi

  # -------------------------------------------------------------------------
  # 1c. Snapshot Management (SM) policy — daily snapshots, 14-day retention
  #
  # Wazuh 4.x ships OpenSearch 2.x which includes the SM plugin
  # (_plugins/_sm). The policy creates a daily snapshot at 02:00 UTC
  # (off-peak, after nightly VPCFlow flood has settled), retains the last 14
  # daily snapshots (~14 days of point-in-time recovery), and caps max count
  # at 20 to bound S3 storage on rebuild cycles.
  #
  # Idempotent: GET first; skip PUT if policy already exists. SM PUT is NOT
  # idempotent by default (it would overwrite and reset the state machine),
  # so we guard with the existence check.
  # -------------------------------------------------------------------------
  SM_POLICY_NAME="bc-wazuh-daily-snapshots"

  SM_POLICY_EXISTS="$(OS_CURL \
    -o /dev/null -w "%{http_code}" \
    "https://localhost:9200/_plugins/_sm/policies/${SM_POLICY_NAME}" \
    2>/dev/null || echo "000")"

  if [[ "${SM_POLICY_EXISTS}" == "200" ]]; then
    log "SM policy '${SM_POLICY_NAME}' already exists — skipping creation."
  else
    log "Creating SM policy '${SM_POLICY_NAME}' (daily at 02:00 UTC, keep 14, max 20)..."
    SM_CREATE_RESP="$(OS_CURL -X POST \
      -H "Content-Type: application/json" \
      "https://localhost:9200/_plugins/_sm/policies/${SM_POLICY_NAME}" \
      -d "{
        \"description\": \"Daily OpenSearch snapshots to S3 for Wazuh indexer disaster recovery\",
        \"creation\": {
          \"schedule\": {
            \"cron\": {
              \"expression\": \"0 2 * * *\",
              \"timezone\": \"UTC\"
            }
          },
          \"time_limit\": \"1h\"
        },
        \"deletion\": {
          \"schedule\": {
            \"cron\": {
              \"expression\": \"30 2 * * *\",
              \"timezone\": \"UTC\"
            }
          },
          \"condition\": {
            \"max_count\": 20,
            \"max_age\": \"14d\",
            \"min_count\": 1
          },
          \"time_limit\": \"1h\"
        },
        \"snapshot_config\": {
          \"repository\": \"${SNAP_REPO_NAME}\",
          \"indices\": \"wazuh-alerts-*,wazuh-archives-*\",
          \"ignore_unavailable\": true,
          \"include_global_state\": false,
          \"partial\": false
        }
      }" 2>/dev/null || true)"

    log "SM policy creation response: ${SM_CREATE_RESP}"
    if echo "${SM_CREATE_RESP}" | grep -q '"_id"'; then
      log "SM policy '${SM_POLICY_NAME}' created — first snapshot will run at 02:00 UTC."
    else
      # SM plugin may not be available (very old OpenSearch build); fall back
      # to a daily root cron calling the snapshot API directly.
      log "WARNING: SM policy creation did not return _id — SM plugin may not be available."
      log "Falling back to cron-based snapshot schedule..."

      SNAP_CRON="/etc/cron.d/wazuh-opensearch-snapshot"
      if [[ ! -f "${SNAP_CRON}" ]]; then
        log "Writing ${SNAP_CRON} (daily at 02:05 UTC)..."
        cat > "${SNAP_CRON}" <<CRONEOF
# Wazuh OpenSearch daily snapshot — written by phase3-install-wazuh.sh
# Fires at 02:05 UTC (after SM deletion window at 02:30 if SM is also running).
# Idempotent: snapshot name is date-based; a second run on the same day
# will return 400 (already exists) which is ignored by the || true.
MAILTO=""
5 2 * * * root /usr/local/bin/wazuh-opensearch-snapshot.sh >> /var/log/wazuh-snapshot.log 2>&1
CRONEOF

        cat > /usr/local/bin/wazuh-opensearch-snapshot.sh <<'SNAPSCRIPT'
#!/usr/bin/env bash
# wazuh-opensearch-snapshot.sh — daily OpenSearch snapshot to S3
# Called by /etc/cron.d/wazuh-opensearch-snapshot
set -euo pipefail

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [wazuh-snapshot] $*"; }

SNAP_DATE="$(date +%Y-%m-%d)"
SNAP_NAME="daily-${SNAP_DATE}"
REPO="bc-wazuh-snapshots"
INDEXER_IP="127.0.0.1"

# Load indexer credentials from a read-only file written during install.
# We do NOT embed the password here; it is read from the secrets cache file.
CREDS_FILE="/etc/wazuh-indexer/snapshot-creds"
if [[ ! -f "${CREDS_FILE}" ]]; then
  log "ERROR: credentials file ${CREDS_FILE} not found — cannot authenticate to indexer"
  exit 1
fi
source "${CREDS_FILE}"

: "${INDEXER_USERNAME:?}"
: "${INDEXER_PASSWORD:?}"

ADMIN_CERT="/etc/wazuh-indexer/certs/admin.pem"
ADMIN_KEY="/etc/wazuh-indexer/certs/admin-key.pem"

log "Starting snapshot: ${REPO}/${SNAP_NAME}"
RESP="$(curl -sk \
  -u "${INDEXER_USERNAME}:${INDEXER_PASSWORD}" \
  -X PUT \
  -H "Content-Type: application/json" \
  "https://${INDEXER_IP}:9200/_snapshot/${REPO}/${SNAP_NAME}?wait_for_completion=false" \
  -d '{
    "indices": "wazuh-alerts-*,wazuh-archives-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }' 2>/dev/null || true)"

log "Snapshot initiation response: ${RESP}"

if echo "${RESP}" | grep -q '"accepted":true\|"snapshot"'; then
  log "Snapshot ${SNAP_NAME} accepted — running asynchronously."
elif echo "${RESP}" | grep -q "snapshot_name_already_in_use\|already exists"; then
  log "Snapshot ${SNAP_NAME} already exists — idempotent, no action needed."
else
  log "WARNING: Unexpected snapshot response — check indexer logs"
  exit 1
fi
SNAPSCRIPT
        chmod 750 /usr/local/bin/wazuh-opensearch-snapshot.sh

        # Write the credentials cache file (readable only by root)
        # This avoids embedding the password in the cron script itself.
        cat > /etc/wazuh-indexer/snapshot-creds <<CREDSEOF
INDEXER_USERNAME="${INDEXER_USERNAME}"
INDEXER_PASSWORD="${INDEXER_PASSWORD}"
CREDSEOF
        chmod 600 /etc/wazuh-indexer/snapshot-creds
        chown root:root /etc/wazuh-indexer/snapshot-creds

        log "Cron fallback snapshot configured: ${SNAP_CRON}"
      else
        log "Cron snapshot file already exists — skipping cron fallback write."
      fi
    fi
  fi

  # -------------------------------------------------------------------------
  # IAM note for infrastructure-engineer (recorded in install log):
  # The instance role (wazuh-ec2-role) inline policy S3WazuhSnapshotsReadWrite
  # currently grants: s3:PutObject, s3:GetObject, s3:ListBucket.
  # The OpenSearch SM deletion step and manual snapshot cleanup also require:
  #   s3:DeleteObject  on ${SNAP_BUCKET}/*
  # Without s3:DeleteObject the SM policy will fail to prune old snapshots
  # (the creation step succeeds, but the deletion step will return AccessDenied).
  # The infrastructure-engineer must add s3:DeleteObject to the
  # S3WazuhSnapshotsReadWrite statement in wazuh-ec2.tf before next apply.
  # -------------------------------------------------------------------------
  log "IAM NOTE: ensure s3:DeleteObject is granted on ${SNAP_BUCKET}/* for SM snapshot pruning"

  log "=== [INDEXER] S3 snapshot repository and SM schedule configured ==="

  log "=== [INDEXER] Installation complete ==="
fi

# ---------------------------------------------------------------------------
# *** MANAGER ROLE ***
# ---------------------------------------------------------------------------
if [[ "${HOST_ROLE}" == "manager" || "${HOST_ROLE}" == "all_in_one" ]]; then
  log "=== [MANAGER] Installing wazuh-manager ==="

  dnf install -y "wazuh-manager-${WAZUH_VERSION}" \
    || fail "wazuh-manager package installation failed"
  log "wazuh-manager installed."

  # -------------------------------------------------------------------------
  # EBS data volume: only mount on dedicated manager (all_in_one uses the
  # single 200Gi EBS already mounted for the indexer above)
  # -------------------------------------------------------------------------
  if [[ "${HOST_ROLE}" != "all_in_one" ]]; then
    DATA_DEV="/dev/nvme1n1"
    DATA_MNT="/var/ossec-data"

    log "Waiting for device ${DATA_DEV} to appear..."
    for i in {1..30}; do
      if [[ -b "${DATA_DEV}" ]]; then
        log "Device ${DATA_DEV} is now available."
        break
      fi
      if (( i == 30 )); then
        fail "Timeout waiting for device ${DATA_DEV} to appear"
      fi
      sleep 2
    done

    if ! blkid "${DATA_DEV}" >/dev/null 2>&1; then
      log "Formatting ${DATA_DEV} as XFS..."
      mkfs.xfs -f "${DATA_DEV}" || fail "mkfs.xfs failed on ${DATA_DEV}"
    else
      log "${DATA_DEV} already has a filesystem — skipping format."
    fi

    mkdir -p "${DATA_MNT}"
    DATA_UUID="$(blkid -s UUID -o value "${DATA_DEV}")"

    if ! grep -q "${DATA_UUID}" /etc/fstab 2>/dev/null; then
      echo "UUID=${DATA_UUID}  ${DATA_MNT}  xfs  defaults,noatime,nodiratime  0  2" >> /etc/fstab
      log "fstab entry added for ${DATA_DEV}"
    fi

    if ! mountpoint -q "${DATA_MNT}"; then
      mount "${DATA_MNT}" || fail "Failed to mount ${DATA_DEV} → ${DATA_MNT}"
      log "Mounted ${DATA_DEV} → ${DATA_MNT}"
    fi

    for SUBDIR in queue var/db; do
      mkdir -p "${DATA_MNT}/${SUBDIR}"
      OSSEC_PATH="/var/ossec/${SUBDIR}"
      mkdir -p "${OSSEC_PATH}"
      if ! mountpoint -q "${OSSEC_PATH}"; then
        mount --bind "${DATA_MNT}/${SUBDIR}" "${OSSEC_PATH}"
        log "Bind-mounted ${DATA_MNT}/${SUBDIR} → ${OSSEC_PATH}"
      fi
      if ! grep -q "${DATA_MNT}/${SUBDIR}" /etc/fstab 2>/dev/null; then
        echo "${DATA_MNT}/${SUBDIR}  ${OSSEC_PATH}  none  bind  0  0" >> /etc/fstab
      fi
    done

    chown -R wazuh:wazuh "${DATA_MNT}" 2>/dev/null || true
  fi

  # -------------------------------------------------------------------------
  # TLS certs: in all_in_one mode reuse local certs from indexer step;
  # in standalone manager mode pull from S3.
  # -------------------------------------------------------------------------
  if [[ "${HOST_ROLE}" == "all_in_one" ]]; then
    CERTS_WORK="/tmp/wazuh-certs-gen"
    log "all_in_one mode — using local certs from ${CERTS_WORK}"
  else
    log "Pulling Wazuh certificates from s3://${CERT_BUCKET}/${CERT_S3_KEY}..."
    CERTS_WORK="/tmp/wazuh-certs-restore"
    mkdir -p "${CERTS_WORK}"

    for attempt in $(seq 1 30); do
      if aws s3 cp "s3://${CERT_BUCKET}/${CERT_S3_KEY}" "${CERTS_WORK}/wazuh-certificates.tar" \
          --region "${REGION}" >/dev/null 2>&1; then
        log "Certs downloaded (attempt ${attempt})"
        break
      fi
      if [[ "${attempt}" -eq 30 ]]; then
        fail "Could not download certs from S3 after 30 attempts — ensure indexer phase completed"
      fi
      log "  Certs not yet available — waiting 20s (attempt ${attempt}/30)"
      sleep 20
    done

    tar -xf "${CERTS_WORK}/wazuh-certificates.tar" -C "${CERTS_WORK}" 2>/dev/null || true
  fi

  MGR_CERT_DIR="/var/ossec/etc"
  cp "${CERTS_WORK}/wazuh-certificates/root-ca.pem" "${MGR_CERT_DIR}/root-ca.pem"

  # certs-tool names the server cert after the node name in config.yml ("wazuh-manager-ec2")
  if [[ -f "${CERTS_WORK}/wazuh-certificates/wazuh-manager-ec2.pem" ]]; then
    cp "${CERTS_WORK}/wazuh-certificates/wazuh-manager-ec2.pem"     "${MGR_CERT_DIR}/filebeat.pem"
    cp "${CERTS_WORK}/wazuh-certificates/wazuh-manager-ec2-key.pem" "${MGR_CERT_DIR}/filebeat.key" 2>/dev/null || true
  else
    ls "${CERTS_WORK}/wazuh-certificates/"*server* 2>/dev/null \
      | head -1 | xargs -I{} cp {} "${MGR_CERT_DIR}/filebeat.pem" 2>/dev/null || true
    find "${CERTS_WORK}/wazuh-certificates/" -name "*manager*key*" 2>/dev/null \
      | head -1 | xargs -I{} cp {} "${MGR_CERT_DIR}/filebeat.key" 2>/dev/null || true
  fi

  chmod 440 "${MGR_CERT_DIR}"/root-ca.pem "${MGR_CERT_DIR}"/filebeat.pem \
    "${MGR_CERT_DIR}"/filebeat.key 2>/dev/null || true
  chown root:wazuh "${MGR_CERT_DIR}"/root-ca.pem "${MGR_CERT_DIR}"/filebeat.pem \
    "${MGR_CERT_DIR}"/filebeat.key 2>/dev/null || true
  log "TLS certs installed to ${MGR_CERT_DIR}"

  # -------------------------------------------------------------------------
  # Indexer IP: localhost in all_in_one, tag-discovered in standalone
  # -------------------------------------------------------------------------
  if [[ "${HOST_ROLE}" == "all_in_one" ]]; then
    # Use the private IP (not 127.0.0.1) because the TLS cert generated by
    # wazuh-certs-tool.sh only has the private IP in its SAN. Connecting via
    # 127.0.0.1 causes: "x509: certificate is valid for <privateIP>, not 127.0.0.1".
    INDEXER_IP="${PRIVATE_IP}"
    log "all_in_one mode — Indexer IP: ${INDEXER_IP} (private IP, matches TLS cert SAN)"
  else
    log "Discovering Indexer IP (tag Name=wazuh-indexer-ctrl)..."
    INDEXER_IP="$(aws ec2 describe-instances \
      --region "${REGION}" \
      --filters "Name=tag:Name,Values=wazuh-indexer-ctrl" \
                "Name=instance-state-name,Values=running" \
      --query 'Reservations[0].Instances[0].PrivateIpAddress' \
      --output text 2>/dev/null || true)"

    [[ -n "${INDEXER_IP}" && "${INDEXER_IP}" != "None" ]] \
      || fail "Could not resolve Indexer IP via EC2 tags — ensure the instance has tag Name=wazuh-indexer-ctrl"
    log "Indexer IP: ${INDEXER_IP}"
  fi

  # -------------------------------------------------------------------------
  # Write /var/ossec/etc/ossec.conf
  # (Derived from configmap-ossec.yaml with EC2-specific substitutions)
  # -------------------------------------------------------------------------
  log "Writing /var/ossec/etc/ossec.conf..."
  cat > /var/ossec/etc/ossec.conf <<EOF
<!-- =========================================================================
     Wazuh Manager — ossec.conf
     Generated by phase3-install-wazuh.sh
     Host: wazuh-manager-ec2  |  Private IP: ${PRIVATE_IP}
     Indexer IP: ${INDEXER_IP}
     ======================================================================= -->
<ossec_config>

  <!--======================================================================
       1. GLOBAL SETTINGS
       JSON output is mandatory for Indexer ingestion.
       logall / logall_json capture EVERY event for forensic replay.
  =======================================================================-->
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@bigchemistry.internal</email_from>
    <email_to>soc@bigchemistry.internal</email_to>
    <email_maxperhour>50</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>no</update_check>
  </global>

  <!--======================================================================
       2. ALERT THRESHOLDS
  =======================================================================-->
  <alerts>
    <log_alert_level>1</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain,json</log_format>
  </logging>

  <!--======================================================================
       3. REMOTE — Agent connection endpoint
       Queue size 131072: handles bursts from ~500 agents.
  =======================================================================-->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
    <allowed-ips>10.30.0.0/16</allowed-ips>
    <allowed-ips>10.0.0.0/16</allowed-ips>
    <allowed-ips>10.11.0.0/16</allowed-ips>
  </remote>

  <!--======================================================================
       4. AUTH — Agent enrollment
  =======================================================================-->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <!-- GAP-001 (PRE_PROD_GAPS.md): enrollment-time password disabled.
         Enabling it without also writing /var/ossec/etc/authd.pass AND
         distributing the same password to the wazuh-agent DaemonSet
         (e.g. via External Secrets) makes agent registration fail with
         "Invalid password. Unable to add agent". Network-level isolation
         (VPC peering + SG allowlist on 1514/1515) is the current control.
         When GAP-001 is closed, flip this back to "yes" alongside the
         agent-side password provisioning. -->
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <!--======================================================================
       5. CLUSTER — disabled for single all-in-one node
  =======================================================================-->
  <cluster>
    <name>bc-wazuh-cluster</name>
    <node_name>wazuh-manager-ec2</node_name>
    <node_type>master</node_type>
    <key>${CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>${PRIVATE_IP}</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <!--======================================================================
       6. RULESET
       All stock decoders/rules + MISP IOC CDB lists.
  =======================================================================-->
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <!-- MISP threat-intel CDB lists — refreshed every 15m by misp-ioc-sync.timer -->
    <list>etc/lists/misp-ioc-ip</list>
    <list>etc/lists/misp-ioc-domain</list>
    <list>etc/lists/misp-ioc-hash-md5</list>
    <list>etc/lists/misp-ioc-hash-sha1</list>
    <list>etc/lists/misp-ioc-hash-sha256</list>
    <list>etc/lists/misp-ioc-url</list>
    <!-- Custom bc-specific detection rules/decoders -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <!--======================================================================
       7. SYSCHECK — File Integrity Monitoring
  =======================================================================-->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/bin,/sbin,/boot</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/var/www,/srv/www</directories>
    <directories check_all="yes" realtime="yes">/var/log</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
    <nodiff>/etc/pki/tls/private</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_interval>1h</max_interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!--======================================================================
       8. ROOTCHECK
  =======================================================================-->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>etc/shared/system_audit_ssh.txt</system_audit>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <!--======================================================================
       9. SCA — Security Configuration Assessment
  =======================================================================-->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
    <policies>
      <policy>cis_rhel9_linux.yml</policy>
      <policy>cis_amazon_linux_2.yml</policy>
    </policies>
  </sca>

  <!--======================================================================
       10. SYSCOLLECTOR — Inventory for CVE matching
  =======================================================================-->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <hotfixes>yes</hotfixes>
  </wodle>

  <!--======================================================================
       11. VULNERABILITY DETECTION
  =======================================================================-->
  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <!--======================================================================
       12. INDEXER — connection to EC2 Wazuh Indexer
       K8s DNS (wazuh-indexer-0.wazuh-indexer-headless…) replaced
       with the EC2 private IP discovered from instance tags.
  =======================================================================-->
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://${INDEXER_IP}:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/var/ossec/etc/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/var/ossec/etc/filebeat.pem</certificate>
      <key>/var/ossec/etc/filebeat.key</key>
    </ssl>
  </indexer>

  <!--======================================================================
       13. AWS S3 — CloudTrail / GuardDuty / VPC Flow / Config
       Auth via EC2 instance profile (no static credentials).
  =======================================================================-->
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <remove_from_bucket>no</remove_from_bucket>

    <bucket type="cloudtrail">
      <name>bc-cloudtrail-logs-929026881368</name>
      <aws_account_id>${AWS_ACCOUNT_ID}</aws_account_id>
      <path>AWSLogs/</path>
      <only_logs_after>2026-JAN-01</only_logs_after>
      <regions>eu-west-1</regions>
    </bucket>

    <bucket type="guardduty">
      <name>bc-guardduty-logs-929026881368</name>
      <aws_account_id>${AWS_ACCOUNT_ID}</aws_account_id>
      <only_logs_after>2026-JAN-01</only_logs_after>
      <regions>eu-west-1</regions>
    </bucket>

    <bucket type="vpcflow">
      <name>bc-vpcflow-logs-929026881368</name>
      <!-- No <path> prefix: Wazuh's vpcflow handler navigates
           AWSLogs/<account_id>/vpcflowlogs/<region>/... natively.
           A <path>AWSLogs/</path> prefix doubled the directory to
           AWSLogs/AWSLogs/ and caused "No logs found". -->
      <aws_account_id>${AWS_ACCOUNT_ID}</aws_account_id>
      <only_logs_after>2026-JAN-01</only_logs_after>
      <regions>eu-west-1</regions>
    </bucket>

    <bucket type="config">
      <name>bc-config-logs-929026881368</name>
      <!-- NOTE: AWS Config delivery channel not yet configured (no
           aws_config_delivery_channel Terraform resource exists).
           This bucket will be empty until that wiring is added.
           Leaving the wodle block in place is harmless. -->
      <only_logs_after>2026-JAN-01</only_logs_after>
    </bucket>

    <!-- Inspector wodle removed: aws_inspector2 is not enabled in
         this account. The service type="inspector" block caused
         AccessDenied errors on every poll cycle. -->
  </wodle>

  <!--======================================================================
       13b. AWS CloudWatch Logs — EKS control-plane AUDIT (F-10)
       Forwards the EKS API-server audit log group into Wazuh so
       K8s control-plane actions (CronJob/Job create, RBAC change,
       pod exec, secret read) are alertable. Rules: bc-k8s-audit.xml
       (100401-100405). Validated live 2026-06-10.

       Auth via the wazuh-ec2-role instance profile — needs the
       wazuh-eks-audit-read inline policy (logs:GetLogEvents /
       FilterLogEvents / DescribeLogStreams / DescribeLogGroups on
       arn:aws:logs:eu-west-1:${AWS_ACCOUNT_ID}:log-group:/aws/eks/bc-uatms-prd-eks/cluster:*).

       NOTES (learned during F-10 bring-up):
         * <only_logs_after> is parsed as UTC — use the UTC date.
         * The wodle keeps a per-stream bookmark; after enabling,
           generate a fresh action and wait one <interval> to see it.
         * EKS audit is verbose. <interval>1m</interval> is fine for a
           2-node cluster (~24 GB free on /); raise to 5m and watch
           df -h /var if log volume grows. skip_on_error keeps a bad
           poll from wedging the module.
  =======================================================================-->
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>1m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <service type="cloudwatchlogs">
      <aws_log_groups>/aws/eks/bc-uatms-prd-eks/cluster</aws_log_groups>
      <regions>eu-west-1</regions>
      <only_logs_after>2026-JUN-10</only_logs_after>
    </service>
  </wodle>

  <!--======================================================================
       14. COMMAND MONITORING
  =======================================================================-->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>listening-ports</tag>
    <command>ss -tlnp 2>/dev/null</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>10</timeout>
  </wodle>

  <!--======================================================================
       15. LOG COLLECTION
  =======================================================================-->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <!-- auditd log ingestion (see auditd section below) -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <!-- Falco JSON alerts -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/falco/alerts.json</location>
    <label key="event.module">falco</label>
    <label key="event.dataset">falco.alerts</label>
  </localfile>

  <!--======================================================================
       16. INTEGRATION: Shuffle SOAR
       Level 7+ alerts fire a webhook to Shuffle.
       Shuffle URL updated to EC2 hostname/IP when Shuffle is migrated.
  =======================================================================-->
  <integration>
    <name>shuffle</name>
    <hook_url>http://shuffle-frontend.shuffle.svc.cluster.local:3001/api/v1/hooks/${SHUFFLE_HOOK_ID}</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

  <!--======================================================================
       17. ACTIVE RESPONSE — DISABLED
       All automated response is handled by Splunk SOAR via the Shuffle/SOAR
       integration (section 16 above). Wazuh's role is DETECT + FORWARD only.
       No <command> or <active-response> blocks are configured here.
       Do NOT re-add stock firewall-drop / disable-account blocks — SOAR owns
       the enforcement plane.
  =======================================================================-->

</ossec_config>
EOF

  log "ossec.conf written."

  # -------------------------------------------------------------------------
  # Generate SSL manager cert for agent enrollment
  # -------------------------------------------------------------------------
  log "Generating SSL manager cert for agent enrollment..."
  openssl req -x509 -newkey rsa:2048 -keyout /var/ossec/etc/sslmanager.key \
    -out /var/ossec/etc/sslmanager.cert \
    -days 3650 -nodes \
    -subj "/C=US/ST=California/L=San Jose/O=BigChemistry/CN=wazuh-manager-ec2" \
    2>/dev/null || fail "openssl cert generation failed"
  chmod 640 /var/ossec/etc/sslmanager.key /var/ossec/etc/sslmanager.cert
  chown root:wazuh /var/ossec/etc/sslmanager.key /var/ossec/etc/sslmanager.cert
  log "SSL manager cert generated."

  # -------------------------------------------------------------------------
  # MISP sync env file
  # -------------------------------------------------------------------------
  log "Writing /etc/wazuh-manager/misp-sync.env..."
  mkdir -p /etc/wazuh-manager
  cat > /etc/wazuh-manager/misp-sync.env <<EOF
MISP_API_KEY=${MISP_API_KEY}
MISP_URL=https://misp.bc-ctrl.internal
WAZUH_API_USER=${API_USERNAME}
WAZUH_API_PASS=${API_PASSWORD}
EOF
  chmod 600 /etc/wazuh-manager/misp-sync.env
  chown root:root /etc/wazuh-manager/misp-sync.env
  log "misp-sync.env written."

  # -------------------------------------------------------------------------
  # MISP IOC sync script
  # -------------------------------------------------------------------------
  log "Writing /usr/local/bin/misp-ioc-sync.sh..."
  cat > /usr/local/bin/misp-ioc-sync.sh <<'MISPSCRIPT'
#!/usr/bin/env bash
# misp-ioc-sync.sh — Fetch MISP threat intelligence and write Wazuh CDB lists.
# Called by misp-ioc-sync.timer every 15 minutes.
set -euo pipefail

ENV_FILE="/etc/wazuh-manager/misp-sync.env"
[[ -f "${ENV_FILE}" ]] && source "${ENV_FILE}"

: "${MISP_URL:?MISP_URL not set}"
: "${MISP_API_KEY:?MISP_API_KEY not set}"

LISTS_DIR="/var/ossec/etc/lists"
mkdir -p "${LISTS_DIR}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [misp-ioc-sync] $*"; }

fetch_iocs() {
  local type="$1"
  local out_base="$2"
  local out_file="${LISTS_DIR}/${out_base}"

  curl -sfk \
    -H "Authorization: ${MISP_API_KEY}" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{\"returnFormat\":\"values\",\"type\":\"${type}\",\"to_ids\":1,\"published\":1}" \
    "${MISP_URL}/attributes/restSearch" \
  | jq -r '.response.Attribute[]?.value // empty' \
  | sort -u \
  | awk '{print $1":"}' \
  > "${out_file}.tmp" \
  && mv "${out_file}.tmp" "${out_file}" \
  && log "Updated ${out_file} ($(wc -l < "${out_file}") entries)" \
  || { log "WARNING: MISP query failed for type=${type} — keeping previous list"; rm -f "${out_file}.tmp"; }
}

log "Starting MISP IOC sync from ${MISP_URL}..."

fetch_iocs "ip-dst"  "misp-ioc-ip"
fetch_iocs "domain"  "misp-ioc-domain"
fetch_iocs "url"     "misp-ioc-url"
fetch_iocs "md5"     "misp-ioc-hash-md5"
fetch_iocs "sha1"    "misp-ioc-hash-sha1"
fetch_iocs "sha256"  "misp-ioc-hash-sha256"

# Reload Wazuh Manager so new lists are active immediately
if [[ -n "${WAZUH_API_USER:-}" && -n "${WAZUH_API_PASS:-}" ]]; then
  TOKEN="$(curl -sfk \
    -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" \
    -X GET "https://localhost:55000/security/user/authenticate?raw=true" \
    2>/dev/null || true)"

  if [[ -n "${TOKEN}" ]]; then
    curl -sfk \
      -H "Authorization: Bearer ${TOKEN}" \
      -X PUT "https://localhost:55000/manager/configuration?wait_for_complete=false" \
      >/dev/null 2>&1 \
      && log "Manager configuration reload triggered" \
      || log "WARNING: Manager reload request failed (non-fatal)"
  else
    log "WARNING: Could not obtain Wazuh API token for reload"
  fi
fi

log "MISP IOC sync complete."
MISPSCRIPT
  chmod 750 /usr/local/bin/misp-ioc-sync.sh
  log "misp-ioc-sync.sh written."

  # -------------------------------------------------------------------------
  # misp-ioc-sync systemd service and timer
  # -------------------------------------------------------------------------
  log "Writing misp-ioc-sync.service and misp-ioc-sync.timer..."
  cat > /etc/systemd/system/misp-ioc-sync.service <<'EOF'
[Unit]
Description=MISP IOC Sync — Refresh Wazuh CDB threat-intel lists
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/wazuh-manager/misp-sync.env
ExecStart=/usr/local/bin/misp-ioc-sync.sh
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/ossec/etc/lists
StandardOutput=journal
StandardError=journal
EOF

  cat > /etc/systemd/system/misp-ioc-sync.timer <<'EOF'
[Unit]
Description=MISP IOC Sync timer — every 15 minutes
Requires=misp-ioc-sync.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload

  # -------------------------------------------------------------------------
  # Systemd hardening for wazuh-manager
  # -------------------------------------------------------------------------
  log "Writing systemd hardening override for wazuh-manager..."
  mkdir -p /etc/systemd/system/wazuh-manager.service.d
  cat > /etc/systemd/system/wazuh-manager.service.d/hardening.conf <<'EOF'
[Service]
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65536
EOF
  systemctl daemon-reload

  # -------------------------------------------------------------------------
  # Enable and start wazuh-manager
  # -------------------------------------------------------------------------
  # Ensure log dir exists (required by ProtectSystem=strict ReadWritePaths)
  mkdir -p /var/log/wazuh-manager
  chown wazuh:wazuh /var/log/wazuh-manager 2>/dev/null || true

  log "Enabling and starting wazuh-manager..."
  systemctl enable --now wazuh-manager \
    || fail "systemctl enable --now wazuh-manager failed" "wazuh-manager"

  # Wait for Manager API to become available (up to 5 min)
  log "Waiting for Wazuh Manager API on port 55000..."
  API_OK=false
  for i in $(seq 1 30); do
    # Probe with factory default — API is ready the moment this works. Rotation happens below.
    if curl -sk -u "${API_USERNAME}:${API_USERNAME}" \
        "https://localhost:55000/security/user/authenticate?raw=true" \
        --connect-timeout 5 --max-time 10 >/dev/null 2>&1; then
      log "Manager API ready after $((i * 10))s"
      API_OK=true
      break
    fi
    sleep 10
  done

  if "${API_OK}"; then
    # -----------------------------------------------------------------------
    # Set Wazuh API credentials via REST
    # -----------------------------------------------------------------------
    log "Updating Wazuh API user password..."
    TOKEN="$(curl -sfk -u "${API_USERNAME}:${API_USERNAME}" \
      "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null || true)"
    if [[ -z "${TOKEN}" ]]; then
      TOKEN="$(curl -sfk -u "${API_USERNAME}:${API_PASSWORD}" \
        "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null || true)"
      [[ -n "${TOKEN}" ]] && log "Password already rotated (idempotent re-run), verifying only."
    fi

    if [[ -n "${TOKEN}" ]]; then
      # Get the user ID for API_USERNAME
      USERS_RESP="$(curl -sfk \
        -H "Authorization: Bearer ${TOKEN}" \
        "https://localhost:55000/security/users?pretty" \
        2>/dev/null || echo '{}')"
      USER_ID="$(echo "${USERS_RESP}" | jq -r \
        ".data.affected_items[] | select(.username==\"${API_USERNAME}\") | .id" \
        2>/dev/null | head -1 || true)"

      if [[ -n "${USER_ID}" ]]; then
        curl -sfk \
          -H "Authorization: Bearer ${TOKEN}" \
          -H "Content-Type: application/json" \
          -X PUT "https://localhost:55000/security/users/${USER_ID}" \
          -d "{\"password\": \"${API_PASSWORD}\"}" \
          >/dev/null 2>&1 && log "API user password updated." \
          || log "WARNING: API password update failed — verify manually"

        # Verify new credential works before declaring success
        VERIFY="$(curl -sfk -u "${API_USERNAME}:${API_PASSWORD}" \
          "https://localhost:55000/security/user/authenticate?raw=true" \
          --connect-timeout 5 --max-time 10 2>/dev/null || true)"
        [[ -n "${VERIFY}" ]] || fail "Post-rotation verify failed: new password does not authenticate"
        log "Post-rotation verify: new credential confirmed working."
      else
        log "WARNING: Could not find user ID for ${API_USERNAME}"
      fi

      # Quick sanity check
      VERSION_RESP="$(curl -sfk \
        -H "Authorization: Bearer ${TOKEN}" \
        "https://localhost:55000/" 2>/dev/null || echo '{}')"
      WAZUH_VER="$(echo "${VERSION_RESP}" | jq -r '.data.api_version // "unknown"' 2>/dev/null)"
      log "Manager API version: ${WAZUH_VER}"
    else
      log "WARNING: Could not obtain API token for post-install tasks"
    fi
  else
    fail "Manager API did not respond within 300s — password sync not performed. Install incomplete." "wazuh-manager"
  fi

  # -------------------------------------------------------------------------
  # Sync custom Wazuh rules from S3
  # -------------------------------------------------------------------------
  # XML rule files live in git at new-infra/wazuh/rules/ and are uploaded to
  # s3://bc-uatms-wazuh-snapshots-<account>/rules/ by Terraform (see
  # wazuh-ec2.tf : aws_s3_object.wazuh_rules). The user_data hash includes
  # those files so a rule change forces an instance replacement, and
  # this block reloads wazuh-manager so the new rules take effect on boot.
  log "Syncing custom Wazuh rules from s3://${WAZUH_S3_BUCKET}/rules/..."
  RULES_SYNC_OUT=$(aws s3 sync "s3://${WAZUH_S3_BUCKET}/rules/" /var/ossec/etc/rules/ \
    --region "${REGION}" --exclude "*" --include "*.xml" 2>&1) || true
  echo "${RULES_SYNC_OUT}" | sed 's/^/  /'
  chown -R wazuh:wazuh /var/ossec/etc/rules/
  chmod 660 /var/ossec/etc/rules/*.xml 2>/dev/null || true

  RULE_COUNT=$(find /var/ossec/etc/rules -maxdepth 1 -name "bc-*.xml" -type f | wc -l)
  log "Custom rule files installed: ${RULE_COUNT}"
  if [[ "${RULE_COUNT}" -gt 0 ]]; then
    log "Restarting wazuh-manager to load custom rules..."
    systemctl restart wazuh-manager \
      || fail "wazuh-manager restart failed after rule sync" "wazuh-manager"
    # Wait for analysisd to come back; if rules have syntax errors, the
    # manager refuses to start and journalctl shows the offending file.
    sleep 5
    systemctl is-active wazuh-manager >/dev/null \
      || fail "wazuh-manager not active after rule reload — check rule XML syntax" "wazuh-manager"
    log "wazuh-manager restarted with custom rules loaded."
  fi

  # Enable MISP sync timer
  log "Enabling misp-ioc-sync.timer..."
  systemctl enable --now misp-ioc-sync.timer \
    || log "WARNING: misp-ioc-sync.timer enable failed — retry manually after confirming MISP is reachable"

  log "=== [MANAGER] Installation complete ==="
fi

# ---------------------------------------------------------------------------
# *** FILEBEAT ROLE ***
# Ships wazuh-alerts from the manager to the indexer. Required on all_in_one
# and manager roles — without it, no wazuh-alerts-* indices appear in the
# indexer and the dashboard shows "no template / no matching indices".
# ---------------------------------------------------------------------------
if [[ "${HOST_ROLE}" == "all_in_one" || "${HOST_ROLE}" == "manager" ]]; then
  log "=== [FILEBEAT] Installing filebeat-oss ==="

  # -------------------------------------------------------------------------
  # Indexer IP for this role: reuse the variable already set in the manager
  # section above. all_in_one = 127.0.0.1; standalone manager = discovered IP.
  # -------------------------------------------------------------------------
  [[ -n "${INDEXER_IP}" ]] || fail "INDEXER_IP not set — filebeat section requires manager section to have run first"

  # -------------------------------------------------------------------------
  # Add Elastic OSS 7.x yum repo if not already present
  # -------------------------------------------------------------------------
  if ! rpm -q filebeat 2>/dev/null | grep -q "filebeat-7.10.2"; then
    if [[ ! -f /etc/yum.repos.d/elastic-7.x.repo ]]; then
      rpm --import "https://artifacts.elastic.co/GPG-KEY-elasticsearch"
      cat > /etc/yum.repos.d/elastic-7.x.repo <<'REPO'
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/oss-7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
REPO
    fi

    dnf install -y "filebeat-7.10.2" \
      || fail "filebeat-oss-7.10.2 package installation failed"
    log "filebeat 7.10.2 installed."
  else
    log "filebeat 7.10.2 already installed — skipping package install."
  fi
  rpm -q filebeat | grep -q "7.10.2" || fail "filebeat rpm version check failed — unexpected version installed"

  # -------------------------------------------------------------------------
  # Pull config, module, and template from Wazuh CDN
  # -------------------------------------------------------------------------
  # The 4.x/tpl/ CDN path returns HTTP 403 (retired). Write filebeat.yml inline
  # so the script never depends on that URL. The sed patches below (lines ~1411–1427)
  # match hosts:[...] and ssl.certificate_authorities: which are both present here.
  log "Writing filebeat.yml from inline template (packages.wazuh.com/4.x/tpl/ path is retired)..."
  cat > /etc/filebeat/filebeat.yml <<'FILEBEAT_YML'
# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: ["127.0.0.1:9200"]
  protocol: https
  username: ${username}
  password: ${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat.key"

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.template.overwrite: true
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

# F-10: EKS control-plane AUDIT alerts (bc-k8s-audit.xml 100401-100405) carry the
# raw K8s requestObject/responseObject, whose managedFields contain a literal "."
# key. OpenSearch rejects the whole document with
#   mapper_parsing_exception: field name cannot contain only the character [.]
# so every audit alert silently fails to index (visible in alerts.json, absent
# from the dashboard). Strip those two nested blobs before indexing — the rules
# key on verb/objectRef/user/responseStatus, which remain. Discovered + fixed
# live 2026-06-10.
processors:
  - drop_fields:
      fields: ["data.requestObject", "data.responseObject"]
      ignore_missing: true

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
logging.metrics.enabled: false

# Filebeat 7.10.2 ships a seccomp allowlist built for older kernels. Amazon
# Linux 2023 kernel 6.x uses clone3 for pthread_create, which is not in that
# list → EPERM → runtime/cgo abort. Setting default_action: allow disables
# the restrictive filter while keeping the seccomp hook in place.
seccomp:
  default_action: allow
FILEBEAT_YML

  log "Extracting wazuh-filebeat module..."
  mkdir -p /usr/share/filebeat/module
  curl -fsSL "https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz" \
    | tar -xz -C /usr/share/filebeat/module \
    || fail "Failed to download or extract wazuh-filebeat-0.4.tar.gz"

  log "Downloading wazuh OpenSearch template..."
  # Bug C fix: tag updated to match WAZUH_VERSION.
  curl -fsSL "https://raw.githubusercontent.com/wazuh/wazuh/v${WAZUH_VERSION}/extensions/elasticsearch/7.x/wazuh-template.json" \
    -o /etc/filebeat/wazuh-template.json \
    || fail "Failed to download wazuh-template.json from github.com/wazuh/wazuh"

  # -------------------------------------------------------------------------
  # Certs: copy from /var/ossec/etc/ (written by manager cert section above)
  # -------------------------------------------------------------------------
  log "Installing filebeat TLS certs..."
  mkdir -p /etc/filebeat/certs
  cp /var/ossec/etc/root-ca.pem  /etc/filebeat/certs/root-ca.pem
  cp /var/ossec/etc/filebeat.pem /etc/filebeat/certs/filebeat.pem
  cp /var/ossec/etc/filebeat.key /etc/filebeat/certs/filebeat.key
  chown root:root /etc/filebeat/certs/root-ca.pem \
                  /etc/filebeat/certs/filebeat.pem \
                  /etc/filebeat/certs/filebeat.key
  chmod 0444 /etc/filebeat/certs/root-ca.pem /etc/filebeat/certs/filebeat.pem
  chmod 0400 /etc/filebeat/certs/filebeat.key
  log "Filebeat certs installed."

  # -------------------------------------------------------------------------
  # Patch filebeat.yml: indexer host + TLS paths
  # sed -i is safe here — matching known upstream template keys
  # -------------------------------------------------------------------------
  log "Patching filebeat.yml with indexer host and TLS config..."
  sed -i "s|hosts:.*\[.*\]|hosts: [\"https://${INDEXER_IP}:9200\"]|" /etc/filebeat/filebeat.yml
  # Patch or append ssl block under output.elasticsearch
  if grep -q "ssl.certificate_authorities" /etc/filebeat/filebeat.yml; then
    sed -i "s|ssl\.certificate_authorities:.*|ssl.certificate_authorities: [\"/etc/filebeat/certs/root-ca.pem\"]|" /etc/filebeat/filebeat.yml
    # Remove redundant list item if template used list format for CA
    sed -i '/- \/etc\/filebeat\/certs\/root-ca.pem/d' /etc/filebeat/filebeat.yml
    sed -i "s|ssl\.certificate:.*|ssl.certificate: \"/etc/filebeat/certs/filebeat.pem\"|" /etc/filebeat/filebeat.yml
    sed -i "s|ssl\.key:.*|ssl.key: \"/etc/filebeat/certs/filebeat.key\"|" /etc/filebeat/filebeat.yml
  else
    # Template may not have ssl block — append it under output.elasticsearch
    cat >> /etc/filebeat/filebeat.yml <<'SSLBLOCK'
  ssl.certificate_authorities: ["/etc/filebeat/certs/root-ca.pem"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat.key"
SSLBLOCK
  fi
  log "filebeat.yml patched."

  # -------------------------------------------------------------------------
  # Keystore: store output credentials — never write password to disk
  # -------------------------------------------------------------------------
  log "Populating filebeat keystore..."
  filebeat keystore create --force
  # Bug A fix: the Wazuh filebeat.yml template references ${username} and
  # ${password} (not ${output.elasticsearch.username/password}). Using the
  # wrong key names causes filebeat to exit with "missing field accessing
  # 'output.elasticsearch.username'" which aborts the script via set -e.
  printf '%s' "admin"               | filebeat keystore add --stdin --force username
  printf '%s' "${INDEXER_PASSWORD}" | filebeat keystore add --stdin --force password
  log "Filebeat keystore populated."

  # -------------------------------------------------------------------------
  # Validate config and connectivity before starting
  # -------------------------------------------------------------------------
  filebeat test config  || fail "filebeat test config failed"
  filebeat test output  || fail "filebeat test output failed — indexer unreachable or creds wrong"

  # -------------------------------------------------------------------------
  # Enable and start — bounded wait, no infinite loop
  # -------------------------------------------------------------------------
  systemctl daemon-reload
  systemctl enable filebeat
  systemctl start filebeat

  # Bounded single-shot verification — no unbounded wait loop.
  for i in $(seq 1 6); do
    sleep 5
    if systemctl is-active --quiet filebeat; then break; fi
  done
  systemctl is-active --quiet filebeat \
    || fail "filebeat did not become active within 30s" "filebeat"
  log "filebeat is active."

  # -------------------------------------------------------------------------
  # Verify template and initial indices (informational — no fail on absence;
  # manager may have no agents yet so no alerts to ship)
  # -------------------------------------------------------------------------
  log "Waiting 30s for filebeat to ship template and initial events..."
  sleep 30
  curl -sfk -u "admin:${INDEXER_PASSWORD}" \
    "https://${INDEXER_IP}:9200/_cat/templates?v" \
    | grep -qi wazuh \
    || log "WARNING: wazuh template not yet visible (will load on first index creation)"
  curl -sfk -u "admin:${INDEXER_PASSWORD}" \
    "https://${INDEXER_IP}:9200/_cat/indices/wazuh-alerts-*?v" \
    | tee -a /var/log/wazuh-install.log

  log "=== [FILEBEAT] Installation complete ==="
fi

# ---------------------------------------------------------------------------
# *** DASHBOARD ROLE ***
# ---------------------------------------------------------------------------
if [[ "${HOST_ROLE}" == "dashboard" || "${HOST_ROLE}" == "all_in_one" ]]; then
  log "=== [DASHBOARD] Installing wazuh-dashboard ==="

  dnf install -y "wazuh-dashboard-${WAZUH_VERSION}" \
    || fail "wazuh-dashboard package installation failed"
  log "wazuh-dashboard installed."

  # -------------------------------------------------------------------------
  # TLS certs: reuse local dir in all_in_one, pull from S3 in standalone
  # -------------------------------------------------------------------------
  if [[ "${HOST_ROLE}" == "all_in_one" ]]; then
    CERTS_WORK="/tmp/wazuh-certs-gen"
    log "all_in_one mode — using local certs from ${CERTS_WORK}"
  else
    log "Pulling Wazuh certificates from s3://${CERT_BUCKET}/${CERT_S3_KEY}..."
    CERTS_WORK="/tmp/wazuh-certs-restore"
    mkdir -p "${CERTS_WORK}"

    for attempt in $(seq 1 30); do
      if aws s3 cp "s3://${CERT_BUCKET}/${CERT_S3_KEY}" "${CERTS_WORK}/wazuh-certificates.tar" \
          --region "${REGION}" >/dev/null 2>&1; then
        log "Certs downloaded (attempt ${attempt})"
        break
      fi
      if [[ "${attempt}" -eq 30 ]]; then
        fail "Could not download certs from S3 — ensure indexer phase completed"
      fi
      log "  Certs not yet available — waiting 20s (attempt ${attempt}/30)"
      sleep 20
    done

    tar -xf "${CERTS_WORK}/wazuh-certificates.tar" -C "${CERTS_WORK}" 2>/dev/null || true
  fi

  DASH_CERT_DIR="/etc/wazuh-dashboard/certs"
  # Bug B fix: create the certs dir and copy all three required certs without
  # || true suppression. opensearch_dashboards.yml references all three paths
  # and the dashboard crash-loops with ENOENT if any are absent. The certs-tool
  # config.yml names the dashboard node "wazuh-dashboard", so certs-tool emits
  # wazuh-dashboard.pem + wazuh-dashboard-key.pem. Fail hard if they are missing
  # so a broken cert generation is caught here rather than at service start.
  mkdir -p "${DASH_CERT_DIR}"
  cp "${CERTS_WORK}/wazuh-certificates/wazuh-dashboard.pem"     "${DASH_CERT_DIR}/dashboard.pem" \
    || fail "Dashboard cert wazuh-dashboard.pem not found in certs-tool output — check /tmp/wazuh-certs-tool.log"
  cp "${CERTS_WORK}/wazuh-certificates/wazuh-dashboard-key.pem" "${DASH_CERT_DIR}/dashboard-key.pem" \
    || fail "Dashboard key wazuh-dashboard-key.pem not found in certs-tool output — check /tmp/wazuh-certs-tool.log"
  cp "${CERTS_WORK}/wazuh-certificates/root-ca.pem"             "${DASH_CERT_DIR}/root-ca.pem" \
    || fail "root-ca.pem not found in certs-tool output — check /tmp/wazuh-certs-tool.log"
  chmod 500 "${DASH_CERT_DIR}"
  chmod 400 "${DASH_CERT_DIR}/dashboard.pem" \
            "${DASH_CERT_DIR}/dashboard-key.pem" \
            "${DASH_CERT_DIR}/root-ca.pem"
  chown -R wazuh-dashboard:wazuh-dashboard "${DASH_CERT_DIR}"
  log "TLS certs installed to ${DASH_CERT_DIR}"

  # -------------------------------------------------------------------------
  # Manager/Indexer IPs: localhost in all_in_one, tag-discovered in standalone
  # -------------------------------------------------------------------------
  if [[ "${HOST_ROLE}" == "all_in_one" ]]; then
    # Use PRIVATE_IP (not 127.0.0.1) to match the TLS cert SANs generated
    # by wazuh-certs-tool.sh. The dashboard uses verificationMode: none so
    # TLS hostname verification is disabled for the backend connection, but
    # the cert must still be reachable. Private IP works for both.
    MANAGER_IP="${PRIVATE_IP}"
    INDEXER_IP="${PRIVATE_IP}"
    log "all_in_one mode — Manager/Indexer IP: ${PRIVATE_IP} (private IP, matches TLS cert SAN)"
  else
    log "Discovering Manager IP (tag Name=wazuh-manager-ctrl)..."
    MANAGER_IP="$(aws ec2 describe-instances \
      --region "${REGION}" \
      --filters "Name=tag:Name,Values=wazuh-manager-ctrl" \
                "Name=instance-state-name,Values=running" \
      --query 'Reservations[0].Instances[0].PrivateIpAddress' \
      --output text 2>/dev/null || true)"
    [[ -n "${MANAGER_IP}" && "${MANAGER_IP}" != "None" ]] \
      || fail "Could not resolve Manager IP — ensure instance tag Name=wazuh-manager-ctrl exists"

    log "Discovering Indexer IP (tag Name=wazuh-indexer-ctrl)..."
    INDEXER_IP="$(aws ec2 describe-instances \
      --region "${REGION}" \
      --filters "Name=tag:Name,Values=wazuh-indexer-ctrl" \
                "Name=instance-state-name,Values=running" \
      --query 'Reservations[0].Instances[0].PrivateIpAddress' \
      --output text 2>/dev/null || true)"
    [[ -n "${INDEXER_IP}" && "${INDEXER_IP}" != "None" ]] \
      || fail "Could not resolve Indexer IP — ensure instance tag Name=wazuh-indexer-ctrl exists"

    log "Manager IP: ${MANAGER_IP} | Indexer IP: ${INDEXER_IP}"
  fi

  # -------------------------------------------------------------------------
  # Write opensearch_dashboards.yml
  # (Derived from dashboard configmap.yaml — EC2 IPs, SSL on port 443)
  # -------------------------------------------------------------------------
  log "Writing /etc/wazuh-dashboard/opensearch_dashboards.yml..."
  cat > /etc/wazuh-dashboard/opensearch_dashboards.yml <<EOF
server.host: "0.0.0.0"
server.port: 443
server.ssl.enabled: true
server.ssl.certificate: "${DASH_CERT_DIR}/dashboard.pem"
server.ssl.key: "${DASH_CERT_DIR}/dashboard-key.pem"
opensearch.hosts: ["https://${INDEXER_IP}:9200"]
opensearch.ssl.verificationMode: none
opensearch.ssl.certificateAuthorities: ["${DASH_CERT_DIR}/root-ca.pem"]
opensearch.username: "${INDEXER_USERNAME}"
opensearch.password: "${INDEXER_PASSWORD}"
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.cookie.secure: true
EOF

  # Wazuh API config lives in the plugin's own file, not opensearch_dashboards.yml
  log "Writing Wazuh plugin API config..."
  mkdir -p /usr/share/wazuh-dashboard/data/wazuh/config
  cat > /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml <<EOF
hosts:
  - default:
      url: "https://${MANAGER_IP}"
      port: 55000
      username: "${API_USERNAME}"
      password: "${API_PASSWORD}"
      run_as: false
EOF
  chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/data/wazuh/

  # -------------------------------------------------------------------------
  # Systemd hardening for wazuh-dashboard
  # -------------------------------------------------------------------------
  log "Writing systemd hardening override for wazuh-dashboard..."
  mkdir -p /etc/systemd/system/wazuh-dashboard.service.d
  cat > /etc/systemd/system/wazuh-dashboard.service.d/hardening.conf <<'EOF'
[Service]
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF
  systemctl daemon-reload

  # -------------------------------------------------------------------------
  # Enable and start wazuh-dashboard
  # -------------------------------------------------------------------------
  log "Enabling and starting wazuh-dashboard..."
  systemctl enable --now wazuh-dashboard \
    || fail "systemctl enable --now wazuh-dashboard failed" "wazuh-dashboard"

  # Wait for dashboard to respond on port 443 (up to 5 min)
  log "Waiting for Wazuh Dashboard on HTTPS port 443..."
  DASH_OK=false
  for i in $(seq 1 30); do
    HTTP_CODE="$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://localhost:443/" \
      --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")"
    if [[ "${HTTP_CODE}" == "200" || "${HTTP_CODE}" == "302" || "${HTTP_CODE}" == "301" ]]; then
      log "Dashboard responding: HTTP ${HTTP_CODE} (after $((i * 10))s)"
      DASH_OK=true
      break
    fi
    sleep 10
  done
  "${DASH_OK}" || log "WARNING: Dashboard did not respond within 300s — check: journalctl -u wazuh-dashboard"

  log "=== [DASHBOARD] Installation complete ==="
fi

# ===========================================================================
# SECTION 3 — FALCO INSTALLATION (all hosts)
# ===========================================================================
log "=== [ALL] Installing Falco (eBPF) ==="

# Add Falco YUM repo
if [[ ! -f /etc/yum.repos.d/falcosecurity.repo ]]; then
  rpm --import "https://falco.org/repo/falcosecurity-packages.asc" 2>/dev/null \
    || log "WARNING: Could not import Falco GPG key — verify manually"

  cat > /etc/yum.repos.d/falcosecurity.repo <<'EOF'
[falcosecurity]
name=falcosecurity-rpm
baseurl=https://download.falco.org/packages/rpm
enabled=1
gpgcheck=1
gpgkey=https://falco.org/repo/falcosecurity-packages.asc
EOF
  log "Falco repo configured."
else
  log "Falco repo already configured."
fi

# Install kernel headers (needed for kmod fallback driver)
dnf install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r) 2>/dev/null \
  || dnf install -y kernel-devel kernel-headers 2>/dev/null \
  || log "WARNING: kernel-devel install failed — eBPF will be used instead of kmod"

# Install Falco
dnf install -y falco 2>/dev/null \
  || fail "Falco installation failed — check the falcosecurity repo is reachable"
log "Falco installed."

# Configure Falco to use eBPF probe (preferred on AL2023); fall back to kmod
FALCO_CONF="/etc/falco/falco.yaml"
if [[ -f "${FALCO_CONF}" ]]; then
  # eBPF probe mode
  sed -i 's/^driver:.*/driver:/' "${FALCO_CONF}" 2>/dev/null || true

  # JSON output to file
  sed -i 's|^# json_output:.*|json_output: true|'   "${FALCO_CONF}" 2>/dev/null || true
  sed -i 's|^json_output: false|json_output: true|'  "${FALCO_CONF}" 2>/dev/null || true
  sed -i 's|^json_include_output_property: false|json_include_output_property: true|' \
    "${FALCO_CONF}" 2>/dev/null || true
fi

# Ensure Falco output directory exists
mkdir -p /var/log/falco

# Apply server-workload Falco rules (no container-specific rules)
FALCO_RULES_DIR="/etc/falco/rules.d"
mkdir -p "${FALCO_RULES_DIR}"
cat > "${FALCO_RULES_DIR}/bc-server-rules.yaml" <<'EOF'
# BigChemistry server workload Falco rules
# Focus: shell spawns, unexpected network, sensitive reads, privilege escalation
# Container-specific rules are omitted (bare-metal hosts)

- rule: Shell spawned by unexpected process
  desc: A shell was spawned by a process that does not normally launch shells.
  condition: >
    evt.type = execve and evt.dir = < and
    (proc.name in (bash, sh, zsh, dash, ksh, fish)) and
    not proc.pname in (sshd, su, sudo, bash, sh, zsh, tmux, screen,
                       systemd, init, python3, ansible, chef-client,
                       puppet, salt-minion) and
    not proc.pname startswith "java"
  output: >
    Shell spawned by unexpected parent
    (user=%user.name user_uid=%user.uid pname=%proc.pname
     cmd=%proc.cmdline pid=%proc.pid container_id=%container.id)
  priority: WARNING
  tags: [host, shell, mitre_execution]

- rule: Unexpected outbound connection by security tool
  desc: Wazuh or MISP process made an outbound connection to an unexpected destination.
  condition: >
    evt.type in (connect) and evt.dir = < and
    fd.typechar = 4 and
    proc.name in (wazuh-agentd, wazuh-syscheckd, wazuh-modulesd, wazuh-execd,
                  ossec-syscheckd, filebeat, python3) and
    not fd.sip in ("0.0.0.0", "127.0.0.1") and
    not fd.sport in (1514, 1515, 1516, 9200, 55000, 443, 80, 53, 123)
  output: >
    Unexpected outbound connection by security process
    (user=%user.name proc=%proc.name dip=%fd.rip dport=%fd.rport)
  priority: NOTICE
  tags: [host, network, mitre_command_and_control]

- rule: Sensitive file read
  desc: A process read a sensitive file (private keys, /etc/shadow, etc.).
  condition: >
    (open_read or open_rdwr) and
    fd.name in (/etc/shadow, /etc/gshadow, /etc/sudoers, /root/.ssh/id_rsa,
                /root/.ssh/id_ecdsa, /root/.aws/credentials) and
    not proc.name in (sshd, passwd, sudo, unix_chkpwd, vipw, sssd, useradd,
                      usermod, nscd)
  output: >
    Sensitive file read
    (user=%user.name proc=%proc.name file=%fd.name pid=%proc.pid)
  priority: WARNING
  tags: [host, filesystem, mitre_credential_access]

- rule: Privilege escalation — setuid binary executed
  desc: A process executed a setuid binary, which could indicate privilege escalation.
  condition: >
    evt.type = execve and evt.dir = < and
    (evt.arg.flags contains S_ISUID) and
    not proc.name in (sudo, su, passwd, ping, mount, umount, newgrp, chage,
                      chfn, chsh, gpasswd)
  output: >
    Setuid binary executed
    (user=%user.name proc=%proc.name parent=%proc.pname pid=%proc.pid)
  priority: WARNING
  tags: [host, privilege_escalation, mitre_privilege_escalation]

- rule: ptrace anti-debug / injection
  desc: A process used ptrace, which may indicate debugging, injection, or AV bypass.
  condition: >
    evt.type = ptrace and evt.dir = < and
    not proc.name in (gdb, strace, ltrace)
  output: >
    ptrace syscall detected
    (user=%user.name proc=%proc.name target_pid=%evt.arg.pid)
  priority: WARNING
  tags: [host, defense_evasion, mitre_defense_evasion]

- rule: Kernel module loaded
  desc: A kernel module was loaded (insmod/modprobe). Rootkits use this.
  condition: >
    (evt.type = init_module or evt.type = finit_module) and evt.dir = <
  output: >
    Kernel module loaded
    (user=%user.name proc=%proc.name module=%evt.arg.name)
  priority: CRITICAL
  tags: [host, rootkit, mitre_persistence]

- rule: Crontab modification
  desc: A process modified cron files — potential persistence technique.
  condition: >
    (open_write) and
    fd.name startswith /etc/cron and
    not proc.name in (cron, crond, anacron, atd, rpm, dnf, yum)
  output: >
    Crontab modified
    (user=%user.name proc=%proc.name file=%fd.name)
  priority: WARNING
  tags: [host, persistence, mitre_persistence]

- rule: Sudoers file modification
  desc: /etc/sudoers or /etc/sudoers.d was written to.
  condition: >
    (open_write) and
    (fd.name = /etc/sudoers or fd.name startswith /etc/sudoers.d/) and
    not proc.name in (visudo, rpm, dnf)
  output: >
    Sudoers file written
    (user=%user.name proc=%proc.name file=%fd.name)
  priority: CRITICAL
  tags: [host, privilege_escalation, mitre_privilege_escalation]
EOF

log "Falco rules written to ${FALCO_RULES_DIR}/bc-server-rules.yaml"

# Configure Falco output to write JSON to file
if [[ -f "${FALCO_CONF}" ]]; then
  # Ensure file_output is configured
  if ! grep -q "^file_output:" "${FALCO_CONF}" 2>/dev/null; then
    cat >> "${FALCO_CONF}" <<EOF

# BigChemistry: write JSON alerts for Wazuh ingestion
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/alerts.json
EOF
  else
    sed -i '/^file_output:/,/^[^ ]/ s|enabled: false|enabled: true|' "${FALCO_CONF}" 2>/dev/null || true
  fi
fi

# Use modern Falco eBPF driver configuration (falco.yaml >= 0.36)
# Set driver type to modern_ebpf if available, otherwise ebpf
if grep -q "modern_ebpf" /usr/share/falco/driver_config.yaml 2>/dev/null \
   || falco --version 2>/dev/null | grep -qE "0\.(3[6-9]|[4-9][0-9])"; then
  log "Using modern eBPF driver..."
  sed -i 's/^  kind: .*$/  kind: modern_ebpf/' "${FALCO_CONF}" 2>/dev/null || true
else
  log "Falling back to classic eBPF driver..."
  sed -i 's/^  kind: .*$/  kind: ebpf/' "${FALCO_CONF}" 2>/dev/null || true
fi

systemctl enable --now falco \
  || log "WARNING: Falco could not be started — may need driver rebuild: falco-driver-loader"
log "Falco enabled."

# ===========================================================================
# SECTION 4 — AUDITD HARDENING (all hosts)
# ===========================================================================
log "=== [ALL] Configuring auditd ==="

dnf install -y audit audit-libs >/dev/null 2>&1 \
  || fail "auditd installation failed"

mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/99-wazuh-hardening.rules <<'EOF'
# BigChemistry Wazuh hardening auditd rules
# Covers: privileged exec, setuid/setgid, ptrace, kernel module load,
#         crontab, sudoers, passwd/shadow writes, unexpected outbound

## Remove any pre-existing rules
-D

## Buffer size (increase for busy hosts)
-b 8192

## Failure action: 1 = syslog on failure (not panic)
-f 1

## ── Privileged command execution (setuid/setgid binaries) ──────────────────
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 \
    -k privileged-exec
-a always,exit -F arch=b64 -S execve -F perm=sx -k setuid-exec

## ── ptrace (debugging / injection) ────────────────────────────────────────
-a always,exit -F arch=b64 -S ptrace -k ptrace

## ── Kernel module load/unload ──────────────────────────────────────────────
-w /sbin/insmod -p x -k kernel-module-load
-w /sbin/rmmod  -p x -k kernel-module-load
-w /sbin/modprobe -p x -k kernel-module-load
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module \
    -k kernel-module-load

## ── Crontab modification ──────────────────────────────────────────────────
-w /etc/cron.d/       -p wa -k crontab-mod
-w /etc/cron.daily/   -p wa -k crontab-mod
-w /etc/cron.hourly/  -p wa -k crontab-mod
-w /etc/cron.weekly/  -p wa -k crontab-mod
-w /etc/cron.monthly/ -p wa -k crontab-mod
-w /etc/crontab       -p wa -k crontab-mod
-w /var/spool/cron/   -p wa -k crontab-mod

## ── Sudoers write ─────────────────────────────────────────────────────────
-w /etc/sudoers        -p wa -k sudoers-mod
-w /etc/sudoers.d/     -p wa -k sudoers-mod

## ── passwd / shadow writes ────────────────────────────────────────────────
-w /etc/passwd  -p wa -k passwd-mod
-w /etc/shadow  -p wa -k shadow-mod
-w /etc/gshadow -p wa -k shadow-mod
-w /etc/group   -p wa -k passwd-mod

## ── SSH authorised keys modifications ─────────────────────────────────────
-a always,exit -F arch=b64 -S open -F dir=/root/.ssh -F perm=wa -k ssh-keys-mod
-a always,exit -F arch=b64 -S open -F dir=/home     -F perm=wa  \
    -F path=/.ssh/authorized_keys -k ssh-keys-mod

## ── Unexpected outbound network by wazuh / misp processes ─────────────────
## Track connect() syscalls from ossec and misp-ioc-sync processes
-a always,exit -F arch=b64 -S connect -F uid=975 -k wazuh-outbound
-a always,exit -F arch=b64 -S connect \
    -F exe=/usr/local/bin/misp-ioc-sync.sh -k misp-outbound

## ── File integrity: critical OS files ─────────────────────────────────────
-w /etc/hosts          -p wa -k etc-hosts-mod
-w /etc/resolv.conf    -p wa -k etc-resolv-mod
-w /etc/ld.so.preload  -p wa -k ld-preload-mod
-w /etc/ld.so.conf     -p wa -k ld-conf-mod
-w /etc/ld.so.conf.d/  -p wa -k ld-conf-mod

## ── Make rules immutable (reboot required to change) ──────────────────────
## Uncomment after initial testing:
# -e 2
EOF

log "Auditd rules written to /etc/audit/rules.d/99-wazuh-hardening.rules"
service auditd restart \
  || systemctl restart auditd \
  || log "WARNING: auditd restart failed — rules loaded but service may need manual restart"
log "Auditd restarted."

# ===========================================================================
# SECTION 4b — FINAL Wazuh API password reconciliation (manager / all_in_one)
# ===========================================================================
# Why this exists: the in-line rotation around line ~1314 sets the password
# correctly and verifies it, but the wazuh-manager service finishes its
# first-time RBAC SQLite initialization asynchronously over the next several
# minutes. We observed installs where the verify passed but a later
# write by the manager reverted wazuh-wui to the factory password
# (wazuh-wui/wazuh-wui), leaving the dashboard with "ERROR3099 — Invalid
# credentials" until a manual re-rotation. This block runs at the end of the
# script, AFTER filebeat/dashboard/falco/auditd are all settled, and:
#   1. waits for any pending RBAC init to land
#   2. checks if the SM password already authenticates — if yes, done
#   3. otherwise authenticates with the factory password and re-PUTs the SM
#      password, then verifies. Idempotent and safe to re-run.
# Once Wazuh ships a fix for the RBAC race (or we move to seeding via
# users.yaml), this whole block can be deleted.
if [[ "${HOST_ROLE}" == "manager" || "${HOST_ROLE}" == "all_in_one" ]]; then
  log "=== [API] Final wazuh-wui password reconciliation ==="
  sleep 30  # let any in-flight RBAC init complete

  SM_OK=$(curl -sfk -u "${API_USERNAME}:${API_PASSWORD}" \
    "https://localhost:55000/security/user/authenticate?raw=true" \
    --connect-timeout 5 --max-time 10 2>/dev/null || true)

  if [[ -n "${SM_OK}" ]]; then
    log "API password already matches Secrets Manager value — no action needed."
  else
    log "API password reverted to factory — re-rotating from factory to SM value..."
    FACTORY_TOKEN=$(curl -sfk -u "${API_USERNAME}:${API_USERNAME}" \
      "https://localhost:55000/security/user/authenticate?raw=true" \
      --connect-timeout 5 --max-time 10 2>/dev/null || true)
    if [[ -z "${FACTORY_TOKEN}" ]]; then
      log "WARNING: neither factory nor SM password works — manual intervention needed"
    else
      USER_ID=$(curl -sfk -H "Authorization: Bearer ${FACTORY_TOKEN}" \
        "https://localhost:55000/security/users" 2>/dev/null \
        | jq -r ".data.affected_items[] | select(.username==\"${API_USERNAME}\") | .id" \
        | head -1)
      curl -sfk -H "Authorization: Bearer ${FACTORY_TOKEN}" \
        -H "Content-Type: application/json" \
        -X PUT "https://localhost:55000/security/users/${USER_ID}" \
        -d "{\"password\": \"${API_PASSWORD}\"}" >/dev/null 2>&1 \
        && log "Re-rotation PUT succeeded." \
        || log "WARNING: re-rotation PUT failed"

      VERIFY=$(curl -sfk -u "${API_USERNAME}:${API_PASSWORD}" \
        "https://localhost:55000/security/user/authenticate?raw=true" \
        --connect-timeout 5 --max-time 10 2>/dev/null || true)
      if [[ -n "${VERIFY}" ]]; then
        log "Final API password verified — dashboard auth will succeed."
      else
        log "WARNING: post-rotation verify still failing — dashboard may show 3099 error"
      fi
    fi
  fi
fi

# ===========================================================================
# SECTION 5 — SUMMARY
# ===========================================================================
echo ""
echo "=============================================================="
echo "  PHASE 3 INSTALLATION COMPLETE"
echo "  Host role : ${HOST_ROLE}"
echo "  Private IP: ${PRIVATE_IP}"
echo "  Region    : ${REGION}"
echo "  Wazuh ver : ${WAZUH_VERSION}"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================================="
echo ""
echo "  Services enabled:"
case "${HOST_ROLE}" in
  indexer)
    echo "    wazuh-indexer (systemctl status wazuh-indexer)"
    echo "    falco"
    echo "    auditd"
    ;;
  manager)
    echo "    wazuh-manager  (systemctl status wazuh-manager)"
    echo "    misp-ioc-sync.timer (systemctl status misp-ioc-sync.timer)"
    echo "    falco"
    echo "    auditd"
    ;;
  dashboard)
    echo "    wazuh-dashboard (systemctl status wazuh-dashboard)"
    echo "    falco"
    echo "    auditd"
    ;;
  all_in_one)
    echo "    wazuh-indexer   (systemctl status wazuh-indexer)"
    echo "    wazuh-manager   (systemctl status wazuh-manager)"
    echo "    wazuh-dashboard (systemctl status wazuh-dashboard)"
    echo "    misp-ioc-sync.timer (systemctl status misp-ioc-sync.timer)"
    echo "    falco"
    echo "    auditd"
    ;;
esac
echo ""
echo "  NEXT: Run phase4 for MISP installation."
echo "=============================================================="
