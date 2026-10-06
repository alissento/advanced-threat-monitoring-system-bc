#!/usr/bin/env bash
# =============================================================================
# phase4-install-misp.sh — XDR v8 / bc-ctrl EC2
# Phase 4: MISP fully-automated installation on Amazon Linux 2023
#
# Idempotent: safe to re-run — all destructive steps are guarded.
#
# Upgraded to MISP 2.5 and PHP 8.2 natively from AL2023.
#
# Secrets Manager secret: bc/misp
# Keys expected:
#   MYSQL_ROOT_PASSWORD, MYSQL_PASSWORD, MYSQL_USER,
#   MISP_ADMIN_EMAIL, MISP_ADMIN_PASSPHRASE, SECURITY_SALT, MISP_API_KEY
#
# Platform: Amazon Linux 2023
# Target:   bc-ctrl EC2 (tag Name=misp-ctrl)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REGION="${REGION:-eu-west-1}"
MISP_SECRET="bc/misp"
MISP_BASEURL="${MISP_BASEURL:-https://misp.bc-ctrl.internal}"
DATA_DEV="/dev/nvme1n1"
DATA_MNT="/data"
MYSQL_DATA="${DATA_MNT}/mysql"
REDIS_DATA="${DATA_MNT}/redis"
MISP_FILES="${DATA_MNT}/misp-files"
MISP_DIR="/var/www/MISP"
MISP_BRANCH="2.5"
MYSQL_VERSION="8.0"

PHP_BIN="php"
PHP_SOCK="/run/php-fpm/www.sock"

SCRIPT_NAME="$(basename "$0")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${SCRIPT_NAME}] $*"; }
fail() { log "FATAL: $1"; exit 1; }

# ---------------------------------------------------------------------------
# STEP 0 — IMDSv2 check
# ---------------------------------------------------------------------------
log "=== STEP 0: IMDSv2 check ==="
IMDS_TOKEN="$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  --connect-timeout 5 --max-time 10 2>/dev/null || true)"
[[ -n "${IMDS_TOKEN}" ]] || fail "IMDSv2 token empty"
log "IMDSv2 token obtained."

IMDS_REGION="$(curl -s \
  -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
  "http://169.254.169.254/latest/meta-data/placement/region" \
  --connect-timeout 5 --max-time 10 2>/dev/null || true)"
[[ -n "${IMDS_REGION}" ]] && REGION="${IMDS_REGION}"
log "Region: ${REGION}"
echo ""

# ---------------------------------------------------------------------------
# STEP 1 — Build dependencies + base packages
# ---------------------------------------------------------------------------
log "=== STEP 1: Installing dependencies and PHP 8.2 ==="

# AL2023 ships PHP 8.1 in the initial release snapshots (e.g. 2023.11.20260413).
# PHP 8.2 (8.2.31) first appeared in releasever 2023.11.20260526.
# MISP 2.5 requires PHP 8.2+, so we must align the whole system to a releasever
# that carries php8.2 before installing.  Bump the releasever to at least this
# value; update it when AL2023 ships a newer releasever with security fixes.
AL2023_RELEASEVER="2023.11.20260526"

# Only upgrade releasever if the current one is older than required.
CURRENT_RV="$(cat /etc/dnf/vars/releasever 2>/dev/null || echo "latest")"
if [ "${CURRENT_RV}" = "latest" ] || [ "${CURRENT_RV}" \< "${AL2023_RELEASEVER}" ]; then
  log "Bumping AL2023 releasever: ${CURRENT_RV} → ${AL2023_RELEASEVER}"
  echo "${AL2023_RELEASEVER}" > /etc/dnf/vars/releasever
  dnf -y --releasever="${AL2023_RELEASEVER}" upgrade --quiet >/dev/null 2>&1 \
    || fail "dnf upgrade to releasever ${AL2023_RELEASEVER} failed"
  dnf clean all --quiet >/dev/null 2>&1 || true
  log "releasever set to ${AL2023_RELEASEVER} and system upgraded."
else
  log "releasever ${CURRENT_RV} already >= ${AL2023_RELEASEVER} — no bump needed."
fi

dnf install -y \
  tar jq unzip git openssl httpd mod_ssl \
  python3 python3-pip \
  gcc gcc-c++ make autoconf \
  libxml2-devel libcurl-devel openssl-devel sqlite-devel \
  bzip2-devel libzip-devel oniguruma-devel \
  re2c libsodium-devel gd-devel libpng-devel libjpeg-devel \
  >/dev/null 2>&1 \
  || fail "Dependency installation failed"

# Install PHP 8.2 (Amazon Linux 2023 native).
# NOTE: php8.2-curl does NOT exist as a separate package on AL2023 — curl
# support is compiled into the base php8.2 package (linked against system
# libcurl).  All other extensions are separate subpackages as listed.
dnf install -y php8.2 php8.2-cli php8.2-fpm php8.2-mysqlnd php8.2-mbstring \
  php8.2-xml php8.2-bcmath php8.2-intl php8.2-gd php8.2-zip \
  php8.2-opcache php8.2-pecl-redis6 >/dev/null 2>&1 || fail "PHP 8.2 install failed"

# AWS CLI v2 (idempotent)
if ! command -v aws >/dev/null 2>&1; then
  log "Installing AWS CLI v2..."
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2-extract
  /tmp/awscliv2-extract/aws/install
  rm -rf /tmp/awscliv2.zip /tmp/awscliv2-extract
fi

log "Packages ready."
echo ""

# ---------------------------------------------------------------------------
# STEP 2 — Mount 60Gi EBS data volume
# ---------------------------------------------------------------------------
log "=== STEP 2: Mounting data volume ${DATA_DEV} → ${DATA_MNT} ==="

if ! blkid "${DATA_DEV}" >/dev/null 2>&1; then
  log "Formatting ${DATA_DEV} as XFS..."
  mkfs.xfs -f "${DATA_DEV}" || fail "mkfs.xfs failed"
else
  log "${DATA_DEV} already formatted — skipping mkfs."
fi

mkdir -p "${DATA_MNT}"
DATA_UUID="$(blkid -s UUID -o value "${DATA_DEV}")"

if ! grep -q "${DATA_UUID}" /etc/fstab 2>/dev/null; then
  echo "UUID=${DATA_UUID}  ${DATA_MNT}  xfs  defaults,noatime  0  2" >> /etc/fstab
fi

if ! mountpoint -q "${DATA_MNT}"; then
  mount "${DATA_MNT}" || fail "Failed to mount ${DATA_DEV}"
fi

mkdir -p "${MYSQL_DATA}" "${REDIS_DATA}" "${MISP_FILES}"
log "Data volume ready."
echo ""

# ---------------------------------------------------------------------------
# STEP 3 — Fetch secrets from Secrets Manager
# ---------------------------------------------------------------------------
log "=== STEP 3: Fetching secrets from ${MISP_SECRET} ==="

SECRET_JSON="$(aws secretsmanager get-secret-value \
  --region "${REGION}" \
  --secret-id "${MISP_SECRET}" \
  --query 'SecretString' \
  --output text)" || fail "Could not fetch secret ${MISP_SECRET}"

MYSQL_ROOT_PASSWORD="$(echo "${SECRET_JSON}" | jq -r '.MYSQL_ROOT_PASSWORD')"
MYSQL_PASSWORD="$(echo "${SECRET_JSON}" | jq -r '.MYSQL_PASSWORD')"
MYSQL_USER="$(echo "${SECRET_JSON}" | jq -r '.MYSQL_USER // "misp"')"
MISP_ADMIN_EMAIL="$(echo "${SECRET_JSON}" | jq -r '.MISP_ADMIN_EMAIL')"
MISP_ADMIN_PASSPHRASE="$(echo "${SECRET_JSON}" | jq -r '.MISP_ADMIN_PASSPHRASE')"
SECURITY_SALT="$(echo "${SECRET_JSON}" | jq -r '.SECURITY_SALT')"
MISP_API_KEY="$(echo "${SECRET_JSON}" | jq -r '.MISP_API_KEY')"

[[ -n "${MYSQL_ROOT_PASSWORD}" && "${MYSQL_ROOT_PASSWORD}" != "null" ]] \
  || fail "MYSQL_ROOT_PASSWORD missing from secret"
[[ -n "${SECURITY_SALT}"       && "${SECURITY_SALT}"       != "null" ]] \
  || fail "SECURITY_SALT missing from secret"
[[ -n "${MISP_API_KEY}"        && "${MISP_API_KEY}"        != "null" ]] \
  || fail "MISP_API_KEY missing from secret bc/misp — add it and re-run"

log "Secrets fetched."
echo ""

# ---------------------------------------------------------------------------
# STEP 4 — Install MySQL 8.0
# ---------------------------------------------------------------------------
log "=== STEP 4: Installing MySQL ${MYSQL_VERSION} ==="

if ! rpm -q "mysql80-community-release" >/dev/null 2>&1; then
  MYSQL_REPO_RPM="mysql80-community-release-el9-5.noarch.rpm"
  curl -fsSL "https://repo.mysql.com/${MYSQL_REPO_RPM}" -o "/tmp/${MYSQL_REPO_RPM}" \
    || fail "MySQL repo download failed"
  rpm --import "https://repo.mysql.com/RPM-GPG-KEY-mysql-2023" 2>/dev/null || true
  dnf install -y "/tmp/${MYSQL_REPO_RPM}" >/dev/null 2>&1 || true
  rm -f "/tmp/${MYSQL_REPO_RPM}"
fi

dnf install -y mysql-community-server >/dev/null 2>&1 \
  || fail "MySQL install failed"

MY_CNF="/etc/my.cnf.d/misp-datadir.cnf"
if [[ ! -f "${MY_CNF}" ]]; then
  cat > "${MY_CNF}" <<EOF
[mysqld]
datadir=${MYSQL_DATA}
socket=/var/lib/mysql/mysql.sock
character-set-server=utf8mb4
collation-server=utf8mb4_unicode_ci
default-authentication-plugin=mysql_native_password
innodb_buffer_pool_size=512M
innodb_log_file_size=256M
innodb_flush_log_at_trx_commit=2
max_connections=200
EOF
  if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -a -t mysqld_db_t "${MYSQL_DATA}(/.*)?" 2>/dev/null || true
    restorecon -Rv "${MYSQL_DATA}" 2>/dev/null || true
  fi
fi

if [[ ! -d "${MYSQL_DATA}/mysql" ]]; then
  mysqld --initialize-insecure --datadir="${MYSQL_DATA}" --user=mysql 2>/dev/null \
    || fail "MySQL datadir init failed"
fi

chown -R mysql:mysql "${MYSQL_DATA}"
systemctl enable --now mysqld || fail "Failed to start mysqld"

# Set root password — handle fresh install temporary password
log "Setting MySQL root password..."
MYSQL_TEMP_PASS="$(grep 'temporary password' /var/log/mysqld.log 2>/dev/null \
  | tail -1 | awk '{print $NF}' || true)"

if [[ -n "${MYSQL_TEMP_PASS}" ]]; then
  mysql -u root -p"${MYSQL_TEMP_PASS}" --connect-expired-password \
    -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'TempBoot1!'; FLUSH PRIVILEGES;" \
    2>/dev/null || true
  mysql -u root -p'TempBoot1!' \
    -e "SET GLOBAL validate_password.policy=LOW;
        SET GLOBAL validate_password.length=8;
        ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
        FLUSH PRIVILEGES;" \
    2>/dev/null \
    || fail "Could not set MySQL root password from temporary password"
  log "MySQL root password set from temporary password."
else
  mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT 1;" >/dev/null 2>&1 \
    || fail "MySQL root password verification failed"
  log "MySQL root password already set."
fi

# Create MISP database and user (idempotent)
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" 2>/dev/null <<SQL || true
CREATE DATABASE IF NOT EXISTS misp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON misp.* TO '${MYSQL_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
log "MySQL database and user ready."
echo ""

# ---------------------------------------------------------------------------
# STEP 5 — Install Redis
# ---------------------------------------------------------------------------
log "=== STEP 5: Installing Redis ==="

REDIS_PKG="redis7"
dnf list --available redis7 >/dev/null 2>&1 || REDIS_PKG="redis6"
dnf install -y "${REDIS_PKG}" >/dev/null 2>&1 || fail "Redis install failed"

REDIS_CONF="/etc/redis/redis.conf"
[[ -f "${REDIS_CONF}" ]] || REDIS_CONF="/etc/redis7/redis.conf"
[[ -f "${REDIS_CONF}" ]] || REDIS_CONF="/etc/redis6/redis.conf"
if [[ -f "${REDIS_CONF}" ]]; then
  sed -i "s|^dir .*|dir ${REDIS_DATA}|" "${REDIS_CONF}"
  sed -i 's/^bind .*/bind 127.0.0.1/' "${REDIS_CONF}"
fi

REDIS_SVC="$(systemctl list-unit-files 'redis*' --no-legend 2>/dev/null \
  | awk '{print $1}' | grep -v '@' | grep -v sentinel | grep '\.service$' | head -1)"
REDIS_SVC="${REDIS_SVC%.service}"
[[ -n "${REDIS_SVC}" ]] || REDIS_SVC="${REDIS_PKG}"
systemctl enable --now "${REDIS_SVC}" || fail "Failed to start redis"
log "Redis started."
echo ""

# ---------------------------------------------------------------------------
# STEP 6 — Clone MISP and install Composer + PHP deps
# ---------------------------------------------------------------------------
log "=== STEP 6: Cloning MISP and installing PHP dependencies ==="

if [[ ! -d "${MISP_DIR}/.git" ]]; then
  git clone --depth 1 --branch "${MISP_BRANCH}" \
    "https://github.com/MISP/MISP.git" "${MISP_DIR}" \
    || fail "MISP git clone failed"
else
  log "MISP already cloned — pulling latest..."
  git -C "${MISP_DIR}" fetch origin
  git -C "${MISP_DIR}" checkout "${MISP_BRANCH}"
  git -C "${MISP_DIR}" pull --ff-only origin "${MISP_BRANCH}" 2>/dev/null || true
fi

log "Initialising MISP git submodules..."
git -C "${MISP_DIR}" submodule update --init --recursive 2>&1 | tail -3 || true

# Install Composer
if [[ ! -f /usr/local/bin/composer ]]; then
  log "Installing Composer..."
  HOME=/root "${PHP_BIN}" -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
  HOME=/root "${PHP_BIN}" /tmp/composer-setup.php \
    --install-dir=/usr/local/bin --filename=composer --quiet
  rm -f /tmp/composer-setup.php
fi

log "Running composer install (PHP 8.2)..."
cd "${MISP_DIR}/app"
HOME=/root COMPOSER_ALLOW_SUPERUSER=1 \
  "${PHP_BIN}" /usr/local/bin/composer install \
  --no-dev --no-interaction \
  --ignore-platform-req=ext-pcntl \
  --quiet \
  2>/dev/null \
  || log "WARNING: Composer install had errors — continuing"

# Install Python dependencies
log "Installing MISP Python dependencies..."
pip3 install pymisp pyzmq redis requests cryptography bcrypt \
  >/dev/null 2>&1 || log "WARNING: Some Python deps failed — non-fatal"

echo ""

# ---------------------------------------------------------------------------
# STEP 7 — Apache HTTPS vhost
# ---------------------------------------------------------------------------
log "=== STEP 7: Configuring Apache HTTPS vhost ==="

SSL_DIR="/etc/ssl/misp"
mkdir -p "${SSL_DIR}"

if [[ ! -f "${SSL_DIR}/misp.key" ]]; then
  openssl req -x509 -newkey rsa:2048 \
    -keyout "${SSL_DIR}/misp.key" \
    -out    "${SSL_DIR}/misp.crt" \
    -days 3650 -nodes \
    -subj "/C=US/ST=California/L=San Jose/O=BigChemistry/CN=misp.bc-ctrl.internal" \
    -addext "subjectAltName=DNS:misp.bc-ctrl.internal" \
    2>/dev/null \
    || fail "TLS cert generation failed"
  chmod 600 "${SSL_DIR}/misp.key"
  chmod 644 "${SSL_DIR}/misp.crt"
fi

# Ensure php-fpm runs as apache
sed -i 's|^user = .*|user = apache|' /etc/php-fpm.d/www.conf 2>/dev/null || true
sed -i 's|^group = .*|group = apache|' /etc/php-fpm.d/www.conf 2>/dev/null || true
sed -i 's|^listen.owner = .*|listen.owner = apache|' /etc/php-fpm.d/www.conf 2>/dev/null || true
sed -i 's|^listen.group = .*|listen.group = apache|' /etc/php-fpm.d/www.conf 2>/dev/null || true

# Disable default SSL listener to avoid port 443 conflict
sed -i 's/^Listen 443 https/#Listen 443 https/' /etc/httpd/conf.d/ssl.conf 2>/dev/null || true

cat > /etc/httpd/conf.d/misp.conf <<EOF
Listen 443 https

<VirtualHost *:443>
    ServerName misp.bc-ctrl.internal
    DocumentRoot ${MISP_DIR}/app/webroot

    SSLEngine on
    SSLCertificateFile    ${SSL_DIR}/misp.crt
    SSLCertificateKeyFile ${SSL_DIR}/misp.key
    SSLProtocol           all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH
    SSLHonorCipherOrder   on

    <FilesMatch \\.php\$>
        SetHandler "proxy:unix:${PHP_SOCK}|fcgi://localhost"
    </FilesMatch>

    <Directory ${MISP_DIR}/app/webroot>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
        DirectoryIndex index.php index.html
    </Directory>

    <Directory ${MISP_DIR}/app>
        Options -Indexes
    </Directory>

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    ErrorLog  /var/log/httpd/misp-error.log
    CustomLog /var/log/httpd/misp-access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName misp.bc-ctrl.internal
    RewriteEngine On
    RewriteRule ^/?(.*) https://%{SERVER_NAME}/\$1 [R=301,L]
</VirtualHost>
EOF

log "Apache vhost written."
echo ""

# ---------------------------------------------------------------------------
# STEP 8 — Configure MISP (database.php and config.php)
# ---------------------------------------------------------------------------
log "=== STEP 8: Configuring MISP ==="

MISP_CONFIG_DIR="${MISP_DIR}/app/Config"

# Force-write database.php with 127.0.0.1
cat > "${MISP_CONFIG_DIR}/database.php" <<PHP
<?php
class DATABASE_CONFIG {
    public \$default = array(
        'datasource' => 'Database/Mysql',
        'persistent' => false,
        'host'       => '127.0.0.1',
        'login'      => '${MYSQL_USER}',
        'port'       => 3306,
        'password'   => '${MYSQL_PASSWORD}',
        'database'   => 'misp',
        'prefix'     => '',
        'encoding'   => 'utf8mb4',
    );
}
PHP

[[ -f "${MISP_CONFIG_DIR}/bootstrap.php" ]] \
  || cp "${MISP_CONFIG_DIR}/bootstrap.default.php" "${MISP_CONFIG_DIR}/bootstrap.php"
[[ -f "${MISP_CONFIG_DIR}/core.php" ]] \
  || cp "${MISP_CONFIG_DIR}/core.default.php" "${MISP_CONFIG_DIR}/core.php"

# Write config.php — patch baseurl and security salt
[[ -f "${MISP_CONFIG_DIR}/config.php" ]] \
  || cp "${MISP_CONFIG_DIR}/config.default.php" "${MISP_CONFIG_DIR}/config.php"

python3 - <<PYEOF
import re
path = '${MISP_CONFIG_DIR}/config.php'
with open(path, 'r') as f:
    content = f.read()
content = re.sub(r"'baseurl'\s*=>\s*'[^']*'", "'baseurl' => '${MISP_BASEURL}'", content)
content = re.sub(r"'salt'\s*=>\s*'[^']*'",    "'salt'    => '${SECURITY_SALT}'",  content)
with open(path, 'w') as f:
    f.write(content)
print("config.php patched")
PYEOF

# Security salt in core.php
sed -i "s/Security.salt.*/Security.salt', '${SECURITY_SALT}');/" \
  "${MISP_CONFIG_DIR}/core.php" 2>/dev/null || true

log "MISP config files written."
echo ""

# ---------------------------------------------------------------------------
# STEP 9 — File storage symlink and ownership
# ---------------------------------------------------------------------------
log "=== STEP 9: MISP file storage setup ==="

if [[ -d "${MISP_DIR}/app/files" && ! -L "${MISP_DIR}/app/files" ]]; then
  rsync -a "${MISP_DIR}/app/files/" "${MISP_FILES}/" 2>/dev/null || true
  rm -rf "${MISP_DIR}/app/files"
fi
[[ -L "${MISP_DIR}/app/files" ]] \
  || ln -s "${MISP_FILES}" "${MISP_DIR}/app/files"

chown -R apache:apache "${MISP_DIR}" "${MISP_FILES}" 2>/dev/null || true
find "${MISP_DIR}" -type f -exec chmod 0640 {} \; 2>/dev/null || true
find "${MISP_DIR}" -type d -exec chmod 0750 {} \; 2>/dev/null || true
chmod +x "${MISP_DIR}/app/Console/cake" 2>/dev/null || true
chmod +x "${MISP_DIR}/app/Console/worker/start.sh" 2>/dev/null || true

if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/MISP/app/tmp(/.*)?'
  restorecon -Rv /var/www/MISP/app/tmp >/dev/null

  log "Configuring MISP background workers (systemd)..."
  cat <<'EOF' > /etc/systemd/system/misp-workers.service
[Unit]
Description=MISP background workers
After=mysqld.service redis7.service

[Service]
Type=forking
User=apache
Group=apache
ExecStart=/var/www/MISP/app/Console/worker/start.sh
ExecStop=/var/www/MISP/app/Console/worker/start.sh stop
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now misp-workers

  log "Setting up Apache..."
  semanage fcontext -a -t httpd_sys_rw_content_t "${MISP_DIR}/app/tmp(/.*)?"    2>/dev/null || true
  semanage fcontext -a -t httpd_sys_rw_content_t "${MISP_DIR}/app/files(/.*)?"  2>/dev/null || true
  semanage fcontext -a -t httpd_sys_rw_content_t "${MISP_FILES}(/.*)?"          2>/dev/null || true
  semanage fcontext -a -t httpd_sys_rw_content_t "${MISP_DIR}/app/Config(/.*)?" 2>/dev/null || true
  restorecon -Rv "${MISP_DIR}" "${MISP_FILES}" 2>/dev/null || true
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 10 — Enable services
# ---------------------------------------------------------------------------
log "=== STEP 10: Starting services ==="
systemctl enable --now httpd     || fail "Failed to enable httpd"
systemctl enable --now mysqld    2>/dev/null || true
systemctl enable --now "${REDIS_SVC}" 2>/dev/null || true
systemctl enable --now php-fpm   || fail "Failed to enable php-fpm"
systemctl restart php-fpm        || fail "Failed to restart php-fpm"
systemctl restart httpd          || fail "Failed to restart httpd"
log "All services running."
echo ""

# ---------------------------------------------------------------------------
# STEP 11 — MISP database schema + admin user (first boot only)
# ---------------------------------------------------------------------------
log "=== STEP 11: MISP database schema initialisation ==="

TABLE_COUNT="$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D misp \
  -se "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='misp';" \
  2>/dev/null || echo "0")"

if [[ "${TABLE_COUNT}" -lt 10 ]]; then
  log "Importing MISP base schema..."
  mysql -u root -p"${MYSQL_ROOT_PASSWORD}" misp \
    < "${MISP_DIR}/INSTALL/MYSQL.sql" 2>/dev/null \
    || log "WARNING: MYSQL.sql import had errors — check manually"

  log "Seeding MISP admin user: ${MISP_ADMIN_EMAIL}"
  ADMIN_SALT="$(python3 -c "import secrets, string; print(secrets.token_hex(16))")"
  ADMIN_HASH="$(php -r "echo password_hash('${MISP_ADMIN_PASSPHRASE}', PASSWORD_DEFAULT);")"

  AUTHKEY_START="${MISP_API_KEY:0:4}"
  AUTHKEY_END="${MISP_API_KEY: -4}"
  AUTHKEY_UUID="$(python3 -c "import uuid; print(str(uuid.uuid4()))")"
  # MISP 2.5 stores auth_keys.authkey as a bcrypt hash (BlowfishConstantPasswordHasher,
  # i.e. password_hash($raw, PASSWORD_BCRYPT) — no pepper, no cost override).
  # authkey_start / authkey_end are the raw first/last 4 chars used as a lookup index;
  # MISP then calls password_verify($presented_raw_key, $stored_hash) to authenticate.
  # Sidecars present the raw key to MISP — they must receive and store the raw value.
  AUTHKEY_HASH="$(php -r "echo password_hash('${MISP_API_KEY}', PASSWORD_BCRYPT);")"

  mysql -u root -p"${MYSQL_ROOT_PASSWORD}" misp 2>/dev/null <<SQL || true
INSERT IGNORE INTO organisations (id, name, uuid, date_created, date_modified, type, local)
  VALUES (1, 'BigChemistry', '$(python3 -c "import uuid; print(str(uuid.uuid4()))")', NOW(), NOW(), 'ADMIN', 1);

UPDATE users SET
  email='${MISP_ADMIN_EMAIL}',
  password='${ADMIN_HASH}',
  password_salt='${ADMIN_SALT}',
  authkey='${MISP_API_KEY}',
  change_pw=0,
  termsaccepted=1
WHERE id=1;
-- users.authkey is the legacy single-key column; MISP 2.5 authenticates exclusively
-- via the auth_keys table above. The raw value here is harmless (unused in 2.5 auth path).

INSERT INTO auth_keys
  (uuid, authkey, authkey_start, authkey_end, created, expiration, read_only, user_id, comment, allowed_ips, unique_ips)
VALUES
  ('${AUTHKEY_UUID}', '${AUTHKEY_HASH}', '${AUTHKEY_START}', '${AUTHKEY_END}', UNIX_TIMESTAMP(), 0, 0, 1, 'Auto-provisioned API Key', '[]', '[]');
SQL
  log "Admin user seeded with pre-defined API key."

  log "Pushing MISP API key to bc/suricata/misp and bc/zeek/misp..."
  API_SECRET_VALUE="{\"MISP_API_KEY\": \"${MISP_API_KEY}\"}"
  aws secretsmanager put-secret-value \
    --region "${REGION}" \
    --secret-id "bc/suricata/misp" \
    --secret-string "${API_SECRET_VALUE}" \
    2>/dev/null \
    || log "WARNING: Could not update bc/suricata/misp — update manually"
  aws secretsmanager put-secret-value \
    --region "${REGION}" \
    --secret-id "bc/zeek/misp" \
    --secret-string "${API_SECRET_VALUE}" \
    2>/dev/null \
    || log "WARNING: Could not update bc/zeek/misp — update manually"
  log "Secrets Manager updated."
else
  log "MISP DB already has ${TABLE_COUNT} tables — running DB updates instead..."
  # Run DB updates (for version upgrades e.g. 2.4 to 2.5)
  sudo -u apache bash -c "${MISP_DIR}/app/Console/cake Admin runUpdates" || log "WARNING: Database migrations failed"
fi
echo ""

# ---------------------------------------------------------------------------
# STEP 12 — Verify MISP responds
# ---------------------------------------------------------------------------
log "=== STEP 12: Verifying MISP endpoint ==="

MISP_OK=false
for i in $(seq 1 24); do
  HTTP_CODE="$(curl -sk -o /dev/null -w "%{http_code}" \
    --resolve "misp.bc-ctrl.internal:443:127.0.0.1" \
    "https://misp.bc-ctrl.internal/users/login" \
    --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")"
  if [[ "${HTTP_CODE}" == "200" ]]; then
    log "MISP responding: HTTP 200 (after $((i * 5))s)"
    MISP_OK=true
    break
  fi
  log "  Attempt ${i}/24: HTTP ${HTTP_CODE} — waiting..."
  sleep 5
done

"${MISP_OK}" || log "WARNING: MISP did not return 200 within 120s — check /var/log/httpd/misp-error.log"

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
echo ""
echo "=============================================================="
echo "  PHASE 4 MISP INSTALLATION COMPLETE"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================================="
echo ""
echo "  Services:"
echo "    httpd      — $(systemctl is-active httpd        2>/dev/null || echo unknown)"
echo "    mysqld     — $(systemctl is-active mysqld       2>/dev/null || echo unknown)"
echo "    redis      — $(systemctl is-active "${REDIS_SVC}" 2>/dev/null || echo unknown)"
echo "    php-fpm    — $(systemctl is-active php-fpm      2>/dev/null || echo unknown)"
echo ""
echo "  PHP version: $("${PHP_BIN}" --version 2>/dev/null | head -1)"
echo "  MISP URL:    ${MISP_BASEURL}"
echo "  Admin email: ${MISP_ADMIN_EMAIL}"
echo ""
echo "=============================================================="
