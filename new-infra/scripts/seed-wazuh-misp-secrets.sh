#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# seed-wazuh-misp-secrets.sh
#
# Creates the base credential secrets that the Wazuh and MISP EC2 install
# scripts (phase3-install-wazuh.sh / phase4-install-misp.sh) read at boot:
#
#   bc/wazuh/manager   — INDEXER_*/API_* creds + cluster key (+ FILL_IN placeholders)
#   bc/misp            — MySQL creds, MISP admin login, security salt, API key
#   bc/suricata/misp   — MISP_API_KEY (for the misp-rule-sync sidecar via ESO)
#   bc/zeek/misp       — MISP_API_KEY (for the misp-intel-sync sidecar via ESO)
#
# WHY THIS EXISTS:
#   These secrets were originally created BY HAND in the first AWS account and
#   never codified (unlike bc/nomad-oasis/* which Terraform + seed-nomad-secrets.sh
#   manage). On a fresh account / cold-start they don't exist, so Wazuh/MISP
#   installs hard-fail. This script makes that bootstrap reproducible.
#
# CREATE-IF-ABSENT, NEVER CLOBBER:
#   Unlike seed-nomad-secrets.sh (which re-syncs from GitHub secrets every run),
#   these values ARE the source of truth — once Wazuh/MISP install with them,
#   regenerating would desync the live software. So an existing secret is left
#   untouched. To rotate, delete the secret and re-run, then re-provision the EC2.
#
# POST-DEPLOY FILL-IN:
#   The real MISP API key / Shuffle hook are reconciled by update-fill-in-secrets.sh
#   AFTER MISP is up. The key seeded here is adopted by MISP at install (phase4
#   inserts it as the admin authkey), so the sidecars work immediately.
#
# Usage:
#   [MISP_ADMIN_EMAIL=admin@bc-ctrl.internal] bash seed-wazuh-misp-secrets.sh
#   Newly-generated human logins are printed to stderr ONCE. Save them.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
REGION="${AWS_REGION:-eu-west-1}"
MISP_ADMIN_EMAIL="${MISP_ADMIN_EMAIL:-admin@bc-ctrl.internal}"

log() { echo "$@" >&2; }

# Strong password with guaranteed complexity (>=1 upper/lower/digit/special).
# Special set excludes shell/JSON/SQL-hazardous chars ($ " ' \ ` / etc.).
gen_pw()    { python3 -c 'import secrets,string; sp="@%._-+="; pools=[string.ascii_uppercase,string.ascii_lowercase,string.digits,sp]; c=[secrets.choice(p) for p in pools]; allc=string.ascii_letters+string.digits+sp; c+=[secrets.choice(allc) for _ in range(24-len(c))]; r=secrets.SystemRandom(); r.shuffle(c); print("".join(c))'; }
gen_alnum() { python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range($1)))"; }
gen_hex()   { python3 -c "import secrets; print(secrets.token_hex($1))"; }

secret_exists() { aws secretsmanager describe-secret --region "$REGION" --secret-id "$1" >/dev/null 2>&1; }

# create_if_absent NAME JSON_STRING
create_if_absent() {
  local name="$1" json="$2"
  if secret_exists "$name"; then
    log "  • ${name} already exists — left untouched"
    return 1
  fi
  aws secretsmanager create-secret --region "$REGION" --name "$name" \
    --description "Seeded by seed-wazuh-misp-secrets.sh" \
    --secret-string "$json" >/dev/null
  log "  ✓ ${name} created"
  return 0
}

log "=== Seeding Wazuh/MISP base secrets in account $(aws sts get-caller-identity --query Account --output text), region ${REGION} ==="

# ── bc/misp (and the shared MISP API key) ───────────────────────────────────
if secret_exists "bc/misp"; then
  log "  • bc/misp already exists — reusing its MISP_API_KEY for sidecar secrets"
  EFFECTIVE_MISP_KEY="$(aws secretsmanager get-secret-value --region "$REGION" --secret-id bc/misp --query SecretString --output text | python3 -c 'import sys,json; print(json.load(sys.stdin).get("MISP_API_KEY",""))')"
else
  MYSQL_ROOT_PASSWORD="$(gen_pw)"
  MYSQL_PASSWORD="$(gen_pw)"
  MISP_ADMIN_PASSPHRASE="$(gen_pw)"
  SECURITY_SALT="$(gen_alnum 40)"
  EFFECTIVE_MISP_KEY="$(gen_alnum 40)"
  MISP_JSON="$(jq -n \
    --arg root "$MYSQL_ROOT_PASSWORD" --arg pw "$MYSQL_PASSWORD" --arg user "misp" \
    --arg email "$MISP_ADMIN_EMAIL" --arg pass "$MISP_ADMIN_PASSPHRASE" \
    --arg salt "$SECURITY_SALT" --arg key "$EFFECTIVE_MISP_KEY" \
    '{MYSQL_ROOT_PASSWORD:$root, MYSQL_PASSWORD:$pw, MYSQL_USER:$user, MISP_ADMIN_EMAIL:$email, MISP_ADMIN_PASSPHRASE:$pass, SECURITY_SALT:$salt, MISP_API_KEY:$key}')"
  create_if_absent "bc/misp" "$MISP_JSON" || true
  log ""
  log "  ┌── MISP dashboard login (SAVE THIS — shown once) ──"
  log "  │  URL (after deploy): https://misp.bc-ctrl.internal"
  log "  │  email:      ${MISP_ADMIN_EMAIL}"
  log "  │  passphrase: ${MISP_ADMIN_PASSPHRASE}"
  log "  │  API key:    ${EFFECTIVE_MISP_KEY}"
  log "  └───────────────────────────────────────────────────"
fi

# ── bc/wazuh/manager ─────────────────────────────────────────────────────────
if ! secret_exists "bc/wazuh/manager"; then
  INDEXER_PASSWORD="$(gen_pw)"
  API_PASSWORD="$(gen_pw)"
  CLUSTER_KEY="$(gen_hex 16)"   # 32 hex chars
  WAZUH_JSON="$(jq -n \
    --arg iu "admin" --arg ip "$INDEXER_PASSWORD" \
    --arg au "wazuh-wui" --arg ap "$API_PASSWORD" --arg ck "$CLUSTER_KEY" \
    '{INDEXER_USERNAME:$iu, INDEXER_PASSWORD:$ip, API_USERNAME:$au, API_PASSWORD:$ap, PLACEHOLDER_CLUSTER_KEY:$ck, PLACEHOLDER_MISP_API_KEY:"", PLACEHOLDER_SHUFFLE_HOOK_ID:""}')"
  create_if_absent "bc/wazuh/manager" "$WAZUH_JSON" || true
  log ""
  log "  ┌── Wazuh logins (SAVE THIS — shown once) ──"
  log "  │  URL (after deploy): https://wazuh-dashboard.bc-ctrl.internal"
  log "  │  indexer admin: admin / ${INDEXER_PASSWORD}"
  log "  │  API user:      wazuh-wui / ${API_PASSWORD}"
  log "  └────────────────────────────────────────────"
else
  log "  • bc/wazuh/manager already exists — left untouched"
fi

# ── bc/suricata/misp + bc/zeek/misp (sidecar API key, synced by ESO) ─────────
SIDECAR_JSON="$(jq -n --arg key "$EFFECTIVE_MISP_KEY" '{MISP_API_KEY:$key}')"
create_if_absent "bc/suricata/misp" "$SIDECAR_JSON" || true
create_if_absent "bc/zeek/misp"     "$SIDECAR_JSON" || true

log ""
log "=== Done. These are the base creds; update-fill-in-secrets.sh reconciles the"
log "    real MISP API key / Shuffle hook after MISP is deployed. ==="
