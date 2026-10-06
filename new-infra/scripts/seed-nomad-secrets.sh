#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# seed-nomad-secrets.sh
#
# Syncs NOMAD Oasis credentials from GitHub Actions environment variables
# (which are populated from GitHub repo secrets) into AWS Secrets Manager.
#
# This runs in the production-plane CI job, AFTER Stage 1 terraform apply
# has created the aws_secretsmanager_secret shells (secrets-nomad.tf), and
# BEFORE Stage 2 applies the NOMAD Helm release.
#
# COLD-START SAFETY:
#   - If a GitHub secret is unset, the env var is empty and we write the
#     placeholder value "unused" instead. This keeps the AWS SM secret as
#     valid JSON so ExternalSecret CRs can sync without error. The NOMAD
#     Helm chart treats "unused" as a no-op for subsystems that are disabled
#     (Keycloak, NORTH, DataCite are all disabled in v1).
#   - If an AWS SM path does not yet exist (TF hasn't run), we emit a WARNING
#     to stderr and skip that path without hard-failing. This allows ad-hoc
#     re-runs of this script outside of the full pipeline without cascading
#     errors.
#
# IDEMPOTENCY:
#   Before every put-secret-value, we fetch the current value and compare
#   sha256 hashes. Only writes if content differs. This prevents creating
#   unnecessary secret versions (each version is stored and billable) on
#   every CI run that doesn't rotate credentials.
#
# SECURITY:
#   - Secret values are NEVER echoed to stdout or stderr.
#   - jq -n constructs JSON from arguments — safe for special characters.
#   - All status output goes to stderr (>&2) so it can be captured separately
#     from the secret JSON if this script is ever used in a pipeline.
#
# ROTATION:
#   To rotate: update the GitHub repo secret, then re-run the pipeline.
#   For emergency rotation, run this script manually via SSM on the runner:
#     aws ssm start-session --target <runner-instance-id> --region eu-west-1
#     export NOMAD_OASIS_API_SECRET="<new-value>"
#     bash new-infra/scripts/seed-nomad-secrets.sh
#   Then restart affected pods:
#     kubectl -n nomad-oasis rollout restart deployment
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REGION="eu-west-1"
PLACEHOLDER="unused"

# ─────────────────────────────────────────────────────────────────────────────
# Helper: write_secret <path> <json>
#   Compares sha256 of the proposed JSON against the current stored value.
#   Only calls put-secret-value if content has changed.
#   Logs result to stderr (updated / skipped / missing-shell).
#   NEVER logs the JSON content itself.
# ─────────────────────────────────────────────────────────────────────────────
write_secret() {
  local path="$1"
  local proposed_json="$2"

  # Check whether the shell secret exists. If it doesn't, TF hasn't run yet.
  local exists
  exists=$(aws secretsmanager describe-secret \
    --region "$REGION" \
    --secret-id "$path" \
    --query 'ARN' \
    --output text 2>/dev/null || echo "NOT_FOUND")

  if [ "$exists" = "NOT_FOUND" ] || [ -z "$exists" ]; then
    echo "  WARNING: $path — secret shell not found in AWS SM. Skipping." >&2
    echo "           Run terraform apply for bc-prd first to create the shell." >&2
    return 0
  fi

  # Fetch current stored value and compute its hash.
  local current_json
  current_json=$(aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$path" \
    --query 'SecretString' \
    --output text 2>/dev/null || echo "")

  local current_hash proposed_hash
  current_hash=$(printf '%s' "$current_json" | sha256sum | cut -d' ' -f1)
  proposed_hash=$(printf '%s' "$proposed_json" | sha256sum | cut -d' ' -f1)

  if [ "$current_hash" = "$proposed_hash" ]; then
    echo "  SKIPPED  $path — content unchanged (hash: ${proposed_hash:0:12}...)" >&2
    return 0
  fi

  aws secretsmanager put-secret-value \
    --region "$REGION" \
    --secret-id "$path" \
    --secret-string "$proposed_json" \
    --output json > /dev/null

  echo "  UPDATED  $path — new version written (hash: ${proposed_hash:0:12}...)" >&2
}

# ─────────────────────────────────────────────────────────────────────────────
# Resolve env vars with placeholder fallback.
# GitHub Actions sets the var to empty string when the secret is unset;
# the || operator catches that and substitutes $PLACEHOLDER.
# ─────────────────────────────────────────────────────────────────────────────
API_SECRET="${NOMAD_OASIS_API_SECRET:-$PLACEHOLDER}"
MONGO_ROOT_PASSWORD="${NOMAD_OASIS_MONGO_ROOT_PASSWORD:-$PLACEHOLDER}"
KEYCLOAK_PASSWORD="${NOMAD_OASIS_KEYCLOAK_PASSWORD:-$PLACEHOLDER}"
KEYCLOAK_CLIENT_SECRET="${NOMAD_OASIS_KEYCLOAK_CLIENT_SECRET:-$PLACEHOLDER}"
KEYCLOAK_DB_PASSWORD="${NOMAD_KEYCLOAK_DB_PASSWORD:-$PLACEHOLDER}"
NORTH_HUB_TOKEN="${NOMAD_OASIS_NORTH_HUB_TOKEN:-$PLACEHOLDER}"
DATACITE_USERNAME="${NOMAD_OASIS_DATACITE_USERNAME:-$PLACEHOLDER}"
DATACITE_PASSWORD="${NOMAD_OASIS_DATACITE_PASSWORD:-$PLACEHOLDER}"

# Use $PLACEHOLDER for any var that is empty after env resolution.
[ -z "$API_SECRET" ]              && API_SECRET="$PLACEHOLDER"
[ -z "$MONGO_ROOT_PASSWORD" ]     && MONGO_ROOT_PASSWORD="$PLACEHOLDER"
[ -z "$KEYCLOAK_PASSWORD" ]       && KEYCLOAK_PASSWORD="$PLACEHOLDER"
[ -z "$KEYCLOAK_CLIENT_SECRET" ]  && KEYCLOAK_CLIENT_SECRET="$PLACEHOLDER"
[ -z "$KEYCLOAK_DB_PASSWORD" ]    && KEYCLOAK_DB_PASSWORD="$PLACEHOLDER"
[ -z "$NORTH_HUB_TOKEN" ]         && NORTH_HUB_TOKEN="$PLACEHOLDER"
[ -z "$DATACITE_USERNAME" ]       && DATACITE_USERNAME="$PLACEHOLDER"
[ -z "$DATACITE_PASSWORD" ]       && DATACITE_PASSWORD="$PLACEHOLDER"

echo "=== Seeding NOMAD Oasis secrets into AWS Secrets Manager ===" >&2

# ─────────────────────────────────────────────────────────────────────────────
# [1/5] bc/nomad-oasis/api
#   Keys: api_secret
#   Used by: nomad.secrets.api (NOMAD Helm values)
# ─────────────────────────────────────────────────────────────────────────────
echo "[1/5] bc/nomad-oasis/api" >&2
nomad_api_json=$(jq -cn \
  --arg api_secret "$API_SECRET" \
  '{"api_secret": $api_secret}')
write_secret "bc/nomad-oasis/api" "$nomad_api_json"

# ─────────────────────────────────────────────────────────────────────────────
# [2/5] bc/nomad-oasis/mongo
#   Keys: root_password
#   Used by: mongodb.auth.rootPassword (NOMAD Helm values)
# ─────────────────────────────────────────────────────────────────────────────
echo "[2/5] bc/nomad-oasis/mongo" >&2
nomad_mongo_json=$(jq -cn \
  --arg root_password "$MONGO_ROOT_PASSWORD" \
  '{"root_password": $root_password}')
write_secret "bc/nomad-oasis/mongo" "$nomad_mongo_json"

# ─────────────────────────────────────────────────────────────────────────────
# [3/5] bc/nomad-oasis/keycloak
#   Keys: password, client_secret, db_password
#   Used by:
#     password      → KEYCLOAK_ADMIN_PASSWORD env in keycloakx sub-chart
#     client_secret → nomad.secrets.keycloak.clientSecret (future OIDC client)
#     db_password   → KC_DB_PASSWORD env (Keycloak → PostgreSQL auth)
#   db_password sourced from NOMAD_KEYCLOAK_DB_PASSWORD GitHub Secret.
# ─────────────────────────────────────────────────────────────────────────────
echo "[3/5] bc/nomad-oasis/keycloak" >&2
nomad_keycloak_json=$(jq -cn \
  --arg password       "$KEYCLOAK_PASSWORD" \
  --arg client_secret  "$KEYCLOAK_CLIENT_SECRET" \
  --arg db_password    "$KEYCLOAK_DB_PASSWORD" \
  '{"password": $password, "client_secret": $client_secret, "db_password": $db_password}')
write_secret "bc/nomad-oasis/keycloak" "$nomad_keycloak_json"

# ─────────────────────────────────────────────────────────────────────────────
# [4/5] bc/nomad-oasis/north
#   Keys: hub_service_api_token
#   Used by: nomad.secrets.north.hubServiceApiToken
#   v1: north federation is disabled — defaults to "unused"
# ─────────────────────────────────────────────────────────────────────────────
echo "[4/5] bc/nomad-oasis/north" >&2
nomad_north_json=$(jq -cn \
  --arg hub_service_api_token "$NORTH_HUB_TOKEN" \
  '{"hub_service_api_token": $hub_service_api_token}')
write_secret "bc/nomad-oasis/north" "$nomad_north_json"

# ─────────────────────────────────────────────────────────────────────────────
# [5/5] bc/nomad-oasis/datacite
#   Keys: username, password
#   Used by: nomad.secrets.datacite.username / .password
#   v1: DataCite DOI minting is disabled — defaults to "unused"
# ─────────────────────────────────────────────────────────────────────────────
echo "[5/5] bc/nomad-oasis/datacite" >&2
nomad_datacite_json=$(jq -cn \
  --arg username "$DATACITE_USERNAME" \
  --arg password "$DATACITE_PASSWORD" \
  '{"username": $username, "password": $password}')
write_secret "bc/nomad-oasis/datacite" "$nomad_datacite_json"

echo "=== NOMAD secret seeding complete ===" >&2
