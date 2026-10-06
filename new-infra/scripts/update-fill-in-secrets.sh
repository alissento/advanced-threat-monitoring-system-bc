#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# update-fill-in-secrets.sh
#
# Run this script after you have:
#   1. Deployed MISP and created an API auth key
#      (Administration → List Auth Keys → Add Authentication Key)
#   2. Created the Shuffle webhook in the SOAR UI
#   3. Created a GitHub PAT for the self-hosted runner
#
# What it does:
#   [1/4] Update bc/wazuh/manager  — PLACEHOLDER_MISP_API_KEY,
#                                     PLACEHOLDER_SHUFFLE_HOOK_ID
#   [2/4] Update bc/suricata/misp  — MISP_API_KEY
#   [3/4] Update bc/zeek/misp      — MISP_API_KEY
#   [4/4] Update bc/misp           — MISP_AUTH_KEY
#
# Usage:
#   export MISP_API_KEY="<key from MISP Admin > Administration > Auth Keys>"
#   export SHUFFLE_HOOK_ID="<UUID from Shuffle Workflow hook URL>"
#   export GITHUB_RUNNER_PAT="ghp_..."
#   bash update-fill-in-secrets.sh
# ──────────────────────────────────────────────────────────────────
set -euo pipefail
REGION="eu-west-1"

: "${MISP_API_KEY:?  Set MISP_API_KEY before running}"
: "${SHUFFLE_HOOK_ID:?  Set SHUFFLE_HOOK_ID before running}"

echo "[1/4] Updating bc/wazuh/manager FILL_IN values..."
CURRENT=$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id bc/wazuh/manager \
  --query SecretString \
  --output text)

UPDATED=$(python3 - <<PYEOF
import json, sys
d = json.loads('''$CURRENT''')
d["PLACEHOLDER_MISP_API_KEY"]    = "$MISP_API_KEY"
d["PLACEHOLDER_SHUFFLE_HOOK_ID"] = "$SHUFFLE_HOOK_ID"
print(json.dumps(d))
PYEOF
)

aws secretsmanager put-secret-value \
  --region "$REGION" \
  --secret-id bc/wazuh/manager \
  --secret-string "$UPDATED"
echo "  bc/wazuh/manager updated"

echo "[2/4] Updating bc/suricata/misp..."
aws secretsmanager put-secret-value \
  --region "$REGION" \
  --secret-id bc/suricata/misp \
  --secret-string "{\"MISP_API_KEY\": \"$MISP_API_KEY\"}"
echo "  bc/suricata/misp updated"

echo "[3/4] Updating bc/zeek/misp..."
aws secretsmanager put-secret-value \
  --region "$REGION" \
  --secret-id bc/zeek/misp \
  --secret-string "{\"MISP_API_KEY\": \"$MISP_API_KEY\"}"
echo "  bc/zeek/misp updated"

echo "[4/4] Updating bc/misp MISP_AUTH_KEY..."
CURRENT_MISP=$(aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id bc/misp \
  --query SecretString \
  --output text)

UPDATED_MISP=$(python3 - <<PYEOF
import json, sys
d = json.loads('''$CURRENT_MISP''')
d["MISP_AUTH_KEY"] = "$MISP_API_KEY"
print(json.dumps(d))
PYEOF
)

aws secretsmanager put-secret-value \
  --region "$REGION" \
  --secret-id bc/misp \
  --secret-string "$UPDATED_MISP"
echo "  bc/misp updated"

echo ""
echo "Done. ExternalSecret operators will pick up the new values"
echo "within their refreshInterval (1h). Force immediate refresh:"
echo "  kubectl annotate externalsecret -n wazuh wazuh-manager-secrets force-sync=\$(date +%s) --overwrite"
echo "  kubectl annotate externalsecret -n suricata suricata-misp-secret force-sync=\$(date +%s) --overwrite"
echo "  kubectl annotate externalsecret -n zeek zeek-misp-secret force-sync=\$(date +%s) --overwrite"
echo "  kubectl annotate externalsecret -n misp misp-secrets force-sync=\$(date +%s) --overwrite"
