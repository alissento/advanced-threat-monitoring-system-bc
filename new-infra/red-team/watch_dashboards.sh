#!/usr/bin/env bash
# watch_dashboards.sh — tail all detection sensors simultaneously in a tmux split
# Run this before launching the attack demo.
#
# Usage:
#   ./new-infra/red-team/watch_dashboards.sh [--no-tmux]
#
# Requires: tmux, kubectl, aws CLI

set -euo pipefail

KUBECONFIG_PATH="${KUBECONFIG:-/tmp/kubeconfig-prd}"
WAZUH_INSTANCE="i-0f5b346b3a4f626a6"
MISP_INSTANCE="i-0a32ffa7d8ba62be9"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

export KUBECONFIG="$KUBECONFIG_PATH"

if [[ "${1:-}" == "--no-tmux" ]]; then
  echo -e "${YELLOW}${BOLD}Dashboard access commands:${NC}"
  echo ""
  echo -e "${CYAN}Wazuh Dashboard${NC} → https://localhost:8443"
  echo "  aws ssm start-session \\"
  echo "    --target $WAZUH_INSTANCE --region eu-west-1 \\"
  echo "    --document-name AWS-StartPortForwardingSession \\"
  echo "    --parameters '{\"portNumber\":[\"443\"],\"localPortNumber\":[\"8443\"]}'"
  echo ""
  echo -e "${CYAN}MISP${NC} → https://localhost:8444"
  echo "  aws ssm start-session \\"
  echo "    --target $MISP_INSTANCE --region eu-west-1 \\"
  echo "    --document-name AWS-StartPortForwardingSession \\"
  echo "    --parameters '{\"portNumber\":[\"443\"],\"localPortNumber\":[\"8444\"]}'"
  echo ""
  echo -e "${CYAN}Hubble UI${NC} → http://localhost:12000"
  echo "  kubectl -n kube-system port-forward svc/hubble-ui 12000:80"
  echo ""
  echo -e "${CYAN}Falco live:${NC}"
  echo "  kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco -f"
  echo ""
  echo -e "${CYAN}Tetragon live:${NC}"
  echo "  kubectl -n kube-system logs ds/tetragon -c export-stdout -f"
  exit 0
fi

# ── tmux layout ──────────────────────────────────────────────────────────────
SESSION="uatms-demo"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
fi

tmux new-session -d -s "$SESSION" -x 220 -y 55

# Pane 0 (top-left): Falco live
tmux send-keys -t "$SESSION:0.0" \
  "echo -e '${YELLOW}${BOLD}[FALCO] Live alert stream${NC}' && \
   kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco -f --tail=5 | \
   grep --line-buffered -E 'Critical|Warning|rule' | \
   python3 -c \"
import sys,json
for line in sys.stdin:
    line=line.strip()
    try:
        d=json.loads(line)
        pri=d.get('priority','?')
        rule=d.get('rule','?')
        ns=d.get('output_fields',{}).get('k8s.ns.name','?')
        t=d.get('time','')[:19]
        col='\\033[91m' if pri=='Critical' else '\\033[93m'
        print(f'{col}[{t}] [{pri}] {rule}  ns={ns}\\033[0m')
    except:
        print(line[:120])
sys.stdout.flush()
\"" Enter

# Split vertically (top-right): Tetragon live
tmux split-window -t "$SESSION:0.0" -h
tmux send-keys -t "$SESSION:0.1" \
  "echo -e '${RED}${BOLD}[TETRAGON] SIGKILL stream${NC}' && \
   kubectl -n kube-system logs ds/tetragon -c export-stdout -f --tail=5 | \
   python3 -c \"
import sys,json
for line in sys.stdin:
    line=line.strip()
    try:
        d=json.loads(line)
        kp=d.get('process_kprobe',{})
        if kp.get('action')=='KPROBE_ACTION_SIGKILL':
            proc=kp.get('process',{})
            binary=proc.get('binary','?')
            policy=kp.get('policy_name','?')
            t=d.get('time','')[:19]
            ns=proc.get('pod',{}).get('namespace','?')
            print(f'\\033[91m\\033[1m[{t}] SIGKILL {binary}  ns={ns}  policy={policy}\\033[0m')
            sys.stdout.flush()
    except:
        pass
\"" Enter

# Split horizontally (bottom): Zeek conn.log tail + Suricata
tmux split-window -t "$SESSION:0.0" -v
tmux send-keys -t "$SESSION:0.2" \
  "echo -e '${CYAN}${BOLD}[ZEEK] Connection log — lateral movement tracker${NC}' && \
   kubectl exec -n zeek zeek-nqdqx -c zeek -- \
     bash -c 'tail -f /var/log/zeek/conn.log 2>/dev/null' | \
   python3 -c \"
import sys,json
for line in sys.stdin:
    line=line.strip()
    try:
        d=json.loads(line)
        state=d.get('conn_state','?')
        src=f\\\"{d.get('id.orig_h')}:{d.get('id.orig_p')}\\\"
        dst=f\\\"{d.get('id.resp_h')}:{d.get('id.resp_p')}\\\"
        col='\\033[92m' if state=='S0' else '\\033[96m'
        print(f'{col}{src} -> {dst}  state={state}\\033[0m')
        sys.stdout.flush()
    except:
        pass
\"" Enter

# Split bottom-right: Suricata alerts
tmux split-window -t "$SESSION:0.2" -h
tmux send-keys -t "$SESSION:0.3" \
  "echo -e '${GREEN}${BOLD}[SURICATA] Alert stream${NC}' && \
   kubectl exec -n suricata suricata-bskdv -c suricata -- \
     bash -c 'tail -f /var/log/suricata/eve.json 2>/dev/null' | \
   python3 -c \"
import sys,json
for line in sys.stdin:
    line=line.strip()
    try:
        d=json.loads(line)
        if d.get('event_type')=='alert':
            sig=d.get('alert',{}).get('signature','?')
            src=d.get('src_ip','?')
            dst=d.get('dest_ip','?')
            t=d.get('timestamp','')[:19]
            print(f'\\033[92m[{t}] ALERT {sig}  {src}->{dst}\\033[0m')
            sys.stdout.flush()
    except:
        pass
\"" Enter

tmux select-pane -t "$SESSION:0.0"
tmux attach-session -t "$SESSION"
