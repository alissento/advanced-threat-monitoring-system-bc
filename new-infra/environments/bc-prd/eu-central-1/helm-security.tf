provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
      command     = "aws"
    }
  }
}

# ---------------------------------------------------------------------------
# IRSA role — Cilium operator (ENI IPAM)
#
# Without IRSA the operator falls back to IMDS → node instance role, which
# only has AmazonEKSWorkerNodePolicy. That role lacks ec2:AssignPrivateIpAddresses
# and friends, so the operator can attach ENIs but cannot populate them with
# secondary IPs. Pod IPs end up unknown to AWS (not on any ENI), VPC DNS
# replies are black-holed, and CoreDNS returns SERVFAIL.
#
# Permission set: Cilium reference policy for ENI IPAM mode.
# https://docs.cilium.io/en/v1.19/network/concepts/ipam/eni/#required-privileges
# ---------------------------------------------------------------------------
resource "aws_iam_role" "cilium_operator" {
  name = "${local.platform_name}-${local.env}-cilium-operator"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:kube-system:cilium-operator"
            "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cilium_operator_eni" {
  name = "cilium-operator-eni"
  role = aws_iam_role.cilium_operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeTags",
          "ec2:CreateNetworkInterface",
          "ec2:AttachNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DetachNetworkInterface",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:CreateTags",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "helm_release" "cilium" {
  name            = "cilium"
  repository      = "https://helm.cilium.io/"
  chart           = "cilium"
  version         = "1.19.3"
  namespace       = "kube-system"
  cleanup_on_fail = true

  depends_on = [
    module.eks,
    aws_iam_role.cilium_operator,
    aws_iam_role_policy.cilium_operator_eni,
  ]

  set {
    name  = "eni.enabled"
    value = "true"
  }
  set {
    name  = "ipam.mode"
    value = "eni"
  }
  # Wire the operator ServiceAccount to the IRSA role so the operator uses
  # dedicated ENI IPAM permissions instead of falling back to IMDS → node role.
  # Without this annotation the operator cannot call AssignPrivateIpAddresses,
  # pod IPs are unregistered on any AWS ENI, and VPC DNS is broken (GAP resolved
  # 2026-05-11).
  set {
    name  = "serviceAccounts.operator.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.cilium_operator.arn
  }

  # AWS region for the EC2 / ENI API calls the operator makes.
  # Without this the AWS SDK falls back to IMDS lookup (slow on hostNetwork
  # in some configs) or defaults to us-east-1, so EC2 calls from a
  # eu-west-1 cluster time out:
  #   level=fatal msg="Unable to start eni allocator"
  #   error="unable to initialize ENI instances manager: timed out waiting for the condition"
  # Discovered 2026-05-11 run 25693xxxxx.
  set {
    name  = "operator.extraEnv[0].name"
    value = "AWS_REGION"
  }
  set {
    name  = "operator.extraEnv[0].value"
    value = local.region
  }
  # Cluster name suppresses the operator warning:
  #   "Unable to detect EKS cluster name for ENI garbage collection.
  #    This operator instance may clean up dangling ENIs from other Cilium
  #    clusters."
  # and scopes ENI GC to this cluster's tags only.
  set {
    name  = "cluster.name"
    value = module.eks.cluster_name
  }
  set {
    name  = "routingMode"
    value = "native"
  }
  set {
    name  = "hubble.enabled"
    value = "true"
  }
  set {
    name  = "hubble.relay.enabled"
    value = "true"
  }
  set {
    name  = "hubble.ui.enabled"
    value = "true"
  }
  # Use "default" not "always": "always" causes endpoint-registration race where pods starting
  # under load (cold-start, scale-up) get identity reserved:unmanaged (id=3) and are implicitly
  # denied before their CNP is installed. Enforcement comes from per-endpoint CNPs in
  # new-infra/k8s/system-netpols/ and per-app cilium-netpol.yaml. Discovered 2026-05-10.
  set {
    name  = "policyEnforcementMode"
    value = "default"
  }

  # Phase G: Replace kube-proxy with Cilium eBPF service routing.
  # kube-proxy addon is removed from cluster_addons in eks.tf.
  set {
    name  = "kubeProxyReplacement"
    value = "true"
  }
  set {
    name  = "k8sServiceHost"
    value = trimprefix(module.eks.cluster_endpoint, "https://")
  }
  set {
    name  = "k8sServicePort"
    value = "443"
  }

  # Phase H: WireGuard node-to-node encryption.
  # UDP 51871 is already permitted by the node SG ingress_self_all rule.
  set {
    name  = "encryption.enabled"
    value = "true"
  }
  set {
    name  = "encryption.type"
    value = "wireguard"
  }
  set {
    name  = "encryption.nodeEncryption"
    value = "true"
  }
}

resource "helm_release" "falco" {
  name             = "falco"
  repository       = "https://falcosecurity.github.io/charts"
  chart            = "falco"
  namespace        = "falco"
  create_namespace = true
  version          = "8.0.2"
  timeout          = 600
  cleanup_on_fail  = true
  wait             = false

  depends_on = [module.eks]

  values = [
    file("${path.module}/falco-rules.yaml")
  ]

  set {
    name  = "driver.kind"
    value = "modern_ebpf"
  }
  set {
    name  = "falcoctl.artifact.install.enabled"
    value = "false"
  }
  set {
    name  = "falcoctl.artifact.follow.enabled"
    value = "false"
  }
  set {
    name  = "collectors.containerEngine.enabled"
    value = "true"
  }

  # Tolerate the nomad-dedicated taint so Falco runs on every node,
  # including ip-10-30-11-243 where the NOMAD Oasis stack is co-located.
  set {
    name  = "tolerations[0].key"
    value = "dedicated"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].value"
    value = "nomad"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "helm_release" "tetragon" {
  name            = "tetragon"
  repository      = "https://helm.cilium.io/"
  chart           = "tetragon"
  version         = "1.6.1"
  namespace       = "kube-system"
  cleanup_on_fail = true

  depends_on = [module.eks]

  # ---------------------------------------------------------------------------
  # Tetragon JSON file export — wired into the Wazuh SIEM pipeline.
  #
  # The chart writes events to:
  #   <exportDirectory>/<tetragon.exportFilename>
  # The chart automatically creates a hostPath volume (type=DirectoryOrCreate)
  # at exportDirectory — no extra volume resources are needed. We point
  # exportDirectory at /var/log/tetragon so the file lands under the node-wide
  # /var/log tree that the wazuh-agent DaemonSet already mounts at
  # /host/var/log. The agent reads /host/var/log/tetragon/tetragon.json via
  # the localfile stanza added to configmap.yaml.
  #
  # exportFilePerm: "640" — readable by root + wazuh group. The wazuh-agent
  # container runs as root (privileged), so "600" would also work, but "640"
  # is defensive in case the agent image changes.
  #
  # Rotation: 10 MB per file, 5 backups retained (50 MB total cap per node).
  # With the allow-list below the active write rate drops to near-zero under
  # normal cluster operation (only suspicious exec and kprobe hits reach the
  # file), so 5 × 10 MB is ample headroom and rotation should be infrequent.
  # Wazuh logcollector tails the live file so rotation (rename + new file) is
  # handled by inotify.
  #
  # ---------------------------------------------------------------------------
  # Export filter design — source-side noise suppression
  # ---------------------------------------------------------------------------
  #
  # exportAllowList (Tetragon FieldFilter semantics):
  #   Multiple newline-separated JSON objects are OR'd. An event passes if it
  #   matches at least one allow-list entry AND is not denied by denyList.
  #   The allowList is evaluated BEFORE the denyList.
  #
  #   Line 1 — ALL kprobe events (any namespace, any binary):
  #     Keeps every PROCESS_KPROBE event so that Wazuh rules 100700 (SIGKILL)
  #     and 100701 (non-SIGKILL kprobe) are always fed. The sigkill-malicious-
  #     tools TracingPolicy fires kprobe hooks on sys_execve for nc/nmap in
  #     any namespace including kube-system and the host; dropping these by
  #     namespace would blind rule 100700. The event-type filter alone is the
  #     right gate — no namespace or binary restriction here.
  #
  #     Volume note (2026-06-03): The primary noise gate for kprobe events is
  #     the matchBinaries NotIn exclusion list in privileges-raise.yaml.
  #     Live investigation on AL2023 + containerd 2.2.3 nodes found that
  #     /usr/sbin/runc (the actual runc path on this AMI) was NOT in the
  #     exclusion list — the policy only had /usr/bin/runc and
  #     /usr/local/sbin/runc. That omission caused /usr/sbin/runc to generate
  #     100% of the kprobe flood (~1.9 MB/min/node, 10 MB rotation every ~6 min).
  #     The rateLimit:"1m" per-selector did NOT suppress this because each new
  #     runc PID (one per container start) has an independent rate-limit counter.
  #     Fix: /usr/sbin/runc and /usr/lib/systemd/systemd added to all
  #     matchBinaries NotIn lists in privileges-raise.yaml. The allowList here
  #     remains unchanged — no events should reach it from those binaries
  #     after the TracingPolicy fix.
  #
  #   Line 2 — PROCESS_EXEC for sensitive binaries only:
  #     binary_regex selects exactly the binaries referenced by rules 100702,
  #     100703, and 100704. Every other exec event (routine kubelet, containerd,
  #     pause, coredns, cilium-agent, etc.) is silently dropped at source —
  #     never written to disk, never forwarded to the Wazuh manager EC2.
  #
  #     Binary coverage cross-check (mirrors bc-tetragon.xml exactly):
  #       Rule 100702 — shells/interpreters:
  #         sh, bash, dash, zsh, fish, python, python2, python3, perl, ruby,
  #         node, lua
  #       Rule 100703 — priv-esc tools:
  #         su, sudo, nsenter, unshare, chroot, setuid, newuidmap, newgidmap
  #       Rule 100704 — network recon tools:
  #         curl, wget, ncat, socat, ss, netstat, dig, nslookup, host
  #       (nc and nmap are NOT listed here: they are SIGKILL'd at kprobe level
  #       by the TracingPolicy and surface via PROCESS_KPROBE / rule 100700,
  #       not PROCESS_EXEC / rule 100704 — they are already covered by line 1.)
  #
  #   PROCESS_EXIT events: intentionally excluded from the allowList.
  #     No current Wazuh rule queries process_exit fields. Including
  #     PROCESS_EXIT unconditionally would add ~1 exit event per matched exec,
  #     doubling volume with zero detection value. Add a third allowList line
  #     here if an exit-based rule is ever written.
  #
  # exportDenyList:
  #   health_check=true is kept to drop kubelet liveness-probe exec events
  #   that Tetragon tags at the API level. The previous change had removed the
  #   default kube-system/"" namespace deny entries to avoid losing kprobe hits
  #   from those namespaces — that removal is now safe to leave in place because
  #   the allowList is the primary gate. kube-system exec noise that would have
  #   leaked through the removed namespace deny is now suppressed by the
  #   binary_regex on line 2: routine kube-system binaries (cilium-agent,
  #   coredns, kubelet, containerd-shim, pause, aws-k8s-agent) do not match
  #   the sensitive-binary regex, so they are dropped by the allowList
  #   before denyList is even evaluated.
  #
  # ---------------------------------------------------------------------------
  # Why values = [ heredoc ] instead of set {} for the export keys:
  #
  # Terraform's helm_release set {} block routes values through Helm's --set
  # parser, which tokenises on [ ] , { } = . as structure characters. The JSON
  # strings in exportAllowList and exportDenyList are dense with those chars
  # (braces, brackets, commas, colons), so --set misparses them — it tries to
  # interpret "[\"PROCESS_EXEC\"]" as a list index and fails with:
  #   "error parsing index: strconv.Atoi: parsing \"PROCESS_EXEC\": invalid syntax"
  # terraform plan does NOT exercise the --set parser (plan only validates TF
  # HCL), so the failure only surfaces at apply time (CI run 26879732371).
  #
  # values = [ <<-EOT ... EOT ] passes the content as a --values file (raw
  # YAML), which Helm reads with its YAML parser — no --set tokenisation.
  # Arbitrary JSON strings are safe in YAML block scalars. The scalar scalars
  # (exportDirectory, exportFilename, etc.) are included here too to keep all
  # export config in one place and avoid set-vs-values precedence confusion.
  #
  # Chart key structure (tetragon 1.6.1, templates/tetragon_configmap.yaml):
  #   .Values.exportDirectory           → top-level (not under tetragon.)
  #   .Values.tetragon.exportFilename   → renders: <exportDirectory>/<exportFilename>
  #   .Values.tetragon.exportFilePerm   → passed through | quote in template
  #   .Values.tetragon.exportFileMaxSizeMB / exportFileMaxBackups → | quote
  #   .Values.tetragon.exportAllowList  → rendered as: export-allowlist: |-
  #                                          {{ . | trim | nindent 4 }}
  #   .Values.tetragon.exportDenyList   → same pattern
  # ---------------------------------------------------------------------------
  values = [
    <<-EOT
    exportDirectory: /var/log/tetragon

    tetragon:
      exportFilename: tetragon.json
      exportFilePerm: "640"
      exportFileMaxSizeMB: 10
      exportFileMaxBackups: 5
      exportAllowList: |-
        {"event_set":["PROCESS_KPROBE"]}
        {"event_set":["PROCESS_EXEC"],"binary_regex":["(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/)(?:sh|bash|dash|zsh|fish|python[23]?|perl|ruby|node|lua|su|sudo|nsenter|unshare|chroot|setuid|newuidmap|newgidmap|curl|wget|ncat|socat|ss|netstat|dig|nslookup|host)"]}
      exportDenyList: |-
        {"health_check":true}
    EOT
  ]
}

resource "helm_release" "external_secrets" {
  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  namespace        = "external-secrets"
  create_namespace = true
  version          = "0.10.7"
  cleanup_on_fail  = true
  wait             = false
  timeout          = 600

  depends_on = [module.eks]

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.external_secrets.arn
  }

  # Disable the validating webhook entirely — the reconcile loop does not need it.
  # The webhook only validates user-submitted manifests; disabling it eliminates the
  # cert-controller startup race that caused ClusterSecretStore creation to fail.
  set {
    name  = "webhook.create"
    value = "false"
  }

  # Allow ESO to spill onto the nomad node when workload nodes are full.
  # t3.medium workload nodes cap at 17 pods; NOMAD Oasis deployment saturated both
  # nodes and left ESO Pending, breaking ClusterSecretStore and all ExternalSecrets.
  # Tolerating dedicated=nomad:NoSchedule does NOT force ESO onto the nomad node —
  # the scheduler still prefers workload slots when available.
  # NOTE: webhook.tolerations and certController.tolerations are included for
  # forward-compatibility; they are no-ops while webhook.create=false.
  set {
    name  = "tolerations[0].key"
    value = "dedicated"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].value"
    value = "nomad"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
  set {
    name  = "webhook.tolerations[0].key"
    value = "dedicated"
  }
  set {
    name  = "webhook.tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "webhook.tolerations[0].value"
    value = "nomad"
  }
  set {
    name  = "webhook.tolerations[0].effect"
    value = "NoSchedule"
  }
  set {
    name  = "certController.tolerations[0].key"
    value = "dedicated"
  }
  set {
    name  = "certController.tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "certController.tolerations[0].value"
    value = "nomad"
  }
  set {
    name  = "certController.tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "aws_iam_role" "external_secrets" {
  name = "bc-uatms-prd-external-secrets"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:external-secrets:external-secrets"
            "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "external_secrets_secrets_manager" {
  name = "external-secrets-secrets-manager"
  role = aws_iam_role.external_secrets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          # Existing XDR stack secrets
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/wazuh/*",
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/suricata/*",
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/zeek/*",
          # NOMAD Oasis secrets (shells created in secrets-nomad.tf; values populated by CI)
          aws_secretsmanager_secret.nomad_api.arn,
          aws_secretsmanager_secret.nomad_mongo.arn,
          aws_secretsmanager_secret.nomad_keycloak.arn,
          aws_secretsmanager_secret.nomad_north.arn,
          aws_secretsmanager_secret.nomad_datacite.arn,
        ]
      },
      {
        # ESO needs Decrypt + DescribeKey to read the SM secrets encrypted with the
        # EKS KMS key (module.eks.kms_key_arn == local.nomad_sm_kms_key_id).
        # kms:ViaService restricts this permission to calls originating from
        # Secrets Manager only — ESO cannot use this grant for raw KMS operations.
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = [module.eks.kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${local.region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# AWS Load Balancer Controller
#
# Required for ALB ingress when NOMAD Oasis Phase I (ACM + public zone) is
# complete. Deployed now so the CRDs (IngressClassParams, TargetGroupBinding)
# are available in the cluster; no ALB is created until ingress.enabled=true
# in the NOMAD Helm values.
#
# IRSA trust: restricts to the aws-load-balancer-controller ServiceAccount in
# kube-system — least-privilege per-service-account binding.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "alb_controller" {
  name = "${local.platform_name}-${local.env}-alb-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
            "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# ALB Controller IAM policy — inline, sourced from the official AWS policy doc.
# Policy document: https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json
# Pinned to the permissions required for v2.x. Update when bumping chart version.
resource "aws_iam_role_policy" "alb_controller" {
  name = "alb-controller-policy"
  role = aws_iam_role.alb_controller.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateServiceLinkedRole"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:DescribeTrustStores",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:GetSubscriptionState",
          "shield:DescribeProtection",
          "shield:CreateProtection",
          "shield:DeleteProtection",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateSecurityGroup"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateTags"]
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          StringEquals = { "ec2:CreateAction" = "CreateSecurityGroup" }
          Null         = { "aws:RequestedRegion" = "false" }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags",
        ]
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          Null = {
            "aws:RequestedRegion"                     = "false"
            "aws:ResourceTag/ingress.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DeleteSecurityGroup",
        ]
        Resource = "*"
        Condition = {
          Null = { "aws:ResourceTag/ingress.k8s.aws/cluster" = "false" }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup",
        ]
        Resource = "*"
        Condition = {
          Null = { "aws:RequestedRegion" = "false" }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:DeleteRule",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags",
        ]
        Resource = [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
        ]
        Condition = {
          Null = {
            "aws:RequestedRegion"                     = "false"
            "aws:ResourceTag/ingress.k8s.aws/cluster" = "true"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags",
        ]
        Resource = [
          "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup",
        ]
        Resource = "*"
        Condition = {
          Null = { "aws:ResourceTag/ingress.k8s.aws/cluster" = "false" }
        }
      },
      {
        Effect = "Allow"
        Action = ["elasticloadbalancing:AddTags"]
        Resource = [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
        ]
        Condition = {
          StringEquals = { "elasticloadbalancing:CreateAction" = ["CreateTargetGroup", "CreateLoadBalancer"] }
          Null         = { "aws:RequestedRegion" = "false" }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
        ]
        Resource = "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:ModifyRule",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "helm_release" "aws_load_balancer_controller" {
  name            = "aws-load-balancer-controller"
  repository      = "https://aws.github.io/eks-charts"
  chart           = "aws-load-balancer-controller"
  namespace       = "kube-system"
  version         = "1.13.0"
  cleanup_on_fail = true
  timeout         = 600

  # Must deploy before NOMAD Helm release so ALB IngressClass CRDs exist.
  # Also depends on the Cilium release being up — otherwise the controller
  # pod has no network and will crash-loop during Helm wait.
  depends_on = [
    module.eks,
    helm_release.cilium,
    aws_iam_role.alb_controller,
  ]

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "region"
    value = local.region
  }
  set {
    name  = "vpcId"
    value = module.vpc.vpc_id
  }
  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.alb_controller.arn
  }

  # Disable the Service-mutator admission webhook.
  #
  # The chart registers three mutating webhooks (mpod, mservice, mtgb).
  # The mservice one intercepts every Service create on the apiserver. On
  # cold-start (or any time an ALB controller pod has a stale/unrouted IP)
  # apiserver calls to the webhook time out. The chart hardcodes
  # failurePolicy=Fail for mservice (webhookConfig.failurePolicy only affects
  # mpod in this chart version), so timeouts block the Service create:
  #
  #   failed to create resource: Internal error occurred: failed calling
  #   webhook "mservice.elbv2.k8s.aws": context deadline exceeded
  #
  # Disabling the webhook entirely is the right move for this stack:
  #   - All our in-cluster Services (NOMAD, security stack) are ClusterIP.
  #   - The mservice webhook only adds AWS-specific labels to LoadBalancer-
  #     type Services for ALB/NLB binding — we have no LoadBalancer Services.
  #   - If LoadBalancer Services are ever introduced (e.g., for Hubble UI
  #     ingress), the chart's Service controller still reconciles them
  #     using its own discovery loop; the webhook is only an optimization.
  set {
    name  = "enableServiceMutatorWebhook"
    value = "false"
  }
}

# resource "helm_release" "shuffle" {
#   name             = "shuffle"
#   chart            = "${path.module}/../../../k8s/shuffle"
#   namespace        = "shuffle"
#   create_namespace = true
#   cleanup_on_fail  = true
#   timeout          = 900
#   wait             = true
#
#   depends_on = [module.eks]
#
#   set {
#     name  = "opensearch.sysctlInit.enabled"
#     value = "true"
#   }
# }
