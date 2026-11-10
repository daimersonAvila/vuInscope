"""Mitigation playbooks. SIMULATION ONLY: the service never executes anything.
All resource identifiers (sg-..., i-...) are fictitious placeholders; user text is never interpolated into commands."""
from __future__ import annotations

from typing import Dict, List

from .i18n_es import PLAYBOOK_ES, norm_lang
from .models import IDENTIFIER_RE

_BY_SEVERITY = {
    "baja": ("Preventive monitoring and a periodic patch audit.",
             [("List pending security updates", "bash",
               "sudo apt-get update && sudo apt-get --just-print upgrade | grep -i security"),
              ("Scan container images on push (AWS ECR)", "bash",
               "aws ecr put-image-scanning-configuration --repository-name app-repo \\\n  --image-scanning-configuration scanOnPush=true")]),
    "media": ("Intermediate perimeter restriction and a scheduled fix (within 30 days).",
              [("Rate-limit the service port (example: 8080)", "bash",
                "sudo iptables -A INPUT -p tcp --dport 8080 -m limit --limit 25/minute -j ACCEPT\nsudo iptables -A INPUT -p tcp --dport 8080 -j DROP"),
               ("Enable a managed WAF rule group in front of the app (AWS WAF)", "bash",
                "aws wafv2 list-available-managed-rule-groups --scope REGIONAL")]),
    "alta": ("Apply urgent patches in the next maintenance window and restrict access meanwhile.",
             [("Upgrade only the affected package", "bash",
               "sudo apt-get install --only-upgrade -y openssl libssl-dev"),
              ("Restrict the resource to the corporate VPN range (AWS Security Group)", "bash",
               "aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 443 --cidr 0.0.0.0/0\n"
               "aws ec2 authorize-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 443 --cidr 192.168.1.0/24")]),
    "critica": ("IMMEDIATE ISOLATION of the resource. Emergency mitigation is active.",
                [("Stop the affected service to halt exploitation", "bash",
                  "sudo systemctl stop vulnerable-service && sudo systemctl disable vulnerable-service"),
                 ("Quarantine the instance with an isolated Security Group (AWS)", "bash",
                  "aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 --groups sg-quarantine-isolated-id")]),
}

_BY_CATEGORY = {
    "secrets": [("Rotate the exposed credential (AWS IAM example)", "bash",
                 "aws iam create-access-key --user-name <service-user>\naws iam update-access-key --user-name <service-user> --access-key-id <OLD_KEY_ID> --status Inactive"),
                ("Purge the secret from git history", "bash",
                 "git filter-repo --invert-paths --path .env   # then force-push and rotate every exposed value")],
    "injection": [("Block common injection payloads at the edge (AWS WAF managed rules)", "bash",
                   "aws wafv2 list-available-managed-rule-groups --scope REGIONAL | grep -i -E 'SQLi|CommonRuleSet'"),
                  ("Run the app with a least-privilege database user", "sql",
                   "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM app_user;\nGRANT SELECT, INSERT, UPDATE ON orders TO app_user;")],
    "execution": [("Run the container read-only, non-root, without extra capabilities", "yaml",
                   "securityContext:\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\n  allowPrivilegeEscalation: false\n  capabilities: { drop: [\"ALL\"] }")],
    "exposure": [("Add baseline security headers at the reverse proxy", "nginx",
                  "add_header X-Content-Type-Options nosniff always;\nadd_header X-Frame-Options DENY always;\nadd_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;")],
}


def build_playbook(severity: str, identifier: str = "", category: str = "", state: str = "abierta", lang: str = "en") -> dict:
    """`severity` uses registry values (baja/media/alta/critica)."""
    es = norm_lang(lang) == "es"
    tr = (lambda x: PLAYBOOK_ES.get(x, x)) if es else (lambda x: x)
    ident = identifier if IDENTIFIER_RE.match(identifier or "") else "n/a"
    if state in ("cerrada", "mitigada"):
        msg = (f"Sin acción pendiente: la vulnerabilidad ya está {state}." if es
               else f"No pending action: the vulnerability is already {state}.")
        return {"simulation": True, "pending_action": False, "strategy": msg, "steps": []}
    strategy, steps = _BY_SEVERITY.get(severity, ("Manual analysis by the security team.", []))
    out: List[Dict[str, str]] = [{"label": tr(l), "language": lg, "code": f"# Reference: {ident}\n{code}"} for l, lg, code in steps]
    for l, lg, code in _BY_CATEGORY.get(category, []):
        out.append({"label": tr(l), "language": lg, "code": code})
    if not out:
        out.append({"label": tr("Configure manual alerts in the cloud console"), "language": "text",
                    "code": tr("No automated script is available for this severity.")})
    return {"simulation": True, "pending_action": True, "strategy": tr(strategy), "reference": ident, "steps": out}
