"""Quality Gate: pass / warning / fail verdict from the severity counts of a scan."""
from __future__ import annotations

# A gate fails when a "fail" limit is exceeded; it only warns when a "warn" limit is exceeded.
FAIL_LIMITS = {"critical": 0, "high": 2}
WARN_LIMITS = {"high": 0, "medium": 5}


def evaluate_gate(by_severity: dict) -> dict:
    counts = {k: int(by_severity.get(k, 0)) for k in ("critical", "high", "medium", "low")}
    failed = [{"severity": k, "count": counts[k], "limit": lim} for k, lim in FAIL_LIMITS.items() if counts[k] > lim]
    warned = [{"severity": k, "count": counts[k], "limit": lim} for k, lim in WARN_LIMITS.items()
              if counts[k] > lim and not any(f["severity"] == k for f in failed)]
    status = "failed" if failed else ("warning" if warned else "passed")
    return {"status": status, "conditions": failed or warned,
            "limits": {"fail": FAIL_LIMITS, "warn": WARN_LIMITS}}