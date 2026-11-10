"""Attack-path risk model: a Markov chain built from scan findings.

States: the attacker enters the app, abuses a class of weakness (injection, secrets, code execution,
exposure/misconfiguration) and either ends up COMPROMISED or is CONTAINED. Transition probabilities
come from a prior (how weaknesses chain together in practice) scaled by how many / how severe the
findings of each class are. Risk = probability of absorption in COMPROMISED starting from ENTRY.
"""
from __future__ import annotations

import math
from typing import Dict, List

from .markov import MarkovChain

WEIGHT = {"low": 1, "medium": 2, "high": 4, "critical": 8}
CATS = ["injection", "secrets", "execution", "exposure"]
LABELS = {
    "entry": "Attacker reaches the app", "injection": "Input injection", "secrets": "Credential theft",
    "execution": "Code execution", "exposure": "Data exposure / misconfiguration",
    "compromised": "System compromised", "contained": "Attack contained",
}
ESCALATION = {"injection": 0.30, "secrets": 0.55, "execution": 0.60, "exposure": 0.25}
LATERAL = {
    "injection": {"execution": 0.25, "secrets": 0.15, "exposure": 0.20},
    "secrets": {"exposure": 0.25, "execution": 0.10},
    "execution": {"secrets": 0.25, "exposure": 0.20},
    "exposure": {"secrets": 0.15, "execution": 0.05},
}
STATES = ["entry"] + CATS + ["compromised", "contained"]


def _level(score: float) -> str:
    return "low" if score < 15 else "moderate" if score < 35 else "high" if score < 60 else "critical"


def build_risk_model(findings: List[dict]) -> dict:
    weight = {c: 0 for c in CATS}
    for f in findings:
        weight[f["category"]] += WEIGHT[f["severity"]]
    intensity = {c: 1 - math.exp(-weight[c] / 8.0) for c in CATS}

    n = len(STATES)
    ix = {s: i for i, s in enumerate(STATES)}
    m = [[0.0] * n for _ in range(n)]
    total_i = sum(intensity.values())
    denom = 1 + 0.5 * total_i
    for c in CATS:
        m[ix["entry"]][ix[c]] = intensity[c] / denom
    m[ix["entry"]][ix["contained"]] = 1 / denom
    for c in CATS:
        row = {"compromised": ESCALATION[c] * (0.4 + 0.6 * intensity[c])}
        for d, p in LATERAL[c].items():
            row[d] = p * intensity[d]
        total = sum(row.values())
        if total > 0.95:
            row = {k: v * 0.95 / total for k, v in row.items()}
            total = 0.95
        for k, v in row.items():
            m[ix[c]][ix[k]] = v
        m[ix[c]][ix["contained"]] = 1 - total
    m[ix["compromised"]][ix["compromised"]] = 1.0
    m[ix["contained"]][ix["contained"]] = 1.0

    chain = MarkovChain(STATES)
    chain.load_matrix(m)
    score = round(chain.absorption_probability("entry", "compromised", ["compromised", "contained"]) * 100, 1)
    path = chain.most_likely_path("entry", "compromised") if score > 0 else None
    return {
        "score": score, "level": _level(score),
        "states": [{"id": s, "label": LABELS[s]} for s in STATES],
        "matrix": [[round(v, 4) for v in row] for row in m],
        "most_likely_path": path or [],
        "path_labels": [LABELS[s] for s in (path or [])],
        "weights": weight,
    }
