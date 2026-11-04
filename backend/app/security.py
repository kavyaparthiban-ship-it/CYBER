from __future__ import annotations

from typing import Any


WEIGHTS = {"FAIL": 30, "WARNING": 15, "PASS": 0, "UNKNOWN": 0}


def _finding(parameter: str, observed: str, expected: str, status: str, reason: str, recommendation: str) -> dict[str, Any]:
    severity = {"FAIL": "HIGH", "WARNING": "MEDIUM", "PASS": "LOW", "UNKNOWN": "INFO"}[status]
    return {
        "id": f"HG-{parameter.upper().replace(' ', '-')}",
        "parameter": parameter,
        "observed": observed,
        "expected": expected,
        "status": status,
        "severity": severity,
        "risk_contribution": WEIGHTS[status],
        "reason": reason,
        "recommendation": recommendation,
    }


def assess(transforms: list[dict[str, Any]]) -> dict[str, Any]:
    """Assess observable IKEv2 SA_INIT offers; never infer negotiation results."""
    by_type: dict[str, list[dict[str, Any]]] = {}
    for transform in transforms:
        by_type.setdefault(transform["type"], []).append(transform)
    findings: list[dict[str, Any]] = []

    encryption = by_type.get("encryption", [])
    if not encryption:
        findings.append(_finding(
            "Encryption algorithm", "Not observed", "A modern, approved cipher suite", "UNKNOWN",
            "No IKEv2 encryption transform was observed in the captured exchange.",
            "Capture a complete IKEv2 SA_INIT exchange containing the SA proposal.",
        ))
    else:
        names = sorted({item["name"] for item in encryption})
        legacy = [item["name"] for item in encryption if item["id"] in (3, 11)]
        cbc = [item["name"] for item in encryption if item["id"] == 12]
        if legacy:
            findings.append(_finding(
                "Encryption algorithm", ", ".join(names), "AEAD such as AES-GCM",
                "FAIL", "The observed offer includes legacy 3DES or a legacy/null cipher.",
                "Remove legacy transforms and prefer an approved authenticated-encryption suite.",
            ))
        elif cbc:
            findings.append(_finding(
                "Encryption algorithm", ", ".join(names), "Prefer an AEAD suite such as AES-GCM",
                "WARNING", "AES-CBC is offered; this is not evidence that a session negotiated it.",
                "Prefer an approved AEAD suite and verify integrity settings in the complete negotiation.",
            ))
        else:
            findings.append(_finding(
                "Encryption algorithm", ", ".join(names), "An approved modern cipher suite", "PASS",
                "The observed encryption offer contains no cipher flagged by this PoC's limited rules.",
                "Confirm policy and key sizes against your organization's current cryptographic standard.",
            ))

    prfs = by_type.get("prf", [])
    if not prfs:
        findings.append(_finding(
            "PRF algorithm", "Not observed", "A current pseudorandom function", "UNKNOWN",
            "No IKEv2 PRF transform was observed in the captured proposal.",
            "Capture a complete IKEv2 SA_INIT exchange containing the SA proposal.",
        ))
    else:
        names = sorted({item["name"] for item in prfs})
        if any(item["id"] == 2 for item in prfs):
            findings.append(_finding(
                "PRF algorithm", ", ".join(names), "Prefer a SHA-2-based PRF",
                "WARNING", "The observed offer includes PRF-HMAC-SHA1; this is an offered transform, not a negotiated setting.",
                "Review peer compatibility and prefer a current PRF allowed by organizational policy.",
            ))
        else:
            findings.append(_finding(
                "PRF algorithm", ", ".join(names), "A currently approved PRF", "PASS",
                "No SHA-1 PRF covered by this PoC's limited rules was observed.",
                "Confirm the complete negotiation and organizational cryptographic policy.",
            ))

    integrity = by_type.get("integrity", [])
    if not integrity and any(item["id"] == 20 for item in encryption):
        findings.append(_finding(
            "Integrity algorithm", "Not separate (AEAD offer observed)", "Authenticated encryption",
            "UNKNOWN", "The observed offer contains AES-GCM; integrity is provided by AEAD, but negotiation was not observed.",
            "Inspect the complete IKE exchange before confirming the negotiated protection.",
        ))
    elif not integrity:
        findings.append(_finding(
            "Integrity algorithm", "Not observed", "A current integrity algorithm or AEAD",
            "UNKNOWN", "No IKEv2 integrity transform was available in the observed SA payload.",
            "Capture a complete IKEv2 SA_INIT exchange containing the SA proposal.",
        ))
    else:
        names = sorted({item["name"] for item in integrity})
        if any(item["id"] in (1, 2, 3) for item in integrity):
            findings.append(_finding(
                "Integrity algorithm", ", ".join(names), "A current SHA-2 integrity transform or AEAD",
                "FAIL", "The offer includes HMAC-SHA1 or an older integrity transform.",
                "Remove SHA-1 and other legacy integrity transforms; prefer current SHA-2 or AEAD.",
            ))
        else:
            findings.append(_finding(
                "Integrity algorithm", ", ".join(names), "A current integrity transform or AEAD", "PASS",
                "No legacy integrity transform covered by this PoC's limited rules was observed.",
                "Confirm the complete negotiation and organizational cryptographic policy.",
            ))

    groups = by_type.get("dh_group", [])
    if not groups:
        findings.append(_finding(
            "Diffie-Hellman group", "Not observed", "A currently approved group", "UNKNOWN",
            "No IKEv2 Diffie-Hellman transform was observed.",
            "Capture an IKEv2 SA_INIT exchange containing the key-exchange proposal.",
        ))
    else:
        names = sorted({item["name"] for item in groups})
        weak = [item["name"] for item in groups if item["id"] in (1, 2, 5)]
        if weak:
            findings.append(_finding(
                "Diffie-Hellman group", ", ".join(names), "A currently approved group (for example, group 14 or stronger)",
                "FAIL", "The offer includes a legacy group, including MODP group 2 (1024-bit).",
                "Remove legacy groups; select a group allowed by current policy and verify peer support.",
            ))
        elif all(item["id"] in (14, 19, 20, 31) for item in groups):
            findings.append(_finding(
                "Diffie-Hellman group", ", ".join(names), "A currently approved group", "PASS",
                "The observed group IDs are not flagged by this PoC's limited rules.",
                "Confirm group approval against the current deployment policy.",
            ))
        else:
            findings.append(_finding(
                "Diffie-Hellman group", ", ".join(names), "A currently approved group", "UNKNOWN",
                "At least one observed group is not covered by this PoC's rule set.",
                "Review every offered group against a current cryptographic policy.",
            ))

    findings.extend([
        _finding(
            "Perfect Forward Secrecy", "Not observed", "Verify per Child SA policy", "UNKNOWN",
            "IKE_SA_INIT proposals alone do not establish the Child SA rekey/PFS configuration.",
            "Capture the relevant Child SA negotiation and inspect the deployed rekey policy.",
        ),
        _finding(
            "IKE authentication", "Not observed", "Verify authentication method and identity policy", "UNKNOWN",
            "The available capture does not establish IKE_AUTH authentication settings.",
            "Capture IKE_AUTH metadata where available; do not infer identity or authentication from encrypted payloads.",
        ),
        _finding(
            "Key lifetime", "Not observed", "Verify configured IKE and Child SA lifetimes", "UNKNOWN",
            "Key lifetime policy is not reliably determined from the observed packet headers.",
            "Review the configured endpoint policy or a complete exchange; this analyzer does not infer a lifetime.",
        ),
    ])
    score = min(100, sum(item["risk_contribution"] for item in findings))
    category = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW"
    return {
        "score": score,
        "category": category,
        "formula": "Sum of deterministic finding weights (FAIL=30, WARNING=15, PASS/UNKNOWN=0), capped at 100.",
        "findings": findings,
    }
