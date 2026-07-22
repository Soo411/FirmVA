# candidates/static/crypt.py: 약한 암호(Cryptography) (단독 항목)
########################################################
# ISTG-FW-CRYPT-001  Usage of Weak Cryptographic Algorithms

# 이 계열은 항목이 1개뿐이라 파일 하나가 곧 하위 에이전트 하나임

# 입력 : observed (StaticRaw JSON)
# 출력 : 취약 판정 Finding 목록
########################################################

import json
import re
from typing import Any

PHASE = "static"
LOC = "filesystem/binaries"


WEAK_CRYPTO_RULES = [
    {
        "name": "weak_hash_md5",
        "category": "weak_hash",
        "pattern": (
            r"\b(?:MD5|EVP_md5|MD5_Init|MD5_Update|MD5_Final|md5sum|"
            r"mbedtls_md5|wolfSSL_MD5)\b"
        ),
        "risk": "MD5 is collision-prone and should not be used for security decisions.",
    },
    {
        "name": "weak_hash_sha1",
        "category": "weak_hash",
        "pattern": (
            r"\b(?:SHA1|SHA-1|EVP_sha1|SHA1_Init|SHA1_Update|SHA1_Final|"
            r"mbedtls_sha1|wolfSSL_SHA1)\b"
        ),
        "risk": "SHA-1 is collision-prone and deprecated for security-sensitive use.",
    },
    {
        "name": "weak_block_cipher_des",
        "category": "weak_cipher",
        "pattern": (
            r"\b(?:DES|3DES|DES_set_key|DES_ecb_encrypt|DES_cbc_encrypt|"
            r"EVP_des|EVP_des_ede3|mbedtls_des|wolfSSL_DES)\b"
        ),
        "risk": "DES and 3DES are deprecated weak block ciphers.",
    },
    {
        "name": "weak_stream_cipher_rc4",
        "category": "weak_cipher",
        "pattern": r"\b(?:RC4|ARCFOUR|RC4_set_key|RC4_options|EVP_rc4|wolfSSL_RC4)\b",
        "risk": "RC4 is a deprecated stream cipher with practical biases.",
    },
    {
        "name": "weak_mode_ecb",
        "category": "weak_mode",
        "pattern": r"\b(?:ECB|AES[-_][0-9]+[-_]ECB|DES[-_]ECB|EVP_aes_[0-9]+_ecb|EVP_des_ecb)\b",
        "risk": "ECB mode leaks plaintext patterns and is unsafe for most encrypted data.",
    },
    {
        "name": "obsolete_tls",
        "category": "weak_protocol",
        "pattern": r"\b(?:SSLv2|SSLv3|TLSv1(?:\.0)?(?!\.\d)|TLSv1_(?:client_|server_)?method|SSLv23_method)\b",
        "risk": "Obsolete SSL/TLS protocols are no longer considered secure.",
    },
    {
        "name": "legacy_rsa_generation",
        "category": "weak_keygen",
        "pattern": r"\b(?:RSA_generate_key|RSA_generate_key_ex)\b",
        "risk": "Legacy RSA key generation APIs require careful key size and padding checks.",
    },
]

HIGH_SIGNAL_FIELDS = {"imports", "dangerous_calls"}
LOW_SIGNAL_VALUES = {
    "content-md5",
    "etag-md5",
    "md5sum",
}


def check_crypt_001(observed: str):
    from ..base import judge

    return judge("ISTG-FW-CRYPT-001", PHASE, observed, LOC)


def run(observed: str) -> list:
    evidence = collect_crypto_evidence(observed)
    if not evidence:
        return []

    crypt_observed = json.dumps(
        {"crypto_evidence": evidence},
        ensure_ascii=False,
        indent=2,
    )
    f = check_crypt_001(crypt_observed)
    return [f] if f else []


def collect_crypto_evidence(observed: str) -> list[dict[str, Any]]:
    raw = _parse_observed(observed)
    if raw is None:
        return []

    findings: list[dict[str, Any]] = []
    for binary in raw.get("binaries", []):
        findings.extend(_scan_binary(binary))

    findings.extend(_scan_global_items("configs", raw.get("configs", [])))
    findings.extend(_scan_global_items("files", raw.get("files", [])))

    return _dedupe_evidence(findings)


def _parse_observed(observed: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(observed)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _scan_binary(binary: dict[str, Any]) -> list[dict[str, Any]]:
    path = str(binary.get("path", "<unknown>"))
    findings: list[dict[str, Any]] = []

    for field in ("imports", "strings", "dangerous_calls"):
        values = binary.get(field, [])
        if not isinstance(values, list):
            continue

        for value in values:
            findings.extend(_scan_value(str(value), field, path))

    return findings


def _scan_global_items(field: str, values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []

    findings: list[dict[str, Any]] = []
    for value in values:
        findings.extend(_scan_value(str(value), field, "filesystem"))
    return findings


def _scan_value(value: str, field: str, location: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    normalized = value.lower()

    for rule in WEAK_CRYPTO_RULES:
        if not re.search(rule["pattern"], value, flags=re.IGNORECASE):
            continue

        confidence = _confidence_hint(field, normalized)
        findings.append({
            "location": location,
            "source_field": field,
            "matched_value": value,
            "rule": rule["name"],
            "category": rule["category"],
            "risk": rule["risk"],
            "confidence_hint": confidence,
        })

    return findings


def _dedupe_evidence(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for finding in findings:
        key = (
            finding["location"],
            finding["source_field"],
            finding["matched_value"],
            finding["rule"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def _confidence_hint(field: str, normalized_value: str) -> str:
    if field in HIGH_SIGNAL_FIELDS:
        return "high"
    if normalized_value in LOW_SIGNAL_VALUES or normalized_value.startswith("content-md5"):
        return "low"
    if "(" in normalized_value or "=" in normalized_value:
        return "medium"
    return "low"
