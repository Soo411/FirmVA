# candidates/static/scrt.py: Secrets candidate checks
########################################################
# ISTG-FW-SCRT-001  Secrets Stored in Public Storage
# ISTG-FW-SCRT-002  Unencrypted Storage of Secrets
# ISTG-FW-SCRT-003  Usage of Hardcoded Secrets
########################################################

import json
import math
import re
from typing import Any

PHASE = "static"
LOC = "filesystem/binaries"


PUBLIC_PATH_PATTERNS = [
    r"/(?:www|wwwroot|htdocs|html|home/httpd|var/www|srv/www)(?:/|$)",
    r"/(?:cgi-bin|web|public)(?:/|$)",
]

SECRET_FILE_PATTERNS = [
    r"(?:^|/)\.env(?:$|\.)",
    r"(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:$|\.)",
    r"(?:^|/).*\.pem$",
    r"(?:^|/).*\.key$",
    r"(?:^|/).*\.p12$",
    r"(?:^|/).*\.pfx$",
    r"(?:^|/)(?:passwd|shadow|httpd\.passwd|htpasswd|password|credentials?|secrets?)(?:$|\.)",
    r"(?:^|/).*(?:password|passwd|secret|credential|token|key|psk|shadow|htpasswd).*\.(?:cfg|conf|ini|json|xml|bak)$",
    r"(?:^|/)iconfig\.cfg$",
]

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|auth[_-]?token|token|session[_-]?key|credential|"
    r"backdoor|admin[_-]?pass|psk|wpa[_-]?psk"
    r")\b\s*[:=]\s*['\"]?([^'\"\s;&]{4,})"
)

PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
HASHED_PASSWORD_RE = re.compile(r"^\$[156y]\$|^[a-f0-9]{32}$|^[a-f0-9]{40}$", re.IGNORECASE)
HIGH_ENTROPY_TOKEN_RE = re.compile(r"(?=.{16,})(?=.*[A-Za-z])(?=.*[0-9#^_+=/@.-])[A-Za-z0-9#^_+=/@.-]+")
DEFAULT_SECRET_VALUES = {
    "admin",
    "root",
    "password",
    "passwd",
    "1234",
    "12345",
    "123456",
    "12345678",
    "0000",
    "qwerty",
}


def check_scrt_001(observed: str):
    from ..base import judge

    return judge("ISTG-FW-SCRT-001", PHASE, observed, LOC)


def check_scrt_002(observed: str):
    from ..base import judge

    return judge("ISTG-FW-SCRT-002", PHASE, observed, LOC)


def check_scrt_003(observed: str):
    from ..base import judge

    return judge("ISTG-FW-SCRT-003", PHASE, observed, LOC)


def run(observed: str) -> list:
    evidence = collect_secret_evidence(observed)
    if not any(evidence.values()):
        return []

    checks = [
        ("public_storage", check_scrt_001),
        ("unencrypted_storage", check_scrt_002),
        ("hardcoded_secrets", check_scrt_003),
    ]

    findings = []
    for key, check in checks:
        if not evidence[key]:
            continue
        payload = json.dumps({key: evidence[key]}, ensure_ascii=False, indent=2)
        finding = check(payload)
        if finding:
            findings.append(finding)

    return findings


def collect_secret_evidence(observed: str) -> dict[str, list[dict[str, Any]]]:
    raw = _parse_observed(observed)
    evidence = {
        "public_storage": [],
        "unencrypted_storage": [],
        "hardcoded_secrets": [],
    }
    if raw is None:
        return evidence

    files = raw.get("files", [])
    if isinstance(files, list):
        for path_value in files:
            path = str(path_value)
            if _is_secret_path(path):
                item = _evidence("files", path, path, "Secret-like file path in extracted filesystem")
                evidence["unencrypted_storage"].append(item)
                if _is_public_path(path):
                    evidence["public_storage"].append(
                        _evidence("files", path, path, "Secret-like file is under a web/public path")
                    )

    configs = raw.get("configs", [])
    if isinstance(configs, list):
        for value in configs:
            for item in _scan_secret_value(str(value), "configs", "filesystem"):
                evidence["unencrypted_storage"].append(item)

    binaries = raw.get("binaries", [])
    if isinstance(binaries, list):
        for binary in binaries:
            if isinstance(binary, dict):
                _scan_binary(binary, evidence)

    return {key: _dedupe(items) for key, items in evidence.items()}


def _parse_observed(observed: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(observed)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _scan_binary(binary: dict[str, Any], evidence: dict[str, list[dict[str, Any]]]) -> None:
    path = str(binary.get("path", "<unknown>"))
    for field in ("strings", "imports", "dangerous_calls"):
        values = binary.get(field, [])
        if not isinstance(values, list):
            continue

        for value in values:
            text = str(value)
            matches = _scan_secret_value(text, field, path)
            evidence["hardcoded_secrets"].extend(matches)
            if field == "strings":
                evidence["unencrypted_storage"].extend(
                    item for item in matches if item["confidence_hint"] != "low"
                )


def _scan_secret_value(value: str, source_field: str, location: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if PRIVATE_KEY_RE.search(value):
        findings.append(
            _evidence(
                source_field,
                location,
                _redact_private_key(value),
                "Embedded private key material",
                "high",
            )
        )

    for match in SECRET_ASSIGNMENT_RE.finditer(value):
        key = match.group(1)
        secret = match.group(2)
        findings.append(
            _evidence(
                source_field,
                location,
                _redact_secret(value, secret),
                f"Literal value assigned to secret-like key '{key}'",
                _secret_confidence(secret),
            )
        )

    if _looks_like_passwd_entry(value):
        findings.append(_evidence(source_field, location, value, "Unix password database style entry", "medium"))

    if source_field in {"strings", "configs"}:
        token = value.strip()
        if _looks_like_bare_secret(token):
            findings.append(
                _evidence(
                    source_field,
                    location,
                    _redact_secret(token, token),
                    "High-entropy literal that may be a hardcoded secret or backdoor key",
                    "medium",
                )
            )

    return findings


def _is_secret_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(re.search(pattern, normalized) for pattern in SECRET_FILE_PATTERNS)


def _is_public_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(re.search(pattern, normalized) for pattern in PUBLIC_PATH_PATTERNS)


def _looks_like_passwd_entry(value: str) -> bool:
    parts = value.split(":")
    if len(parts) < 7:
        return False
    password_field = parts[1]
    return bool(password_field and password_field not in {"x", "*", "!"})


def _secret_confidence(secret: str) -> str:
    normalized = secret.strip().lower()
    if normalized in DEFAULT_SECRET_VALUES:
        return "high"
    if HASHED_PASSWORD_RE.search(normalized):
        return "medium"
    if len(secret) >= 16 and re.search(r"[A-Za-z]", secret) and re.search(r"\d|[+/=_-]", secret):
        return "high"
    return "medium"


def _looks_like_bare_secret(value: str) -> bool:
    if len(value) > 128 or "/" in value or "\\" in value or "://" in value:
        return False
    if SECRET_ASSIGNMENT_RE.search(value):
        return False
    if not HIGH_ENTROPY_TOKEN_RE.fullmatch(value):
        return False
    return _shannon_entropy(value) >= 3.2


def _shannon_entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact_secret(value: str, secret: str) -> str:
    if len(secret) <= 4:
        replacement = "<redacted>"
    else:
        replacement = f"{secret[:2]}...{secret[-2:]}"
    return value.replace(secret, replacement, 1)


def _redact_private_key(value: str) -> str:
    return re.sub(
        r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?-----END \1-----",
        r"-----BEGIN \1-----<redacted>-----END \1-----",
        value,
        flags=re.DOTALL,
    )


def _evidence(
    source_field: str,
    location: str,
    matched_value: str,
    reason: str,
    confidence_hint: str = "medium",
) -> dict[str, Any]:
    return {
        "location": location,
        "source_field": source_field,
        "matched_value": matched_value,
        "reason": reason,
        "confidence_hint": confidence_hint,
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for finding in findings:
        key = (
            finding["location"],
            finding["source_field"],
            finding["matched_value"],
            finding["reason"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped
