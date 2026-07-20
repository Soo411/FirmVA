# candidates/static/conf.py: 소프트웨어 구성(Configuration/Composition) 계열 (한 파일 통합)
########################################################
# ISTG-FW-CONF-001  Usage of Outdated Software
# ISTG-FW-CONF-002  Presence of Unnecessary Software and Functionalities

# 통합 이유:
# 두 항목 모두 '설치된 구성요소/서비스 목록과 버전 문자열'이라는
# 같은 관찰 데이터를 근거로 판정합니다.

# 입력 : observed (StaticRaw JSON)
# 출력 : 취약 판정 Finding 목록
########################################################

import json
import re
from typing import Any

from ..base import judge


PHASE = "static"

# AI 판정의 확신도가 이 값보다 낮으면 보고서에서 제외한다.
# 값을 높이면 오탐은 줄지만, 실제 취약점을 놓칠 가능성은 커진다.
MIN_CONFIDENCE = 0.75


# 프로젝트 내부의 보수적 "구버전" 기준.
# 실제 서비스에서는 CVE/EOL 데이터베이스와 연동해 갱신해야 한다.
OUTDATED_VERSION_POLICY = {
    "busybox": (1, 30, 0),
    "openssl": (1, 1, 1),
    "dropbear": (2020, 81),
}


# 빌드 흔적일 뿐, 단독으로 실제 취약점 근거가 될 수 없는 문자열
REVIEW_ONLY_KEYWORDS = (
    "gcc",
    "sourcery",
    "toolchain",
    "compiler",
    "buildroot",
)


# 외부 노출 시 위험할 수 있는 서비스.
# FTP/SSH/UPnP 등은 환경에 따라 정상 기능일 수 있으므로 자동 확정에서 제외했다.
HIGH_RISK_SERVICES = (
    "telnetd",
    "telnet",
    "rshd",
    "rlogin",
    "rexecd",
    "tftpd",
    "tftp",
)


# 서비스가 실제로 활성화된 정황
ENABLED_MARKERS = (
    "=1",
    "=true",
    "enabled",
    "enable",
    "start",
    "running",
    "rcs",
)


# 서비스가 외부에서 접근 가능할 수 있는 정황
EXPOSURE_MARKERS = (
    "0.0.0.0",
    "listen",
    "inetd",
    "wan",
    "internet",
    "external",
    "port",
)


def _safe_load(observed: str) -> dict[str, Any]:
    """StaticRaw JSON을 안전하게 읽는다."""
    try:
        data = json.loads(observed)
    except (json.JSONDecodeError, TypeError):
        return {}

    return data if isinstance(data, dict) else {}


def _version_tuple(text: str) -> tuple[int, ...] | None:
    """'v1.2.3' 또는 '1.2.3'을 (1, 2, 3)으로 바꾼다."""
    match = re.search(r"\b(?:v(?:ersion)?\s*)?(\d+(?:\.\d+){1,3})\b", text, re.I)

    if match is None:
        return None

    return tuple(int(part) for part in match.group(1).split("."))


def _is_lower_version(found: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    """1.2와 1.2.0처럼 자릿수가 다른 버전도 비교한다."""
    length = max(len(found), len(minimum))

    found_padded = found + (0,) * (length - len(found))
    minimum_padded = minimum + (0,) * (length - len(minimum))

    return found_padded < minimum_padded


def _has_marker(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _format_evidence(items: list[dict[str, str]]) -> str:
    """LLM과 최종 보고서에 전달할 근거 문자열을 만든다."""
    return "\n\n".join(
        (
            f"[source: {item['location']}]\n"
            f"[reason: {item['reason']}]\n"
            f"[value: {item['value']}]"
        )
        for item in items
    )


def _find_outdated_software(data: dict[str, Any]) -> list[dict[str, str]]:
    """
    CONF-001 근거를 찾는다.

    조건:
    - 실행 바이너리 문자열에 소프트웨어 이름이 있어야 함
    - 실제 버전이 있어야 함
    - 프로젝트의 구버전 기준보다 낮아야 함
    - GCC/Sourcery 같은 빌드 도구 흔적만 있으면 제외
    """
    evidence = []

    for binary in data.get("binaries", []):
        if not isinstance(binary, dict):
            continue

        binary_path = str(binary.get("path", "unknown binary"))
        strings = binary.get("strings", [])

        if not isinstance(strings, list):
            continue

        for value in strings:
            if not isinstance(value, str):
                continue

            lowered = value.lower()

            if _has_marker(lowered, REVIEW_ONLY_KEYWORDS):
                continue

            for component, minimum_version in OUTDATED_VERSION_POLICY.items():
                if component not in lowered:
                    continue

                found_version = _version_tuple(value)

                # 이름만 있고 버전이 없으면 취약점으로 확정하지 않는다.
                if found_version is None:
                    continue

                if _is_lower_version(found_version, minimum_version):
                    evidence.append(
                        {
                            "location": binary_path,
                            "reason": (
                                f"{component} {'.'.join(map(str, found_version))} "
                                f"is below policy minimum "
                                f"{'.'.join(map(str, minimum_version))}"
                            ),
                            "value": value,
                        }
                    )

    return evidence


def _find_risky_enabled_services(data: dict[str, Any]) -> list[dict[str, str]]:
    """
    CONF-002 근거를 찾는다.

    고위험 서비스 이름뿐 아니라, 같은 서비스가 활성화됐고 외부 노출될 수 있다는
    설정 근거가 함께 있어야 한다.
    """
    evidence = []

    services = data.get("services", [])
    configs = data.get("configs", [])

    if not isinstance(services, list):
        services = []

    if not isinstance(configs, list):
        configs = []

    config_lines = [line for line in configs if isinstance(line, str)]

    for service in services:
        if not isinstance(service, str):
            continue

        service_lower = service.lower()

        matched_service = next(
            (
                name
                for name in HIGH_RISK_SERVICES
                if name in service_lower
            ),
            None,
        )

        if matched_service is None:
            continue

        # 해당 서비스 이름이 포함된 설정 줄만 사용한다.
        related_configs = [
            line
            for line in config_lines
            if matched_service in line.lower()
        ]

        context = "\n".join([service, *related_configs])

        enabled = _has_marker(context, ENABLED_MARKERS)
        exposed = _has_marker(context, EXPOSURE_MARKERS)

        # 서비스 이름만 있거나, 활성/노출 근거가 하나라도 없으면 제외한다.
        if not (enabled and exposed):
            continue

        evidence.append(
            {
                "location": f"service:{service}",
                "reason": (
                    f"High-risk service '{matched_service}' has both enabled "
                    "and exposure-related configuration evidence"
                ),
                "value": context,
            }
        )

    return evidence


def _finalize_finding(finding, evidence_items: list[dict[str, str]]):
    """
    AI 판정 뒤에도 근거와 신뢰도 기준을 다시 확인한다.
    통과한 결과에는 정적 분석 원본 근거를 붙인다.
    """
    if finding is None or not evidence_items:
        return None

    try:
        confidence = float(finding.confidence)
    except (TypeError, ValueError):
        return None

    if confidence < MIN_CONFIDENCE:
        return None

    evidence_text = _format_evidence(evidence_items)
    locations = sorted({item["location"] for item in evidence_items})

    finding.evidence = (
        f"Static evidence:\n{evidence_text}\n\n"
        f"LLM assessment:\n{finding.evidence}"
    )
    finding.location = ", ".join(locations)

    return finding


def check_conf_001(observed: str):
    """ISTG-FW-CONF-001: 오래된 소프트웨어 사용 여부."""
    data = _safe_load(observed)
    evidence_items = _find_outdated_software(data)

    # 명확한 버전 근거가 없다면 AI 판정도 요청하지 않는다.
    if not evidence_items:
        return None

    evidence_text = _format_evidence(evidence_items)
    locations = ", ".join(sorted({item["location"] for item in evidence_items}))

    finding = judge(
        "ISTG-FW-CONF-001",
        PHASE,
        evidence_text,
        locations,
    )

    return _finalize_finding(finding, evidence_items)


def check_conf_002(observed: str):
    """ISTG-FW-CONF-002: 불필요하거나 위험한 기능 존재 여부."""
    data = _safe_load(observed)
    evidence_items = _find_risky_enabled_services(data)

    # remote_support=1 같은 단순 키워드만으로는 확정 취약점 처리하지 않는다.
    if not evidence_items:
        return None

    evidence_text = _format_evidence(evidence_items)
    locations = ", ".join(sorted({item["location"] for item in evidence_items}))

    finding = judge(
        "ISTG-FW-CONF-002",
        PHASE,
        evidence_text,
        locations,
    )

    return _finalize_finding(finding, evidence_items)


def run(observed: str) -> list:
    """CONF-001, CONF-002를 검사하고 모든 기준을 통과한 결과만 반환한다."""
    results = [
        check_conf_001(observed),
        check_conf_002(observed),
    ]

    return [finding for finding in results if finding is not None]