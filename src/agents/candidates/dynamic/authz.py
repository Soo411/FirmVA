# candidates/dynamic/authz.py: 인가(Authorization) 계열 한 파일로 통합
########################################################
# ISTG-FW[INST]-AUTHZ-001  Unauthorized Access to the Firmware
# ISTG-FW[INST]-AUTHZ-002  Privilege Escalation

# 통합 이유:
# 두 항목 모두 'QEMU 동적 실행 관찰 결과'라는 같은 데이터를 근거로,
#  무인증 접근이 성립했는지 / 그로 인해 권한 상승까지 갔는지만 달리 봄

# 입력 : observed (DynamicRaw.observations 를 JSON 문자열로 만든 관찰 데이터)
# 출력 : 취약 판정 Finding 목록
########################################################

# candidates/dynamic/authz.py
# ISTG-FW[INST]-AUTHZ-001  Unauthorized Access to the Firmware
# ISTG-FW[INST]-AUTHZ-002  Privilege Escalation

import json
import re
from typing import Any

PHASE = "dynamic"
LOC = "qemu-runtime"


# AUTHZ-001: 인증 없이 보호된 기능/데이터 접근이 실제 성공한 경우
_UNAUTHENTICATED_PATTERN = re.compile(
    r"\b(?:"
    r"unauthenticated|"
    r"without authentication|"
    r"no auth(?:entication)?|"
    r"auth(?:entication)? bypass(?:ed)?|"
    r"no session(?: cookie)?"
    r")\b",
    re.IGNORECASE,
)

_ACCESS_SUCCESS_PATTERN = re.compile(
    r"\b(?:"
    r"access granted|"
    r"request succeeded|"
    r"http\s*2\d\d|"
    r"status\s*[=:]\s*2\d\d|"
    r"returned (?:configuration|settings|data)|"
    r"privileged (?:page|function|operation)|"
    r"command executed"
    r")\b",
    re.IGNORECASE,
)

# AUTHZ-002: 실제 root 권한/셸/명령 실행이 성공한 경우만 인정
# 단순 SIGSEGV, PC overwrite 등은 권한 상승 성공으로 보지 않는다.
_ROOT_OBTAINED_PATTERN = re.compile(
    r"\b(?:"
    r"uid\s*[=:]\s*0(?:\s*\([^)]*root[^)]*\))?|"
    r"euid\s*[=:]\s*0|"
    r"gid\s*[=:]\s*0|"
    r"root shell|"
    r"shell obtained as root|"
    r"root command (?:executed|succeeded)|"
    r"privilege escalation succeeded"
    r")\b",
    re.IGNORECASE,
)


def check_authz_001(observed: str):
    """무인증 접근 성공 증거로 AUTHZ-001을 판정한다."""
    from ..base import judge
    return judge("ISTG-FW[INST]-AUTHZ-001", PHASE, observed, LOC)


def check_authz_002(observed: str):
    """root 권한 획득 성공 증거로 AUTHZ-002를 판정한다."""
    from ..base import judge
    return judge("ISTG-FW[INST]-AUTHZ-002", PHASE, observed, LOC)


def run(observed: str) -> list:
    """관찰 데이터를 AUTHZ-001/002 증거로 분리해 각각 판정한다."""
    evidence = collect_authz_evidence(observed)
    results = []

    if evidence["unauthorized_access"]:
        authz_001_observed = json.dumps(
            {"unauthorized_access": evidence["unauthorized_access"]},
            ensure_ascii=False,
            indent=2,
        )
        results.append(check_authz_001(authz_001_observed))

    if evidence["privilege_escalation"]:
        authz_002_observed = json.dumps(
            {"privilege_escalation": evidence["privilege_escalation"]},
            ensure_ascii=False,
            indent=2,
        )
        results.append(check_authz_002(authz_002_observed))

    return [finding for finding in results if finding]


def collect_authz_evidence(observed: str) -> dict[str, list[dict[str, Any]]]:
    """
    DynamicRaw.observations JSON에서 인가 취약점 증거를 추출한다.

    AUTHZ-001:
      - 무인증/인증 우회 증거
      - 실제 접근 성공 증거
      두 조건이 모두 있어야 한다.

    AUTHZ-002:
      - uid=0, root shell, root 명령 성공 등
      - 실제 root 권한 획득 증거가 있어야 한다.
    """
    evidence: dict[str, list[dict[str, Any]]] = {
        "unauthorized_access": [],
        "privilege_escalation": [],
    }

    for observation in _parse_observations(observed):
        if not observation.get("reproduced", False):
            continue

        result = str(observation.get("result", ""))
        trace = str(observation.get("trace", ""))
        text = f"{result}\n{trace}"

        item = {
            "ep_id": str(observation.get("ep_id", "<unknown>")),
            "target": str(observation.get("target", "<unknown>")),
            "result": result,
            "trace": trace,
        }

        # 인증 없는 요청이 실제로 보호 기능/데이터 접근에 성공했는지
        if (
            _UNAUTHENTICATED_PATTERN.search(text)
            and _ACCESS_SUCCESS_PATTERN.search(text)
        ):
            evidence["unauthorized_access"].append(item)

        # 단순 크래시는 제외하고 root 획득 성공만 권한 상승으로 인정
        if _ROOT_OBTAINED_PATTERN.search(text):
            evidence["privilege_escalation"].append(item)

    return evidence


def _parse_observations(observed: str) -> list[dict[str, Any]]:
    """Candidate 호출부가 전달한 observations JSON 배열을 안전하게 읽는다."""
    try:
        parsed = json.loads(observed)
    except (TypeError, json.JSONDecodeError):
        return []

    if not isinstance(parsed, list):
        return []

    return [item for item in parsed if isinstance(item, dict)]