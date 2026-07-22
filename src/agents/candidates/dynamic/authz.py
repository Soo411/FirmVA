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

# HTTP 2xx 자체는 로그인/오류 페이지일 수 있으므로, 보호된 기능이나 데이터가
# 실제로 반환 또는 실행됐다는 증거를 별도로 요구한다.
_PROTECTED_RESOURCE_PATTERN = re.compile(
    r"\b(?:"
    r"returned (?:configuration|settings|data)|"
    r"(?:privileged|protected|admin) "
    r"(?:page|function|operation|configuration|settings|data)|"
    r"sensitive data returned|"
    r"firmware (?:download|read) succeeded"
    r")\b",
    re.IGNORECASE,
)

# AUTHZ-002: 실제 root 권한/셸/명령 실행이 성공한 경우만 인정
# 단순 SIGSEGV, PC overwrite 등은 권한 상승 성공으로 보지 않는다.
_ROOT_OBTAINED_PATTERN = re.compile(
    r"\b(?:"
    r"uid\s*[=:]\s*0(?:\s*\([^)]*root[^)]*\))?|"
    r"euid\s*[=:]\s*0|"
    r"root shell|"
    r"shell obtained as root|"
    r"root command (?:executed|succeeded)"
    r")\b",
    re.IGNORECASE,
)

_ESCALATION_SUCCESS_PATTERN = re.compile(
    r"\b(?:"
    r"command injection succeeded|"
    r"exploit(?:ation)? succeeded|"
    r"privilege escalation succeeded|"
    r"shell obtained as root|"
    r"root command (?:executed|succeeded)"
    r")\b",
    re.IGNORECASE,
)

_LOW_PRIVILEGE_ORIGIN_PATTERN = re.compile(
    r"\b(?:"
    r"(?:initial|original|before|pre-exploit)\s+e?uid\s*[=:]\s*(?!0\b)\d+|"
    r"e?uid\s+before\s*[=:]\s*(?!0\b)\d+|"
    r"low[- ]privileged (?:user|process|session|input)|"
    r"unprivileged (?:user|process|session|input)|"
    r"unauthenticated (?:request|input|session|user)"
    r")\b",
    re.IGNORECASE,
)

# 자유 텍스트에 성공 키워드가 들어 있어도 부정되거나 실패한 문맥이면 증거가 아니다.
_NEGATION_BEFORE_PATTERN = re.compile(
    r"(?:\bno\b|\bnot\b|\bwithout\b|\bfailed\s+to\b|"
    r"\bunable\s+to\b|\bdid\s+not\b)[^.\n;]{0,32}$",
    re.IGNORECASE,
)
_NEGATION_AFTER_PATTERN = re.compile(
    r"^[^.\n;]{0,32}\b(?:failed|denied|was\s+not|not\s+obtained|"
    r"not\s+granted|not\s+executed|not\s+succeeded)\b",
    re.IGNORECASE,
)


def check_authz_001(observed: str, location: str = LOC):
    """무인증 접근 성공 증거로 AUTHZ-001을 판정한다."""
    from ..base import judge
    return judge("ISTG-FW[INST]-AUTHZ-001", PHASE, observed, location)


def check_authz_002(observed: str, location: str = LOC):
    """root 권한 획득 성공 증거로 AUTHZ-002를 판정한다."""
    from ..base import judge
    return judge("ISTG-FW[INST]-AUTHZ-002", PHASE, observed, location)


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
        results.append(
            check_authz_001(
                authz_001_observed,
                _evidence_location(evidence["unauthorized_access"]),
            )
        )

    if evidence["privilege_escalation"]:
        authz_002_observed = json.dumps(
            {"privilege_escalation": evidence["privilege_escalation"]},
            ensure_ascii=False,
            indent=2,
        )
        results.append(
            check_authz_002(
                authz_002_observed,
                _evidence_location(evidence["privilege_escalation"]),
            )
        )

    return [finding for finding in results if finding]


def collect_authz_evidence(observed: str) -> dict[str, list[dict[str, Any]]]:
    """
    DynamicRaw.observations JSON에서 인가 취약점 증거를 추출한다.

    AUTHZ-001:
      - 무인증/인증 우회 증거
      - 실제 접근 성공 증거
      두 조건이 모두 있어야 한다.

    AUTHZ-002:
      - 공격 전 낮은 권한 또는 무인증 상태
      - 공격 성공
      - 공격 후 uid=0/euid=0 또는 root shell 획득
      세 조건이 모두 있어야 한다.
    """
    evidence: dict[str, list[dict[str, Any]]] = {
        "unauthorized_access": [],
        "privilege_escalation": [],
    }

    for observation in _parse_observations(observed):
        if observation.get("reproduced") is not True:
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
        for field in (
            "input_privilege",
            "exploit_succeeded",
            "uid_before",
            "uid_after",
            "root_shell_obtained",
        ):
            if field in observation:
                item[field] = observation[field]

        # 인증 없는 요청이 실제로 보호 기능/데이터 접근에 성공했는지
        if (
            _has_positive_match(_UNAUTHENTICATED_PATTERN, text)
            and _has_positive_match(_ACCESS_SUCCESS_PATTERN, text)
            and _has_positive_match(_PROTECTED_RESOURCE_PATTERN, text)
        ):
            evidence["unauthorized_access"].append(item)

        # 낮은 권한에서 시작해 공격에 성공하고 root를 획득한 경우만 인정한다.
        if (
            _has_low_privilege_origin(observation, text)
            and _has_exploit_success(observation, text)
            and _has_root_outcome(observation, text)
        ):
            evidence["privilege_escalation"].append(item)

    return evidence


def _has_positive_match(pattern: re.Pattern[str], text: str) -> bool:
    """부정 또는 실패 문맥에 포함되지 않은 정규식 매치가 있는지 확인한다."""
    for match in pattern.finditer(text):
        before = text[max(0, match.start() - 48):match.start()]
        after = text[match.end():match.end() + 48]
        if _NEGATION_BEFORE_PATTERN.search(before):
            continue
        if _NEGATION_AFTER_PATTERN.search(after):
            continue
        return True
    return False


def _has_low_privilege_origin(observation: dict[str, Any], text: str) -> bool:
    """공격자의 초기 접근 수준 또는 공격 전 UID가 저권한인지 확인한다."""
    input_privilege = observation.get("input_privilege")
    if input_privilege in {"unauthenticated", "low"}:
        return True
    if input_privilege == "root":
        return False

    uid_before = observation.get("uid_before")
    if type(uid_before) is int:
        return uid_before != 0
    return _has_positive_match(_LOW_PRIVILEGE_ORIGIN_PATTERN, text)


def _has_exploit_success(observation: dict[str, Any], text: str) -> bool:
    """구조화된 공격 결과를 우선하고, 없을 때만 텍스트 증거를 사용한다."""
    exploit_succeeded = observation.get("exploit_succeeded")
    if type(exploit_succeeded) is bool:
        return exploit_succeeded
    return _has_positive_match(_ESCALATION_SUCCESS_PATTERN, text)


def _has_root_outcome(observation: dict[str, Any], text: str) -> bool:
    """공격 후 UID 또는 root 셸 결과가 명시되면 텍스트보다 우선한다."""
    uid_after = observation.get("uid_after")
    root_shell_obtained = observation.get("root_shell_obtained")
    has_structured_outcome = (
        type(uid_after) is int or type(root_shell_obtained) is bool
    )
    if has_structured_outcome:
        return uid_after == 0 or root_shell_obtained is True
    return _has_positive_match(_ROOT_OBTAINED_PATTERN, text)


def _evidence_location(items: list[dict[str, Any]]) -> str:
    """최종 Finding에서 재현 지점을 확인할 수 있도록 진입점을 요약한다."""
    locations = {
        f"{item.get('ep_id', '<unknown>')}: {item.get('target', '<unknown>')}"
        for item in items
    }
    return ", ".join(sorted(locations)) or LOC


def _parse_observations(observed: str) -> list[dict[str, Any]]:
    """Candidate 호출부가 전달한 observations JSON 배열을 안전하게 읽는다."""
    try:
        parsed = json.loads(observed)
    except (TypeError, json.JSONDecodeError):
        return []

    if not isinstance(parsed, list):
        return []

    return [item for item in parsed if isinstance(item, dict)]
