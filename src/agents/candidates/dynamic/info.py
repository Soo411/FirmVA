# candidates/dynamic/info.py: 사용자 데이터 노출 (단독 항목)
########################################################
# ISTG-FW[INST]-INFO-001  Disclosure of User Data

# 이 계열은 항목이 1개뿐이라 파일 하나가 곧 하위 에이전트 하나임
# 정적 info.py 와 이름은 같지만, 서로 다른 폴더(static/ vs dynamic/)라 충돌 X

# 입력 : observed (DynamicRaw.observations JSON)
# 출력 : 취약 판정 Finding 목록

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Optional
 
from ..base import judge
 
PHASE = "dynamic"
LOC = "qemu-runtime"
 
 
@dataclass
class Evidence:
    kind: str
    channel: str
    detail: str 
    where: list[str] = field(default_factory=list)  
    why: str = ""     
    strength: str = "moderate" 
    occurrences: int = 1  
 
def _parse_observations(observed: str) -> list[dict]:
    """observed 는 Observation 딕셔너리의 '배열' 문자열이다 (DynamicRaw 래핑 없음)."""
    try:
        data = json.loads(observed) if observed else None
    except (json.JSONDecodeError, TypeError):
        return []
    return data if isinstance(data, list) else []
 
 
def _mask(value: str) -> str:
    """민감값을 부분 마스킹한다 (패턴 인식은 가능하되 원문은 복원 불가하게)."""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
 
 
def _redact_window(text: str, match: re.Match, radius: int = 40) -> str:
    """매치 주변 텍스트를 잘라내되, 민감값 그룹(value)이 있으면 마스킹해서 넣는다."""
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    window = text[start:end]
 
    groups = match.groupdict()
    sensitive = groups.get("value") or match.group(0)
    if sensitive and sensitive in window:
        window = window.replace(sensitive, _mask(sensitive), 1)
 
    return f"{prefix}{window}{suffix}"
 
 
def _raw_value(match: re.Match) -> str:
    """비교/집계용 원본 민감값(마스킹 전). Evidence에는 절대 이 값을 그대로 넣지 않는다."""
    groups = match.groupdict()
    return groups.get("value") or match.group(0)
 
 

_RESPONSE_RULES = [
    ("account_dump", r"(?:username|account|user_id|계정)\s*[:=]\s*(?P<value>[^\s,;\"']{2,})",
     "응답에 계정/사용자 식별 정보가 그대로 노출됨", "strong"),
    ("personal_info", r"(?P<value>[\w.+-]+@[\w-]+\.[\w.-]+|01[0-9][-.\s]?\d{3,4}[-.\s]?\d{4})",
     "응답에 이메일/전화번호 등 개인정보로 보이는 값이 노출됨", "strong"),
    ("credential_in_response", r"(?:password|passwd|pwd)\s*[:=]\s*(?P<value>[^\s,;\"']{3,})",
     "응답 본문에 비밀번호 값이 그대로 노출됨", "moderate"),
]
 

_PROCESS_RULES = [
    ("secret_via_cmdline_or_env", r"(?:execve\(|environ\[|getenv\()[^\n]*"
     r"(?:password|passwd|token|secret|api[_-]?key)\s*=\s*(?P<value>[^\s,;\"')]{3,})",
     "비밀번호/토큰이 커맨드라인 인자 또는 환경변수로 전달되어, "
     "syscall 트레이스만으로도 관찰 가능한 채널에 노출됨", "strong"),
    ("secret_value_in_syscall", r"(?:password|passwd|token|secret)\s*[:=]\s*(?P<value>[^\s,;\"')]{3,})",
     "syscall 트레이스 안에 자격증명으로 보이는 값이 그대로 노출됨", "strong"),
]
 
 
def _scan_first_match(text: str, rules: list[tuple]) -> Optional[tuple[str, str, str, str, str]]:
    """규칙을 우선순위 순서(구체적인 것 먼저)로 검사해서 첫 매치 하나만 채택한다.
    반환: (kind, redacted_detail, raw_value, why, base_strength) 또는 None."""
    for kind, pattern, why, strength in rules:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return kind, _redact_window(text, m), _raw_value(m), why, strength
    return None
 
 
def _collect_raw_hits(observations: list[dict]) -> list[dict]:
    """observation 하나하나에서 (ep_id, kind, channel, redacted, raw_value, why, strength) 를 뽑는다."""
    hits: list[dict] = []
 
    for obs in observations:
        if not obs.get("reproduced"):
            continue
 
        ep_id = str(obs.get("ep_id", "<unknown>"))
 
        result_text = str(obs.get("result", "") or "")
        hit = _scan_first_match(result_text, _RESPONSE_RULES)
        if hit:
            kind, redacted, raw, why, strength = hit
            hits.append({"ep_id": ep_id, "channel": "response", "kind": kind,
                          "detail": redacted, "raw": raw, "why": why, "strength": strength})
 
        trace_text = str(obs.get("trace", "") or "")
        hit = _scan_first_match(trace_text, _PROCESS_RULES)
        if hit:
            kind, redacted, raw, why, strength = hit
            hits.append({"ep_id": ep_id, "channel": "process", "kind": kind,
                          "detail": redacted, "raw": raw, "why": why, "strength": strength})
 
    return hits
 
 
def _find_user_data_disclosure(observations: list[dict]) -> list[Evidence]:
    hits = _collect_raw_hits(observations)
    if not hits:
        return []

    
    grouped: dict[tuple[str, str], list[dict]] = {}
    for h in hits:
        grouped.setdefault((h["ep_id"], h["kind"]), []).append(h)
 

    value_to_eps: dict[str, set[str]] = {}
    for h in hits:
        value_to_eps.setdefault(h["raw"], set()).add(h["ep_id"])
 
    evidence: list[Evidence] = []
    for (ep_id, kind), items in grouped.items():
        first = items[0]
        strength = first["strength"]
        occurrences = len(items)
        why = first["why"]
 
        if occurrences >= 2:
            strength = "strong"
 
        distinct_eps_with_same_value = value_to_eps.get(first["raw"], {ep_id})
        if len(distinct_eps_with_same_value) >= 2:
            strength = "weak"
            why += " (단, 서로 다른 엔드포인트에서 동일한 값이 반복 관찰되어 " \
                   "사용자별 데이터가 아니라 고정 문자열일 가능성도 있음)"
 
        evidence.append(Evidence(
            kind=kind, channel=first["channel"], detail=first["detail"],
            where=[ep_id], why=why, strength=strength, occurrences=occurrences,
        ))
 
    return evidence
 
 

def check_info_001(observed: str):
    observations = _parse_observations(observed)
    evidence = _find_user_data_disclosure(observations)
    if not evidence:
        return None
 
    payload = json.dumps({"evidence": [asdict(e) for e in evidence]}, ensure_ascii=False, indent=2)
    finding = judge("ISTG-FW[INST]-INFO-001", PHASE, payload, LOC)
    return _finalize(finding, evidence)
 
 
def _finalize(finding, evidence: list[Evidence]):
    """LLM이 vulnerable로 판정하면, location을 실제 증거가 나온 ep_id들로 덮어쓴다."""
    if finding is None:
        return None
 
    eps = sorted({ep for e in evidence for ep in e.where})
    if eps:
        finding.location = ", ".join(eps)
 
    return finding
 
 
def run(observed: str) -> list:
    f = check_info_001(observed)
    return [f] if f else []
