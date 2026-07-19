# candidates/static/info.py: 정보 노출(Information Disclosure) 계열 (한 파일로 통합)
########################################################
# ISTG-FW-INFO-001  Disclosure of Source Code and Binaries
# ISTG-FW-INFO-002  Disclosure of Implementation Details
# ISTG-FW-INFO-003  Disclosure of Ecosystem Details

# 통합 이유:
# 세 항목 모두 정적 로우 데이터(문자열/파일 목록/바이너리)라는
# '같은 관찰 데이터'를 근거로 판정하므로, 하나의 파일에서 항목별 함수로 나눔

# 입력 : observed (StaticRaw를 JSON 문자열로 만든 관찰 데이터)
# 출력 : 취약으로 판정된 Finding 목록
########################################################

import json
import re
from dataclasses import asdict, dataclass
from typing import Optional
 
from ..base import judge
 
PHASE = "static"
LOC = "filesystem/binaries"
 
 
@dataclass
class Evidence:
    kind: str
    detail: str
    where: str
    why: str
    strength: str
 
 
def _parse(observed: str) -> Optional[dict]:
    try:
        data = json.loads(observed) if observed else None
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None
 
 

_SOURCE_EXTENSIONS = (".c", ".cpp", ".h", ".hpp", ".lua", ".php", ".py")
_VCS_MARKERS = (".git", ".svn")
 
 
def _find_source_disclosure(raw: dict) -> list[Evidence]:
    found: list[Evidence] = []
 
    for path in raw.get("files", []) or []:
        lower = str(path).lower()
        if lower.endswith(_SOURCE_EXTENSIONS):
            found.append(Evidence(
                kind="source_file", detail=path, where="files",
                why="소스코드 확장자를 가진 파일이 이미지 안에 그대로 포함되어 있음",
                strength="strong",
            ))
        elif any(marker in lower for marker in _VCS_MARKERS):
            found.append(Evidence(
                kind="vcs_metadata", detail=path, where="files",
                why="버전관리 메타데이터가 남아있어 저장소 구조/이력이 노출될 수 있음",
                strength="strong",
            ))
 
    for binary in raw.get("binaries", []) or []:
        path = binary.get("path", "<unknown>")
        if binary.get("stripped") is False:
            found.append(Evidence(
                kind="unstripped_symbols", detail=path, where="binaries.stripped",
                why="심볼 테이블이 제거되지 않아 함수명/변수명이 그대로 노출됨",
                strength="strong",
            ))
 
    return found
 
 

def _classify_debug_string(value: str) -> Optional[str]:
    if re.search(r"/home/|/usr/src/|/build/|[A-Za-z]:\\Users\\", value):
        return "빌드 환경의 절대경로가 노출되어 내부 개발 환경을 추정할 수 있음"
    if re.search(r"GCC:|Sourcery\s+G\+\+|clang version", value, re.IGNORECASE):
        return "컴파일러/툴체인 버전 문자열이 노출됨"
    if re.search(r"\[?DEBUG\]?:|\bTODO\b|\bFIXME\b|[A-Za-z_][\w]*\.c:\d+", value):
        return "디버그 로그 또는 소스 위치(파일:줄번호) 정보가 노출됨"
    return None
 
 
def _find_implementation_disclosure(raw: dict) -> list[Evidence]:
    found: list[Evidence] = []
 
    for binary in raw.get("binaries", []) or []:
        path = binary.get("path", "<unknown>")
        for value in binary.get("strings", []) or []:
            reason = _classify_debug_string(str(value))
            if reason:
                found.append(Evidence(
                    kind="implementation_string", detail=value,
                    where=f"binaries.strings:{path}", why=reason, strength="moderate",
                ))
 
    return found
 
 

_PUBLIC_DOMAINS = ("pool.ntp.org", "googleapis.com", "google.com", "apple.com")
 
 
def _classify_ecosystem_string(value: str) -> Optional[str]:
    if re.search(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b", value):
        return "사설 IP 대역이 노출되어 내부망 구조를 추정할 수 있음"
    if re.search(r"[\w.-]+\.(internal|corp|local)\b", value, re.IGNORECASE):
        return "내부 전용으로 보이는 호스트명이 노출됨"
    if re.search(r"https?://", value):
        return "백엔드/업데이트 서버로 추정되는 URL이 노출됨"
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", value):
        return "하드코딩된 이메일/연락처가 노출됨"
    return None
 
 
def _find_ecosystem_disclosure(raw: dict) -> list[Evidence]:
    found: list[Evidence] = []
    candidates: list[tuple[str, str]] = []
 
    for binary in raw.get("binaries", []) or []:
        path = binary.get("path", "<unknown>")
        for value in binary.get("strings", []) or []:
            candidates.append((str(value), f"binaries.strings:{path}"))
    for value in raw.get("configs", []) or []:
        candidates.append((str(value), "configs"))
 
    for value, where in candidates:
        if any(domain in value for domain in _PUBLIC_DOMAINS):
            continue
        reason = _classify_ecosystem_string(value)
        if reason:
            found.append(Evidence(kind="ecosystem_info", detail=value, where=where, why=reason, strength="moderate"))
 
    return found
 
 

def _judge_evidence(istg_id: str, evidence: list[Evidence]):
    if not evidence:
        return None
    payload = json.dumps({"evidence": [asdict(e) for e in evidence]}, ensure_ascii=False, indent=2)
    return judge(istg_id, PHASE, payload, LOC)
 
 
def check_info_001(observed: str):
    raw = _parse(observed)
    evidence = _find_source_disclosure(raw) if raw else []
    return _judge_evidence("ISTG-FW-INFO-001", evidence)
 
 
def check_info_002(observed: str):
    raw = _parse(observed)
    evidence = _find_implementation_disclosure(raw) if raw else []
    return _judge_evidence("ISTG-FW-INFO-002", evidence)
 
 
def check_info_003(observed: str):
    raw = _parse(observed)
    evidence = _find_ecosystem_disclosure(raw) if raw else []
    return _judge_evidence("ISTG-FW-INFO-003", evidence)
 
 

def run(observed: str) -> list:
    results = [
        check_info_001(observed),
        check_info_002(observed),
        check_info_003(observed),
    ]
    return [f for f in results if f]
