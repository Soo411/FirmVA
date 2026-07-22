# schemas.py
########################################################
# 에이전트들이 주고받는 데이터 형식을 정의

# 핵심 규칙:
#   모든 에이전트는 결과를 JSON(Pydantic 모델 -> dict)으로 생성
#   Orchestrator를 통해 다음 에이전트에게 전달

# 데이터 흐름(요약):
#  Analysis   -> ExtractResult      (extract.json)
#  Static     -> StaticRaw          (store 에 저장, 재사용)
#  Candidate  -> [Finding, ...]     (static_findings.json / dynamic_findings.json)
#  Surface    -> AttackSurface      (surface.json)
#  Dynamic    -> DynamicRaw         (dynamic_raw.json)
#  Report     -> report.txt
########################################################

from typing import List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class LLMVerdict(BaseModel):
    """OpenAI Structured Outputs로 받는 취약점 판정 형식."""

    verdict: Literal["vulnerable", "not_vulnerable"]
    severity: Literal["low", "medium", "high"]
    confidence: float
    evidence: str

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float) -> float:
        # OpenAI JSON Schema의 지원 범위와 무관하게 애플리케이션에서 강제한다.
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence는 0.0 이상 1.0 이하여야 합니다")
        return value


# 2번: Analysis Agent 출력
# binwalk 로 .bin 을 분해한 결과
class ExtractResult(BaseModel):
    firmware: str                                   # 원본 파일명
    arch: str = "unknown"                           # 예: ARM
    endian: str = "unknown"                         # 예: little
    bootloader: Optional[str] = None                # 추출된 부트로더 경로
    kernel: Optional[str] = None                    # 추출된 커널 경로
    rootfs: Optional[str] = None                    # 추출된 파일시스템 루트 경로
    signatures: List[str] = Field(default_factory=list)  # binwalk 시그니처 요약


# 3번: Static Analysis Agent 출력(공유 로우 데이터)
# 하나의 실행 바이너리(예: timepro.cgi)에 대한 정적 관찰 데이터
class BinaryInfo(BaseModel):
    path: str
    stripped: bool = True
    imports: List[str] = Field(default_factory=list)   # strcpy, system ...
    strings: List[str] = Field(default_factory=list)   # 의미있는 문자열 표본
    dangerous_calls: List[str] = Field(default_factory=list)  # 위험 함수 호출부

# Static Analysis Agent가 만든 관찰 데이터 전체.
# Orchestrator의 공유 저장소(store)에 저장되어 여러 에이전트가 재사용
class StaticRaw(BaseModel):
    binaries: List[BinaryInfo] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)     # 파일시스템 파일 목록
    configs: List[str] = Field(default_factory=list)   # 설정 파일 내용 표본
    services: List[str] = Field(default_factory=list)  # 실행 서비스 추정 목록


# 4번/6번: Candidate 하위 에이전트 출력
# 취약점 판정 결과 1건 (취약하지 않다고 본 것은 생성하지 않음)
class Finding(BaseModel):
    istg_id: str                        # 예: ISTG-FW-SCRT-003
    name: str                           # 예: Usage of Hardcoded Secrets
    phase: Literal["static", "dynamic"]
    verdict: Literal["vulnerable"] = "vulnerable"
    severity: Literal["low", "medium", "high"] = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: str = ""                  # 판정 근거(관찰된 데이터)
    location: str = ""                  # 어디서 발견했는지(파일/진입점)


# 4(2)번: Attack Surface Agent 출력
# 공격자가 접근할 수 있는 진입점 1개
class EntryPoint(BaseModel):
    
    ep_id: str                       # 예: ep1
    type: str                        # 예: http-cgi / service / uart
    target: str                      # 예: /nd-bin/netdetect.cgi
    param: Optional[str] = None      # 예: commit
    auth_required: bool = True       # 인증 필요 여부(무인증이 최우선)(조건 4-2)
    note: str = ""                   # 근거/메모(예: strcpy sink)

# 진입점 목록. auth_required=False인 항목이 앞쪽에 오도록 정렬해 전달
class AttackSurface(BaseModel):
    entrypoints: List[EntryPoint] = Field(default_factory=list)


# 5번: Dynamic Analysis Agent 출력
# 하나의 진입점을 QEMU 에서 실제로 찔러본 관찰 결과
class Observation(BaseModel):
    ep_id: str
    target: str
    reproduced: bool = False         # 실제 재현/동작했는지
    result: str = ""                 # 예: "SIGSEGV at 0x42424242"
    trace: str = ""                  # strace/ltrace/로그 표본
    input_privilege: Optional[
        Literal["unauthenticated", "low", "root"]
    ] = None                                 # 공격자의 초기 접근 수준
    exploit_succeeded: Optional[bool] = None  # 공격 자체의 성공 여부
    uid_before: Optional[int] = None          # 공격 전 세션/실행 컨텍스트 UID
    uid_after: Optional[int] = None           # 공격 후 프로세스/세션 UID
    root_shell_obtained: Optional[bool] = None  # root 셸 획득 여부

# Dynamic Analysis Agent 결과.
# observations만 Candidate 로 넘기고, new_entrypoints 는 넘기지 않고 따로 기록
class DynamicRaw(BaseModel):
    observations: List[Observation] = Field(default_factory=list)
    new_entrypoints: List[EntryPoint] = Field(default_factory=list)  # 향후 확장용 별도 기록
