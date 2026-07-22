# config.py: 프로젝트 전체 설정을 관리합니다.
########################################################
# 민감 정보는 코드에 직접 쓰지 않고 .env 파일에서 가져옵니다.
########################################################

import os
from pathlib import Path
from dotenv import load_dotenv

# .env 파일을 읽어 환경변수로 로드
load_dotenv()

# 경로 설정 
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
INPUT_DIR = DATA / "input"      # 업로드된 .bin 원본
WORK_DIR = DATA / "work"        # binwalk 추출물(부트로더/커널/파일시스템)
STORAGE_DIR = DATA / "storage"  # 공유 저장소(로우 데이터 json 등)
OUT_DIR = ROOT / "out"          # 최종 보고서(.txt)

for _d in (INPUT_DIR, WORK_DIR, STORAGE_DIR, OUT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# LLM API 설정
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_TIMEOUT_SECONDS = float(os.getenv("OPENAI_TIMEOUT_SECONDS", "60"))
OPENAI_MAX_RETRIES = int(os.getenv("OPENAI_MAX_RETRIES", "2"))
OPENAI_MAX_OUTPUT_TOKENS = int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "512"))

BINWALK_SCAN_TIMEOUT_SECONDS = float(os.getenv("BINWALK_SCAN_TIMEOUT_SECONDS", "120"))
BINWALK_EXTRACT_TIMEOUT_SECONDS = float(os.getenv("BINWALK_EXTRACT_TIMEOUT_SECONDS", "1800"))

# 도구 및 MCP 설정
# Ghidra 공개 MCP를 사용합니다.
GHIDRA_MCP_URL = os.getenv("GHIDRA_MCP_URL", "http://127.0.0.1:8081/sse")
# Ghidra CodeBrowser에 현재 열어 둔 바이너리의 rootfs 내부 경로(선택)
GHIDRA_BINARY_PATH = os.getenv("GHIDRA_BINARY_PATH", "")
# QEMU MCP Server를 사용합니다.
QEMU_MCP_URL = os.getenv("QEMU_MCP_URL", "http://127.0.0.1:8090/sse")

# 타겟 펌웨어 기본값
TARGET_NAME = os.getenv("TARGET_NAME", "iptime_G104_v7.60")

# Demo Mode 실행 시 true, 실제 LLM API 사용 시 false
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

# QEMU 구현/연결 전 정적 파이프라인만 독립적으로 실행할 때 false
ENABLE_DYNAMIC_ANALYSIS = os.getenv("ENABLE_DYNAMIC_ANALYSIS", "true").lower() == "true"


class ConfigurationError(RuntimeError):
    """실제 실행에 필요한 환경 설정이 올바르지 않을 때 발생."""


def validate_runtime() -> None:
    if not DEMO_MODE and not OPENAI_API_KEY:
        raise ConfigurationError(
            "DEMO_MODE=false에서는 OPENAI_API_KEY를 설정해야 합니다."
        )
