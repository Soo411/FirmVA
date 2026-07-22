# llm.py: OpenAI API 호출
########################################################
# API 키는 config 를 통해 .env 에서만 읽어옴
# Candidate 하위 에이전트가 "이 관찰 데이터가 취약한가?" 를 판정할 때 이 함수를 사용함
# 판정은 OpenAI Structured Outputs와 Pydantic 모델로 검증
########################################################

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import ValidationError

from . import config
from .schemas import LLMVerdict
from test import demo   # 데모 판정은 test/demo.py 로 분리됨


class LLMConfigurationError(RuntimeError):
    """실제 OpenAI 모드에 필요한 설정이 없을 때 발생."""


class LLMCallError(RuntimeError):
    """OpenAI 호출 또는 구조화 응답 검증에 실패했을 때 발생."""


def ask_json(system: str, user: str) -> dict:
    """검증된 취약점 판정을 dict로 반환.

    데모 데이터는 DEMO_MODE=true일 때만 사용한다. 실제 모드의 설정 오류,
    API 오류, 거절, 응답 검증 실패를 ``not_vulnerable`` 판정으로 바꾸지 않는다.
    """
    if config.DEMO_MODE:
        return _validate_verdict(demo.llm_verdict(user)).model_dump()

    if not config.OPENAI_API_KEY:
        raise LLMConfigurationError(
            "DEMO_MODE=false에서는 OPENAI_API_KEY가 필요합니다."
        )

    llm = ChatOpenAI(
        model=config.OPENAI_MODEL,
        api_key=config.OPENAI_API_KEY,
        temperature=0,
        timeout=config.OPENAI_TIMEOUT_SECONDS,
        max_retries=config.OPENAI_MAX_RETRIES,
        max_completion_tokens=config.OPENAI_MAX_OUTPUT_TOKENS,
    )
    structured_llm = llm.with_structured_output(
        LLMVerdict,
        method="json_schema",
        strict=True,
    )

    try:
        result = structured_llm.invoke([
            SystemMessage(content=system),
            HumanMessage(content=user),
        ])
        return _validate_verdict(result).model_dump()
    except LLMCallError:
        raise
    except Exception as exc:
        raise LLMCallError(
            f"OpenAI 판정 호출에 실패했습니다 (model={config.OPENAI_MODEL}): {exc}"
        ) from exc


def _validate_verdict(value: object) -> LLMVerdict:
    if isinstance(value, LLMVerdict):
        return value
    try:
        return LLMVerdict.model_validate(value)
    except (ValidationError, TypeError) as exc:
        raise LLMCallError(f"OpenAI 판정 응답 형식이 올바르지 않습니다: {exc}") from exc
