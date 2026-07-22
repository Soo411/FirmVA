from unittest.mock import patch

from src import llm
from src.schemas import LLMVerdict


class FakeStructuredLLM:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def invoke(self, messages):
        assert len(messages) == 2
        if self.error:
            raise self.error
        return self.result


class FakeChatOpenAI:
    structured = None
    init_kwargs = None

    def __init__(self, **kwargs):
        FakeChatOpenAI.init_kwargs = kwargs

    def with_structured_output(self, schema, *, method, strict):
        assert schema is LLMVerdict
        assert method == "json_schema"
        assert strict is True
        return FakeChatOpenAI.structured


def test_real_mode_requires_api_key():
    with patch.object(llm.config, "DEMO_MODE", False):
        with patch.object(llm.config, "OPENAI_API_KEY", ""):
            try:
                llm.ask_json("system", "user")
            except llm.LLMConfigurationError:
                pass
            else:
                raise AssertionError("LLMConfigurationError was not raised")


def test_structured_output_returns_validated_dict():
    FakeChatOpenAI.structured = FakeStructuredLLM(LLMVerdict(
        verdict="vulnerable",
        severity="high",
        confidence=0.9,
        evidence="observed strcpy sink",
    ))
    with patch.object(llm, "ChatOpenAI", FakeChatOpenAI):
        with patch.object(llm.config, "DEMO_MODE", False):
            with patch.object(llm.config, "OPENAI_API_KEY", "test-key"):
                result = llm.ask_json("system", "user")

    assert result["verdict"] == "vulnerable"
    assert result["confidence"] == 0.9
    assert FakeChatOpenAI.init_kwargs["max_retries"] == llm.config.OPENAI_MAX_RETRIES


def test_api_failure_is_not_converted_to_not_vulnerable():
    FakeChatOpenAI.structured = FakeStructuredLLM(error=RuntimeError("rate limited"))
    with patch.object(llm, "ChatOpenAI", FakeChatOpenAI):
        with patch.object(llm.config, "DEMO_MODE", False):
            with patch.object(llm.config, "OPENAI_API_KEY", "test-key"):
                try:
                    llm.ask_json("system", "user")
                except llm.LLMCallError as exc:
                    assert "rate limited" in str(exc)
                else:
                    raise AssertionError("LLMCallError was not raised")


def test_invalid_confidence_is_rejected():
    try:
        llm._validate_verdict({
            "verdict": "not_vulnerable",
            "severity": "low",
            "confidence": 1.5,
            "evidence": "none",
        })
    except llm.LLMCallError:
        pass
    else:
        raise AssertionError("LLMCallError was not raised")
