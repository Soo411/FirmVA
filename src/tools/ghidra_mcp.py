# ghidra_mcp.py: Ghidra를 사용해 정적 분석을 수행
########################################################
# Ghidra는 공개된 MCP 서버 존재
# LaurieWired/GhidraMCP  (https://github.com/LaurieWired/GhidraMCP)
# 따라서 공개 MCP 를 그대로 사용

# 이 모듈은 위 MCP 서버에 붙어서 list_imports / list_methods / list_strings
# 도구를 호출하고, 그 결과를 우리 형식(StaticRaw)에 맞게 정리해 돌려줍니다.

# 블랙박스 원칙에 따라 원본 소스코드 없이, Ghidra가 관찰한
# 문자열/임포트/함수 목록만으로 로우 데이터를 생성

# 사용 방법(요약):
#    1) Ghidra 실행 -> 대상 바이너리 import 후 GhidraMCP 플러그인 활성화
#    2) 별도 터미널에서:
#       python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
#    3) .env 의 GHIDRA_MCP_URL 을 위 주소로 맞춤
#
# 공개 GhidraMCP는 프로그램 import/전환 도구를 제공하지 않으므로 현재
# CodeBrowser에 열린 프로그램을 분석하며, GHIDRA_BINARY_PATH로 경로를 기록합니다.
########################################################

from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

from langchain_mcp_adapters.client import MultiServerMCPClient

from .. import config
from test import demo   # 데모 정적 데이터는 test/demo.py 로 분리됨


class GhidraMCPError(RuntimeError):
    """실제 Ghidra 관찰 데이터를 수집하지 못했을 때 발생."""


_PAGE_LIMIT = 1_000
_MAX_PAGES = 20
_MAX_FILES = 20_000
_MAX_CONFIG_FILES = 200
_MAX_CONFIG_BYTES = 128 * 1024
_MAX_CONFIG_CHARS = 4_000

_CONFIG_SUFFIXES = {
    ".cfg", ".conf", ".config", ".ini", ".json", ".properties", ".xml",
    ".yaml", ".yml",
}
_DANGEROUS_SYMBOLS = {
    "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
    "gets", "memcpy", "popen", "scanf", "sprintf", "strcat", "strcpy",
    "strncat", "strncpy", "system", "vfork", "vsprintf",
}
_ERROR_PREFIXES = ("error:", "request failed:")
_HTTP_ERROR_PATTERN = re.compile(r"^error\s+\d{3}:", re.IGNORECASE)


def analyze(rootfs: str) -> dict:
    """현재 Ghidra에 열린 프로그램의 정적 관찰 데이터를 수집.

    데모 모드는 명시적으로 유지한다. 실제 모드의 연결/도구 오류는 데모로
    대체하지 않고 전달해 실제 펌웨어 분석과 데모가 섞이지 않게 한다.
    """
    if config.DEMO_MODE:
        return demo.static_raw(rootfs)

    root = Path(rootfs).expanduser()
    if not rootfs or not root.exists():
        raise GhidraMCPError(f"rootfs 경로를 찾을 수 없습니다: {rootfs or '<empty>'}")

    return _call_ghidra_mcp(str(root.resolve()))


def _call_ghidra_mcp(rootfs: str) -> dict:
    return _run_coroutine(_call_ghidra_mcp_async(rootfs))


async def _call_ghidra_mcp_async(rootfs: str) -> dict:
    client = MultiServerMCPClient(
        {
            "ghidra": {
                "url": config.GHIDRA_MCP_URL,
                "transport": "sse",
            }
        },
        handle_tool_errors=False,
    )

    try:
        tools = await client.get_tools(server_name="ghidra")
    except Exception as exc:
        raise GhidraMCPError(
            f"Ghidra MCP 서버에 연결할 수 없습니다 ({config.GHIDRA_MCP_URL}): {exc}"
        ) from exc

    tool_map = {tool.name: tool for tool in tools}
    required = {"list_imports", "list_methods", "list_strings"}
    missing = sorted(required - tool_map.keys())
    if missing:
        raise GhidraMCPError(f"Ghidra MCP 필수 도구가 없습니다: {', '.join(missing)}")

    imports, methods, strings = await asyncio.gather(
        _read_paged(tool_map["list_imports"]),
        _read_paged(tool_map["list_methods"]),
        _read_paged(tool_map["list_strings"]),
    )

    imports = _unique(imports)
    methods = _unique(methods)
    strings = _unique(strings)
    dangerous = _find_dangerous_calls(imports + methods)
    files, configs, services = _inventory_rootfs(Path(rootfs))

    binary_path = config.GHIDRA_BINARY_PATH.strip()
    if not binary_path:
        binary_path = rootfs if Path(rootfs).is_file() else "<ghidra-current-program>"

    return {
        "binaries": [{
            "path": binary_path,
            "stripped": _looks_stripped(methods),
            "imports": imports,
            "strings": strings,
            "dangerous_calls": dangerous,
        }],
        "files": files,
        "configs": configs,
        "services": services,
    }


async def _read_paged(tool: Any) -> list[str]:
    """Read one of GhidraMCP's offset/limit based list tools."""
    collected: list[str] = []
    for page in range(_MAX_PAGES):
        try:
            response = await tool.ainvoke({"offset": page * _PAGE_LIMIT, "limit": _PAGE_LIMIT})
        except Exception as exc:
            raise GhidraMCPError(f"Ghidra MCP 도구 호출 실패 ({tool.name}): {exc}") from exc

        lines = _response_lines(response)
        error = next((line for line in lines if _is_tool_error(line)), None)
        if error:
            raise GhidraMCPError(f"Ghidra MCP 도구 오류 ({tool.name}): {error}")

        collected.extend(lines)
        if len(lines) < _PAGE_LIMIT:
            break
    else:
        raise GhidraMCPError(
            f"Ghidra MCP 응답이 {_MAX_PAGES * _PAGE_LIMIT}개 제한을 초과했습니다 ({tool.name})"
        )
    return collected


def _is_tool_error(line: str) -> bool:
    lowered = line.lower()
    return lowered.startswith(_ERROR_PREFIXES) or bool(_HTTP_ERROR_PATTERN.match(line))


def _response_lines(value: Any) -> list[str]:
    """Flatten LangChain/MCP response variants into non-empty text lines."""
    if value is None:
        return []
    if isinstance(value, str):
        return [line.strip() for line in value.splitlines() if line.strip()]
    if isinstance(value, dict):
        for key in ("content", "text", "result"):
            if key in value:
                return _response_lines(value[key])
        return [str(value)]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        result: list[str] = []
        for item in value:
            result.extend(_response_lines(item))
        return result
    if hasattr(value, "content"):
        return _response_lines(value.content)
    if hasattr(value, "text"):
        return _response_lines(value.text)
    return [str(value).strip()] if str(value).strip() else []


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _find_dangerous_calls(symbols: Iterable[str]) -> list[str]:
    found: set[str] = set()
    for line in symbols:
        lowered = line.lower()
        for symbol in _DANGEROUS_SYMBOLS:
            if re.search(rf"(?<![a-z0-9_]){re.escape(symbol)}(?![a-z0-9_])", lowered):
                found.add(symbol)
    return sorted(found)


def _looks_stripped(methods: Iterable[str]) -> bool:
    """Use Ghidra's generated FUN_/sub_ names as a conservative heuristic."""
    names = list(methods)
    if not names:
        return True
    generated = sum(
        1 for name in names
        if re.search(r"(?:^|\s)(?:FUN_|sub_)[0-9a-f]+", name, re.IGNORECASE)
    )
    return generated / len(names) >= 0.5


def _inventory_rootfs(root: Path) -> tuple[list[str], list[str], list[str]]:
    """Create the non-Ghidra portions of StaticRaw from an extracted rootfs."""
    if root.is_file():
        return [str(root)], [], []

    files: list[str] = []
    configs: list[str] = []
    services: list[str] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = "/" + path.relative_to(root).as_posix()
        files.append(relative)
        if len(files) >= _MAX_FILES:
            break

        if _is_service_file(relative):
            services.append(path.name)

        if len(configs) < _MAX_CONFIG_FILES and _is_config_file(relative, path):
            sample = _read_text_sample(path)
            if sample:
                configs.append(f"[{relative}]\n{sample}")

    return files, _unique(configs), _unique(services)


def _is_config_file(relative: str, path: Path) -> bool:
    lowered = relative.lower()
    return (
        lowered.startswith("/etc/")
        or path.suffix.lower() in _CONFIG_SUFFIXES
    ) and path.stat().st_size <= _MAX_CONFIG_BYTES


def _is_service_file(relative: str) -> bool:
    lowered = relative.lower()
    return lowered.startswith("/etc/init.d/") or lowered.startswith("/etc/rc.d/")


def _read_text_sample(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in raw:
        return ""
    return raw.decode("utf-8", errors="replace")[:_MAX_CONFIG_CHARS].strip()


def _run_coroutine(coro: Any) -> Any:
    """Run MCP async calls from both CLI and FastAPI's running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()
