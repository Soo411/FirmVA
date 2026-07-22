# qemu_mcp.py: QEMU 에뮬레이션 기반 동적 분석을 수행
########################################################
# 블랙박스 원칙에 따라 소스 없이 실제 실행 동작만 관찰

# 이 서버가 제공하는 도구:
#    - boot(rootfs, kernel)      : QEMU versatilepb 로 부팅
#    - poke(url, param, payload) : 특정 진입점(URL/파라미터)을 실제로 요청/실행
#    - trace(pid)                : strace/ltrace로 위험 함수 호출 관찰
########################################################

import asyncio
import json
from typing import Any, List, Optional

from .. import config, store
from test import demo   # 데모 동적 데이터는 test/demo.py 로 분리됨


def run(surface: dict) -> dict:
    if config.DEMO_MODE:
        return demo.dynamic_raw(surface)

    try:
        return _call_qemu_mcp(surface)
    except Exception as e:                      # noqa
        return demo.dynamic_raw(surface, note=f"(MCP 연결 실패, 데모로 대체: {e})")


def _call_qemu_mcp(surface: dict) -> dict:
    """동기 진입점. 내부적으로 비동기 MCP 클라이언트를 돌려서 결과를 모은다."""
    return asyncio.run(_call_qemu_mcp_async(surface))


async def _call_qemu_mcp_async(surface: dict) -> dict:
    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient({
        "qemu": {
            "url": config.QEMU_MCP_URL,
            "transport": "sse",
        }
    })

    tools = await client.get_tools()
    tool_map = {t.name: t for t in tools}
    for name in ("boot", "poke", "trace"):
        if name not in tool_map:
            raise RuntimeError(f"QEMU MCP 서버에 '{name}' 도구가 없습니다 (mcp/qemu/server.py 확인).")


    extract = store.load("extract") or {}
    rootfs = extract.get("rootfs") or ""
    kernel = extract.get("kernel") or ""
    arch = (extract.get("arch") or "arm").lower()
    endian = (extract.get("endian") or "little").lower()
    if not rootfs:
        raise RuntimeError("추출된 rootfs 경로가 없습니다 (Analysis 단계 실행 여부 확인).")

    boot_info = _as_dict(await tool_map["boot"].ainvoke({
        "rootfs": rootfs, "kernel": kernel, "arch": arch, "endian": endian,
    }))
    if boot_info.get("status") != "booted":
        raise RuntimeError(f"QEMU 부팅 실패: {boot_info}")
    http_addr = boot_info.get("http", "127.0.0.1:8080")


    observations: List[dict] = []
    for ep in surface.get("entrypoints", []):
        observations.append(
            await _poke_entrypoint(tool_map, ep, http_addr)
        )


    new_entrypoints: List[dict] = []

    return {"observations": observations, "new_entrypoints": new_entrypoints}


async def _poke_entrypoint(tool_map: dict, ep: dict, http_addr: str) -> dict:
    ep_id = ep.get("ep_id", "")
    target = ep.get("target", "")
    param = ep.get("param") or ""


    if ep.get("type") != "http-cgi":
        return {
            "ep_id": ep_id, "target": target,
            "reproduced": False, "result": "정적 서비스 목록: QEMU 상에서 직접 poke 하지 않음",
            "trace": "",
        }

    url = target if target.startswith("http") else f"http://{http_addr}{target}"
    poke_info = _as_dict(await tool_map["poke"].ainvoke({
        "url": url, "param": param, "payload": ep.get("note", ""),
    }))

    observation = {
        "ep_id": ep_id,
        "target": target,
        "reproduced": bool(poke_info.get("crashed") or poke_info.get("reproduced")),
        "result": str(poke_info.get("observed", poke_info.get("result", ""))),
        "trace": "",
    }


    pid = poke_info.get("pid")
    if pid:
        trace_info = _as_dict(await tool_map["trace"].ainvoke({"pid": int(pid)}))
        observation["trace"] = str(trace_info.get("trace", ""))

    return observation


def _as_dict(result: Any) -> dict:
    """MCP 도구 호출 결과(dict / JSON 문자열 / 기타)를 dict로 정규화."""
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
            return parsed if isinstance(parsed, dict) else {"raw": parsed}
        except json.JSONDecodeError:
            return {"raw": result}
    return {"raw": str(result)}

