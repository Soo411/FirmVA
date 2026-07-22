import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.tools import ghidra_mcp


class FakeTool:
    def __init__(self, name, pages):
        self.name = name
        self.pages = pages

    async def ainvoke(self, args):
        return self.pages.get(args["offset"], [])


class FakeClient:
    def __init__(self, connections, *, handle_tool_errors):
        assert connections["ghidra"]["transport"] == "sse"
        assert handle_tool_errors is False

    async def get_tools(self, *, server_name):
        assert server_name == "ghidra"
        return [
            FakeTool("list_imports", {0: ["strcpy", "puts"]}),
            FakeTool("list_methods", {0: ["FUN_00401000", "main"]}),
            FakeTool("list_strings", {0: ["admin", "system"]}),
        ]


def test_response_lines_flattens_mcp_content():
    response = [{"type": "text", "text": "strcpy\nsystem"}, "puts"]
    assert ghidra_mcp._response_lines(response) == ["strcpy", "system", "puts"]


def test_dangerous_calls_are_exact_and_deduplicated():
    symbols = ["00401000 strcpy", "system", "my_system_helper", "strcpy"]
    assert ghidra_mcp._find_dangerous_calls(symbols) == ["strcpy", "system"]


def test_read_paged_collects_until_short_page():
    tool = FakeTool("list_imports", {0: ["strcpy", "puts"]})
    assert asyncio.run(ghidra_mcp._read_paged(tool)) == ["strcpy", "puts"]


def test_read_paged_rejects_bridge_errors():
    tool = FakeTool("list_imports", {0: ["Request failed: connection refused"]})
    try:
        asyncio.run(ghidra_mcp._read_paged(tool))
    except ghidra_mcp.GhidraMCPError as exc:
        assert "connection refused" in str(exc)
    else:
        raise AssertionError("GhidraMCPError was not raised")


def test_read_paged_keeps_import_symbol_named_error():
    tool = FakeTool("list_imports", {0: ["error -> EXTERNAL:00000056"]})
    assert asyncio.run(ghidra_mcp._read_paged(tool)) == ["error -> EXTERNAL:00000056"]


def test_read_paged_rejects_http_errors():
    tool = FakeTool("list_imports", {0: ["Error 404: Not Found"]})
    try:
        asyncio.run(ghidra_mcp._read_paged(tool))
    except ghidra_mcp.GhidraMCPError as exc:
        assert "404" in str(exc)
    else:
        raise AssertionError("GhidraMCPError was not raised")


def test_inventory_rootfs_collects_files_configs_and_services():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        init = root / "etc" / "init.d" / "httpd"
        conf = root / "etc" / "httpd.conf"
        binary = root / "bin" / "httpd"
        init.parent.mkdir(parents=True)
        binary.parent.mkdir(parents=True)
        init.write_text("#!/bin/sh\n/bin/httpd", encoding="utf-8")
        conf.write_text("listen=80", encoding="utf-8")
        binary.write_bytes(b"\x7fELF\x00")

        files, configs, services = ghidra_mcp._inventory_rootfs(root)

    assert "/bin/httpd" in files
    assert any("listen=80" in item for item in configs)
    assert services == ["httpd"]


def test_async_client_builds_static_raw_shape():
    with tempfile.TemporaryDirectory() as temp_dir:
        with patch.object(ghidra_mcp, "MultiServerMCPClient", FakeClient):
            with patch.object(ghidra_mcp.config, "GHIDRA_BINARY_PATH", "/bin/httpd"):
                result = asyncio.run(ghidra_mcp._call_ghidra_mcp_async(temp_dir))

    assert result["binaries"][0] == {
        "path": "/bin/httpd",
        "stripped": True,
        "imports": ["strcpy", "puts"],
        "strings": ["admin", "system"],
        "dangerous_calls": ["strcpy"],
    }
    assert result["files"] == []


def test_real_mode_does_not_fall_back_to_demo():
    with tempfile.TemporaryDirectory() as temp_dir:
        with patch.object(ghidra_mcp.config, "DEMO_MODE", False):
            with patch.object(
                ghidra_mcp,
                "_call_ghidra_mcp",
                side_effect=ghidra_mcp.GhidraMCPError("offline"),
            ):
                try:
                    ghidra_mcp.analyze(temp_dir)
                except ghidra_mcp.GhidraMCPError as exc:
                    assert "offline" in str(exc)
                else:
                    raise AssertionError("GhidraMCPError was not raised")
