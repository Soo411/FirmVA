import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.tools import binwalk_tool


def test_real_mode_requires_binwalk():
    with patch.object(binwalk_tool.config, "DEMO_MODE", False):
        with patch.object(binwalk_tool.shutil, "which", return_value=None):
            try:
                binwalk_tool.run("firmware.bin")
            except binwalk_tool.BinwalkError as exc:
                assert "찾을 수 없습니다" in str(exc)
            else:
                raise AssertionError("BinwalkError was not raised")


def test_nonzero_exit_is_an_error():
    completed = subprocess.CompletedProcess(
        args=["binwalk"], returncode=2, stdout="", stderr="bad image"
    )
    with patch.object(binwalk_tool.subprocess, "run", return_value=completed):
        try:
            binwalk_tool._execute(["binwalk"], timeout=1)
        except binwalk_tool.BinwalkError as exc:
            assert "bad image" in str(exc)
        else:
            raise AssertionError("BinwalkError was not raised")


def test_timeout_is_an_error():
    with patch.object(
        binwalk_tool.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(["binwalk"], 1),
    ):
        try:
            binwalk_tool._execute(["binwalk"], timeout=1)
        except binwalk_tool.BinwalkError as exc:
            assert "초과" in str(exc)
        else:
            raise AssertionError("BinwalkError was not raised")


def test_real_run_uses_absolute_path_and_finds_rootfs():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        firmware = root / "sample.bin"
        work = root / "work"
        firmware.write_bytes(b"firmware")
        work.mkdir()

        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            if "-e" in args:
                extracted_rootfs = Path(kwargs["cwd"]) / "extractions" / "squashfs-root"
                extracted_rootfs.mkdir(parents=True)
            output = "0 0x0 ARM firmware, little endian" if "-e" not in args else ""
            return subprocess.CompletedProcess(args, 0, output, "")

        with patch.object(binwalk_tool.config, "DEMO_MODE", False):
            with patch.object(binwalk_tool.config, "WORK_DIR", work):
                with patch.object(binwalk_tool.shutil, "which", return_value="/usr/bin/binwalk"):
                    with patch.object(binwalk_tool.subprocess, "run", side_effect=fake_run):
                        result = binwalk_tool.run(str(firmware))

    assert result["arch"] == "ARM"
    assert result["endian"] == "little"
    assert result["rootfs"].endswith("squashfs-root")
    assert calls[0][0][-1] == str(firmware.resolve())
    assert calls[1][0] == ["/usr/bin/binwalk", "-e", str(firmware.resolve())]
