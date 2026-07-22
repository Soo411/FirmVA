# binwalk_tool.py: binwalk 을 호출해 펌웨어 .bin 을 분해
########################################################
# binwalk 로 시그니처 스캔 -> Squashfs, 커널, 부트로더 위치 확인
########################################################

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .. import config
from test import demo   # 데모 결과는 test/demo.py 로 분리됨


class BinwalkError(RuntimeError):
    """실제 binwalk 스캔 또는 추출을 완료하지 못했을 때 발생."""


def run(bin_path: str) -> dict:
    """binwalk 실행 결과를 dict 로 반환.
    반환 예: {"arch","endian","signatures","rootfs","kernel","bootloader"}"""
    if config.DEMO_MODE:
        return demo.binwalk_result(bin_path)

    executable = shutil.which("binwalk")
    if executable is None:
        raise BinwalkError("DEMO_MODE=false이지만 binwalk 실행 파일을 찾을 수 없습니다.")

    firmware = Path(bin_path).expanduser().resolve()
    if not firmware.is_file():
        raise BinwalkError(f"펌웨어 파일을 찾을 수 없습니다: {firmware}")

    # 1) 시그니처 스캔
    scan = _execute(
        [executable, str(firmware)],
        timeout=config.BINWALK_SCAN_TIMEOUT_SECONDS,
    )
    signatures = [
        line.strip()
        for line in scan.stdout.splitlines()
        if line.strip() and line.lstrip()[0].isdigit()
    ]

    # 2) 추출 (-e). 이전 추출물과 섞이지 않도록 실행별 작업 폴더 사용
    # Binwalk v2/v3의 출력 디렉터리 구조가 달라도 펌웨어별 작업 폴더
    # 아래에서 rootfs를 재귀 탐색할 수 있도록 실행 위치를 고정한다.
    extraction_workdir = Path(tempfile.mkdtemp(
        prefix=f"{firmware.stem[:40]}_",
        dir=config.WORK_DIR,
    ))
    _execute(
        [executable, "-e", str(firmware)],
        timeout=config.BINWALK_EXTRACT_TIMEOUT_SECONDS,
        cwd=extraction_workdir,
    )

    rootfs = _find_rootfs(extraction_workdir)
    if rootfs is None:
        raise BinwalkError(
            f"binwalk 추출은 완료됐지만 rootfs를 찾지 못했습니다: {extraction_workdir}"
        )

    scan_text = scan.stdout.lower()
    return {
        "arch": _guess_arch(signatures),
        "endian": _guess_endian(scan_text),
        "signatures": signatures,
        "rootfs": str(rootfs.resolve()),
        "kernel": _find_first(extraction_workdir, ["*uImage*", "*zImage*", "*kernel*"]),
        "bootloader": _find_first(
            extraction_workdir,
            ["*u-boot*", "*uboot*", "*bootloader*"],
        ),
    }


def _execute(
    args: list[str],
    *,
    timeout: float,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BinwalkError(f"binwalk 실행 시간이 {timeout}초를 초과했습니다: {args}") from exc
    except OSError as exc:
        raise BinwalkError(f"binwalk 프로세스를 실행할 수 없습니다: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "오류 상세 없음").strip()[-1_000:]
        raise BinwalkError(
            f"binwalk가 종료 코드 {result.returncode}을 반환했습니다: {detail}"
        )
    return result


# 이하 보조 함수들
def _guess_arch(signatures: list[str]) -> str:
    text = " ".join(signatures).lower()
    # aarch64를 arm보다 먼저 확인해야 ARM으로 잘못 분류되지 않는다.
    for token, label in (
        ("aarch64", "AARCH64"),
        ("mips", "MIPS"),
        ("arm", "ARM"),
        ("x86", "X86"),
    ):
        if token in text:
            return label
    return "unknown"


def _guess_endian(scan_text: str) -> str:
    if "little endian" in scan_text:
        return "little"
    if "big endian" in scan_text:
        return "big"
    return "unknown"


def _find_rootfs(extracted: Path) -> Path | None:
    preferred_names = ("squashfs-root", "ubifs-root", "jffs2-root", "cpio-root")
    for name in preferred_names:
        for path in extracted.rglob(name):
            if path.is_dir():
                return path
    for path in extracted.rglob("*-root*"):
        if path.is_dir():
            return path
    return None


def _find_first(base: Path, patterns: list[str]) -> str | None:
    for pattern in patterns:
        for path in base.rglob(pattern):
            return str(path.resolve())
    return None
