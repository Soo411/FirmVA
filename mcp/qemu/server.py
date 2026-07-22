# server.py:  별도 구현 QEMU MCP Server
########################################################
# QEMU는 이 프로젝트에 적절한 공개 MCP가 존재하지 않음
# 따라서, 프로젝트를 위한 QEMU MCP Server를 별도 구현해 사용
# FastMCP 를 사용하면 함수에 데코레이터만 붙여 MCP 도구를 간편하게 사용 가능함
########################################################

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests
from fastmcp import FastMCP

mcp = FastMCP("qemu-firmva")

# ------------------------------------------------------------------
# 이 서버 전용 작업 디렉터리(디스크 이미지 / 콘솔 로그를 여기에 둠)
# ------------------------------------------------------------------
WORK_DIR = Path(__file__).resolve().parent / "work"
WORK_DIR.mkdir(parents=True, exist_ok=True)

CPIO_BIN = os.getenv("CPIO_BIN", "cpio")
GZIP_BIN = os.getenv("GZIP_BIN", "gzip")
HOST_HTTP_PORT = int(os.getenv("QEMU_HOST_HTTP_PORT", "8080"))
BOOT_WAIT_SECONDS = float(os.getenv("QEMU_BOOT_WAIT", "8"))

# 현재 파이프라인이 지원하는 아키텍처 -> (기본 QEMU 바이너리, 머신 타입, 콘솔 장치)
# 신규/재인증 기기는 실물 정보가 없으므로, binwalk(Analysis 단계)가 관찰한
# ExtractResult.arch / endian 값을 그대로 넘겨받아 여기서 선택한다.
def _resolve_qemu_target(arch: str, endian: str) -> Optional[dict]:
    arch = (arch or "").strip().lower()
    endian = (endian or "little").strip().lower()
    is_little = endian.startswith("lit") or endian in ("le", "little")

    if arch == "arm":
        return {
            "bin": os.getenv("QEMU_BIN_ARM", "qemu-system-arm"),
            "machine": os.getenv("QEMU_MACHINE_ARM", "versatilepb"),
            "console": "ttyAMA0",
        }
    if arch == "mips":
        default_bin = "qemu-system-mipsel" if is_little else "qemu-system-mips"
        return {
            "bin": os.getenv("QEMU_BIN_MIPS", default_bin),
            "machine": os.getenv("QEMU_MACHINE_MIPS", "malta"),
            "console": "ttyS0",
        }
    return None  # 아직 지원하지 않는 아키텍처 (arm / mips 만 지원)

# 현재 부팅된 QEMU 인스턴스 상태 (이 서버 프로세스가 살아있는 동안만 유지)
_STATE = {
    "proc": None,          # subprocess.Popen
    "initrd": None,        # 빌드한 initrd(cpio.gz) 경로
    "serial_log": None,    # 콘솔 로그 경로 (커널 oops/segfault 메시지 관찰용)
    "http": None,          # "127.0.0.1:8080"
}


def _stop_previous_instance() -> None:
    """이전에 띄운 QEMU가 남아있으면 정리하고 새로 부팅할 수 있게 함."""
    proc = _STATE.get("proc")
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _build_initrd(rootfs: str) -> Path:
    """binwalk가 추출한 rootfs 디렉터리를 QEMU -initrd 로 바로 넘길 수 있는
    cpio(newc)+gzip 이미지로 변환. 디스크 이미지/파일시스템 포맷 도구가 필요 없음."""
    missing = [b for b in (CPIO_BIN, GZIP_BIN, "find") if shutil.which(b) is None]
    if missing:
        raise RuntimeError(
            f"다음 도구가 없습니다: {', '.join(missing)}. "
            "apt-get install cpio gzip findutils 로 설치한 뒤 다시 시도하세요."
        )

    initrd_path = WORK_DIR / "rootfs.cpio.gz"
    # rootfs 디렉터리 내부를 상대경로로 담아야 부팅 시 '/'로 풀림
    # find . | cpio -o -H newc | gzip -9 > rootfs.cpio.gz  (rootfs 를 cwd로 실행)
    find_proc = subprocess.Popen(
        ["find", ".", "-print0"], cwd=rootfs, stdout=subprocess.PIPE,
    )
    cpio_proc = subprocess.Popen(
        [CPIO_BIN, "--null", "-o", "-H", "newc"],
        cwd=rootfs, stdin=find_proc.stdout, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    find_proc.stdout.close()  # cpio 쪽에서 SIGPIPE 제대로 받도록

    with open(initrd_path, "wb") as out_f:
        gzip_proc = subprocess.Popen(
            [GZIP_BIN, "-9"], stdin=cpio_proc.stdout, stdout=out_f,
            stderr=subprocess.PIPE,
        )
        cpio_proc.stdout.close()
        _, gzip_err = gzip_proc.communicate()
        _, cpio_err = cpio_proc.communicate()
        find_proc.wait()

    if gzip_proc.returncode != 0:
        raise RuntimeError(f"gzip 실패: {gzip_err.decode(errors='ignore')}")
    if cpio_proc.returncode not in (0, None):
        raise RuntimeError(f"cpio 실패: {cpio_err.decode(errors='ignore')}")

    return initrd_path


# 추출한 파일시스템을 사용해 (arch/endian에 맞는) QEMU 가상 공유기를 부팅
@mcp.tool()
def boot(rootfs: str, kernel: str = "", arch: str = "arm", endian: str = "little") -> dict:
    if not rootfs or not Path(rootfs).exists():
        return {"status": "error", "rootfs": rootfs,
                "error": f"rootfs 경로를 찾을 수 없습니다: {rootfs}"}
    if not kernel or not Path(kernel).exists():
        return {"status": "error", "rootfs": rootfs,
                "error": f"kernel 경로를 찾을 수 없습니다: {kernel}"}

    target = _resolve_qemu_target(arch, endian)
    if target is None:
        return {"status": "error", "rootfs": rootfs,
                "error": f"지원하지 않는 아키텍처입니다: arch={arch!r} endian={endian!r} "
                         "(현재 arm / mips 만 지원. mcp/qemu/server.py의 _resolve_qemu_target에 추가하세요)"}

    qemu_bin, machine, console = target["bin"], target["machine"], target["console"]
    if shutil.which(qemu_bin) is None:
        return {"status": "error", "rootfs": rootfs,
                "error": f"'{qemu_bin}' 이 설치되어 있지 않습니다 (apt-get install {qemu_bin})."}

    _stop_previous_instance()

    try:
        initrd_path = _build_initrd(rootfs)
    except (RuntimeError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        return {"status": "error", "rootfs": rootfs, "error": f"initrd 생성 실패: {detail}"}

    serial_log = WORK_DIR / "console.log"
    serial_log.write_text("")  # 이전 로그 초기화

    cmd = [
        qemu_bin,
        "-M", machine,
        "-kernel", kernel,
        "-initrd", str(initrd_path),
        # 별도 root= 없이 initramfs 로 부팅. 커널이 initramfs 안의
        # /init, /sbin/init, /etc/init, /bin/init, /bin/sh 순으로 자동 탐색함
        "-append", f"console={console}",
        "-net", "nic",
        "-net", f"user,hostfwd=tcp::{HOST_HTTP_PORT}-:80",
        "-nographic",
        "-serial", f"file:{serial_log}",
    ]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        return {"status": "error", "rootfs": rootfs, "error": f"QEMU 실행 실패: {e}"}

    # 커널/유저랜드가 뜰 때까지 잠시 대기 (완벽한 부팅 감지 대신 고정 대기 + 조기 종료 확인)
    time.sleep(BOOT_WAIT_SECONDS)
    if proc.poll() is not None:
        tail = serial_log.read_text(errors="ignore")[-2000:] if serial_log.exists() else ""
        return {"status": "error", "rootfs": rootfs,
                "error": f"QEMU가 조기 종료됨 (코드 {proc.returncode}, {qemu_bin}/{machine})",
                "console_tail": tail}

    _STATE.update({
        "proc": proc, "initrd": str(initrd_path),
        "serial_log": str(serial_log), "http": f"127.0.0.1:{HOST_HTTP_PORT}",
    })

    return {"status": "booted", "rootfs": rootfs, "http": _STATE["http"],
            "arch": arch, "endian": endian, "qemu_bin": qemu_bin, "machine": machine}


def _tail_console(n_chars: int = 1500) -> str:
    log = _STATE.get("serial_log")
    if not log or not Path(log).exists():
        return ""
    return Path(log).read_text(errors="ignore")[-n_chars:]


"""
부팅된 가상 공유기의 특정 진입점(URL/파라미터)에 요청을 보내 동작을 관찰합니다.
"""
@mcp.tool()
def poke(url: str, param: str = "", payload: str = "") -> dict:
    if _STATE.get("proc") is None or _STATE["proc"].poll() is not None:
        return {"url": url, "param": param,
                "observed": "QEMU 인스턴스가 부팅되어 있지 않습니다. boot()를 먼저 호출하세요.",
                "crashed": False}

    before_console = _tail_console()
    params = {param: payload} if param else None

    try:
        resp = requests.get(url, params=params, timeout=8)
        status_code = resp.status_code
        body_snippet = resp.text[:300]
        crashed = False
        observed = f"HTTP {status_code} 응답, 본문 일부: {body_snippet!r}"
    except requests.exceptions.Timeout:
        status_code = None
        crashed = True
        observed = "요청 타임아웃 (대상 프로세스가 응답하지 않음: 크래시/행 가능성)"
    except requests.exceptions.ConnectionError as e:
        status_code = None
        crashed = True
        observed = f"연결 끊김/거부됨 (프로세스 크래시로 서비스가 죽었을 가능성): {e}"

    # 요청 전후 콘솔 로그 차이를 확인해 커널이 보고한 세그폴트 등 단서 확보
    after_console = _tail_console()
    new_console = after_console[len(before_console):] if after_console.startswith(before_console) else after_console
    segv_match = re.search(r"(segfault|Oops|Unable to handle kernel)[^\n]*", new_console, re.IGNORECASE)
    if segv_match:
        crashed = True
        observed += f" | 콘솔 로그: {segv_match.group(0)}"

    return {
        "url": url, "param": param,
        "status_code": status_code,
        "observed": observed,
        "crashed": crashed,
        "reproduced": crashed or (status_code is not None),
        "console_excerpt": new_console.strip()[-500:],
    }


"""
실행 중 프로세스를 strace/ltrace 로 추적해 위험 함수 호출을 관찰합니다.
"""
@mcp.tool()
def trace(pid: int, seconds: float = 3.0) -> dict:
    if shutil.which("strace") is None:
        # strace 를 못 쓰면 최소한 커널 콘솔 로그(세그폴트 등)라도 근거로 제공
        return {"pid": pid, "trace": _tail_console(),
                "note": "'strace' 미설치: 콘솔 로그로 대체"}

    out_log = WORK_DIR / f"strace_{pid}.log"
    try:
        proc = subprocess.Popen(
            ["strace", "-f", "-tt", "-p", str(pid), "-o", str(out_log)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        return {"pid": pid, "trace": "", "error": f"strace 실행 실패: {e}"}

    time.sleep(seconds)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

    trace_text = out_log.read_text(errors="ignore") if out_log.exists() else ""
    if not trace_text.strip():
        # 대상 프로세스가 host 에서 보이지 않는 guest 내부 프로세스인 경우(전체 시스템 에뮬레이션)
        # strace로 직접 붙을 수 없으므로 커널 콘솔 로그를 대신 근거로 반환
        trace_text = _tail_console()
        return {"pid": pid, "trace": trace_text,
                "note": "host에서 해당 pid를 추적할 수 없어 콘솔 로그로 대체함"}

    return {"pid": pid, "trace": trace_text[-3000:]}


if __name__ == "__main__":
    # SSE 트랜스포트로 실행 -> .env 의 QEMU_MCP_URL과 맞춤
    mcp.run(transport="sse", host="127.0.0.1", port=8090)
