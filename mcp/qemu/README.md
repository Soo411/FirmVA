# QEMU MCP Server
  
## 개요
Ghidra와 달리, QEMU는 이 프로젝트에 적절한 공개 MCP가 존재하지 않습니다.
  
따라서, 프로젝트를 위한 QEMU MCP Server를 별도 구현해 사용합니다.

  
## 제공 도구
| 도구 | 설명 |
|------|------|
| `boot(rootfs, kernel, arch="arm", endian="little")` | 추출한 파일시스템 사용해 아키텍처에 맞는 QEMU 가상 공유기 부팅 |
| `poke(url, param, payload)` | 특정 진입점(CGI URL)에 요청 보내 동작 및 크래시 관찰 |
| `trace(pid)` | strace, ltrace 사용해 실행 프로세스 추적 |
  

## 실행 방법
```bash
pip install fastmcp requests
# arm 대상: qemu-system-arm / mips 대상: qemu-system-mips, qemu-system-mipsel
sudo apt-get install qemu-system-arm qemu-system-mips cpio gzip   # 필요한 아키텍처만 설치해도 됨
python mcp/qemu/server.py                 # 127.0.0.1:8090 (SSE) 대기
```

QEMU 설치 후 `.env` 의 `QEMU_MCP_URL` 이 `http://127.0.0.1:8090/sse` 인지 확인합니다.
  
`DEMO_MODE=false` 로 바꾸면 `Dynamic Analysis Agent` 가 이 QEMU MCP Server를 실제 호출합니다.

## 동작 방식(구현됨)
- `boot(rootfs, kernel, arch, endian)`: **아키텍처를 미리 고정하지 않고**, Analysis 단계(binwalk)가 관찰한
  `arch`/`endian` 값을 그대로 받아 그에 맞는 QEMU 바이너리/머신 타입을 고릅니다(`_resolve_qemu_target`).
  신규 출시·재인증 대상처럼 사전 정보가 없는 기기라도, binwalk가 실제로 뽑아낸 값을 근거로 삼기 때문에
  별도 코드 수정 없이 대응됩니다.
  - `arch="arm"` → `qemu-system-arm -M versatilepb`, 콘솔 `ttyAMA0`
  - `arch="mips"`, `endian="little"` → `qemu-system-mipsel -M malta`, 콘솔 `ttyS0`
  - `arch="mips"`, `endian="big"` → `qemu-system-mips -M malta`, 콘솔 `ttyS0`
  - 그 외 아키텍처는 아직 매핑이 없어 **명확한 에러**로 실패합니다(무작정 arm으로 부팅 시도하지 않음).
    필요하면 `_resolve_qemu_target()`에 항목을 추가하세요.

  추출된 rootfs 디렉터리는 `cpio`(newc 포맷) + `gzip`으로 압축해 initrd(`mcp/qemu/work/rootfs.cpio.gz`)로
  만들어 `-initrd`로 넘깁니다(디스크 이미지 빌드 도구 불필요). 게스트의 80 포트는 호스트
  `QEMU_HOST_HTTP_PORT`(기본 8080)로 포워딩하고, 콘솔 출력은 `mcp/qemu/work/console.log`에 기록합니다.
- `poke(url, param, payload)`: `requests`로 실제 HTTP 요청을 보냅니다. 연결 끊김/타임아웃이 발생하거나
  콘솔 로그에 `segfault`/`Oops` 등이 새로 찍히면 `crashed: true`로 판정합니다.
- `trace(pid, seconds=3)`: 호스트에서 보이는 pid라면 `strace -f -p <pid>`로 실제 추적합니다(strace 미설치
  시 자동으로 콘솔 로그로 대체). 전체 시스템 에뮬레이션 특성상 게스트 내부 프로세스의 pid는 호스트에서
  직접 보이지 않을 수 있는데, 이 경우에도 콘솔 로그를 대신 근거로 반환합니다.

### 환경변수(선택)
| 변수 | 기본값 | 설명 |
|------|--------|------|
| `QEMU_BIN_ARM` | `qemu-system-arm` | arch=arm 일 때 쓰는 QEMU 실행 파일 |
| `QEMU_MACHINE_ARM` | `versatilepb` | arch=arm 일 때 머신 타입 |
| `QEMU_BIN_MIPS` | `qemu-system-mips(el)` | arch=mips 일 때 쓰는 QEMU 실행 파일 (endian에 따라 자동 선택) |
| `QEMU_MACHINE_MIPS` | `malta` | arch=mips 일 때 머신 타입 |
| `CPIO_BIN` | `cpio` | rootfs → initrd 변환에 쓰는 cpio |
| `GZIP_BIN` | `gzip` | initrd 압축에 쓰는 gzip |
| `QEMU_HOST_HTTP_PORT` | `8080` | 게스트 80 포트를 포워딩할 호스트 포트 |
| `QEMU_BOOT_WAIT` | `8` | 부팅 후 poke 가능해질 때까지 대기 시간(초) |

## 알려진 한계
- `arch`/`endian`은 Analysis 단계(binwalk)가 추정한 값을 그대로 신뢰합니다. binwalk가 시그니처를 잘못
  판별하면(특히 사전 정보가 없는 신규 기기) 부팅도 그만큼 부정확해질 수 있으니, `boot()` 응답의
  `console_tail`(부팅 실패 시)을 보고 실제 아키텍처가 맞는지 교차 확인하는 것을 권장합니다.
- 현재 arm(versatilepb) / mips(malta) 두 조합만 매핑되어 있습니다. 다른 아키텍처(ARM64, PowerPC 등)는
  `_resolve_qemu_target()`에 새 분기를 추가해야 합니다.
- initramfs 부팅은 커널이 `/init`, `/sbin/init`, `/etc/init`, `/bin/init`, `/bin/sh` 순서로 자동 탐색해
  실행합니다. rootfs 안에 이 경로들 중 하나가 없으면 부팅이 안 될 수 있으니, 그런 경우 `-append`에
  `rdinit=<실제 init 경로>`를 추가하도록 조정이 필요합니다.
- `versatilepb`/`malta`는 실제 공유기 보드가 아닌 QEMU의 범용 개발 보드이기 때문에, 원본 벤더 커널이
  플래시 컨트롤러/스위치 칩 등 이 보드에 없는 하드웨어를 요구하면 부팅 도중 멈추거나 패닉이 날 수
  있습니다. 이 경우 `console.log`를 확인해 원인을 좁혀야 합니다.
- 부팅 대기시간(`QEMU_BOOT_WAIT`)은 대상 펌웨어의 커널/init 구성에 따라 늘려야 할 수 있습니다.
- 전체 시스템 에뮬레이션이라 게스트 프로세스 pid를 호스트에서 직접 얻을 방법이 없어, `trace()`는
  guest pid가 아닌 경우 콘솔 로그로 대체합니다.
