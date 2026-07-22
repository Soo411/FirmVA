# agents/surface.py: Attack Surface Agent
########################################################
# 역할: 정적 로우 데이터로부터 공격 가능한 진입점 목록(공격표면)을 생성
#       각 진입점에 '인증 필요 여부'를 태깅
#       (인증 없는 진입점이 동적 분석 우선순위 최상위이므로 앞으로 정렬)
# 입력 : 공유 저장소의 static_raw (Candidate 정적과 병렬 실행)
# 출력 : state["surface"] = AttackSurface
# 전달형식: surface.json (Orchestrator 거쳐 Dynamic Analysis Agent로 전달)
# 주의: 이 에이전트는 Candidate(정적) 하위 에이전트들과 '병렬 실행1' 그룹임
#       LLM 판정이 아닌, 관찰 데이터에서 진입점을 규칙적으로 뽑아내는 역할
########################################################
from ..schemas import StaticRaw, AttackSurface, EntryPoint
from .. import store

# 진입점 판정 fallback 에서 "위험할 수 있는 네트워크/실행 관련 함수"로 간주할 심볼들.
# 정적분석이 관찰한 바이너리가 .cgi 확장자가 아니어도(예: httpd, boa 본체),
# 이런 함수를 쓰는 바이너리는 원격 입력을 처리할 가능성이 있어 후보로 남긴다.
_RISKY_CALLS = (
    "system", "exec", "execve", "execl", "popen",
    "strcpy", "strcat", "sprintf", "memcpy",
    "recv", "read", "accept", "socket",
)


# 공유 저장소에서 static_raw 를 재사용해서 읽음
def run(state: dict) -> dict:
    raw = StaticRaw(**store.load("static_raw"))
    print("[Surface] 공격표면(진입점) 생성 중 ...")
    eps = []
    n = 0

    # 1) 웹 CGI 진입점: 위험 함수(strcpy 등)를 쓰는 CGI는 우선 후보
    #    - 기존에는 path.endswith(".cgi") 만 확인했는데, 이러면 실행 파일명이
    #      cgi 확장자가 아닌 경우(예: /www/cgi-bin/formLogin, 확장자 없음)를 놓친다.
    #      확장자 또는 cgi-bin 경로 포함 여부를 함께 확인하도록 완화.
    for b in raw.binaries:
        if _looks_like_cgi(b.path):
            n += 1
            # netdetect처럼 인증 설정에 걸리지 않는 경로는 무인증으로 태깅
            no_auth = "ndbin" in b.path or "netdetect" in b.path
            eps.append(EntryPoint(
                ep_id=f"ep{n}",
                type="http-cgi",
                target=_to_url(b.path),
                param=_guess_param(b),
                auth_required=not no_auth,
                note="위험함수 사용: " + ", ".join(b.dangerous_calls) if b.dangerous_calls else "",
            ))

    # 2) 네트워크 서비스 진입점 (raw.services 가 비어있을 수 있으므로 안전하게 처리)
    for svc in (raw.services or []):
        n += 1
        eps.append(EntryPoint(
            ep_id=f"ep{n}", type="service", target=svc,
            param=None, auth_required=True, note="원격 서비스",
        ))

    # 3) Fallback: 위 두 규칙에서 아무 진입점도 못 찾았을 때.
    #    정적분석이 바이너리를 1개만 관찰한 경우(예: httpd 본체) 흔히 발생.
    #    이 경우 침묵 속에 "진입점 0개"로 끝나면 이후 동적 분석 단계 전체가
    #    무의미해지므로, 위험 함수를 쓰는 바이너리를 최소한 후보로 남긴다.
    if not eps:
        print("[Surface] 경고: 규칙 기반 진입점 0개 -> 위험 함수 기반 fallback 시도")
        for b in raw.binaries:
            risky = [c for c in (b.dangerous_calls or []) if c in _RISKY_CALLS]
            if not risky:
                continue
            n += 1
            eps.append(EntryPoint(
                ep_id=f"ep{n}",
                type="http-cgi",
                target=_to_url(b.path),
                param=_guess_param(b),
                auth_required=True,  # 근거 불충분하므로 인증 필요로 보수적 태깅
                note=(
                    "[fallback: cgi/service 규칙 미매칭] 위험함수 사용: "
                    + ", ".join(risky)
                ),
            ))

    if not eps:
        print(
            "[Surface] 경고: fallback 에서도 진입점을 찾지 못함 "
            f"(관찰된 바이너리 {len(raw.binaries)}개, 서비스 {len(raw.services or [])}개). "
            "Static 단계에서 dangerous_calls/경로 추출이 제대로 됐는지 확인 필요."
        )

    # 4) 인증 없는 진입점을 맨 앞으로 정렬 (동적 분석 우선순위 최상위)
    eps.sort(key=lambda e: e.auth_required)
    result = AttackSurface(entrypoints=eps)
    store.save("surface", result)
    print(f"[Surface] 완료: 진입점 {len(eps)}개 (무인증 우선 정렬)")
    return {"surface": result}


def _looks_like_cgi(path: str) -> bool:
    """확장자가 .cgi 이거나 cgi-bin 계열 경로에 있으면 CGI 진입점으로 간주."""
    lowered = path.lower()
    if lowered.endswith(".cgi"):
        return True
    return "cgi-bin" in lowered or "ndbin" in lowered


# /cramfs/ndbin/netdetect.cgi -> /nd-bin/netdetect.cgi 형태로 대략 매핑
def _to_url(path: str) -> str:
    name = path.split("/")[-1]
    if "ndbin" in path or "netdetect" in name:
        return f"/nd-bin/{name}"
    return f"/cgi-bin/{name}"


def _guess_param(b) -> str:
    for s in b.strings:
        if s in ("commit", "flag", "cmd"):
            return s
    return "commit"
