# candidates/static/info.py: 정보 노출(Information Disclosure) 계열 (한 파일로 통합)
########################################################
# ISTG-FW-INFO-001  Disclosure of Source Code and Binaries
# ISTG-FW-INFO-002  Disclosure of Implementation Details
# ISTG-FW-INFO-003  Disclosure of Ecosystem Details

# 통합 이유:
# 세 항목 모두 정적 로우 데이터(문자열/파일 목록/바이너리)라는
# '같은 관찰 데이터'를 근거로 판정하므로, 하나의 파일에서 항목별 함수로 나눔

# 입력 : observed (StaticRaw를 JSON 문자열로 만든 관찰 데이터)
# 출력 : 취약으로 판정된 Finding 목록
########################################################

from ..base import judge

PHASE = "static"
LOC = "filesystem/binaries"

# 소스코드/바이너리 노출 여부
def check_info_001(observed: str):   
    return judge("ISTG-FW-INFO-001", PHASE, observed, LOC)

# 구현 세부정보(빌드 경로, 디버그 문자열 등) 노출 여부
def check_info_002(observed: str):    
    return judge("ISTG-FW-INFO-002", PHASE, observed, LOC)

# 생태계(백엔드 주소, 업데이트 URL 등) 정보 노출 여부
def check_info_003(observed: str):
    return judge("ISTG-FW-INFO-003", PHASE, observed, LOC)

# INFO 계열 3개 항목을 모두 진단하고, 취약 판정만 모아 반환
def run(observed: str) -> list:
    results = [
        check_info_001(observed),
        check_info_002(observed),
        check_info_003(observed),
    ]
    return [f for f in results if f]
