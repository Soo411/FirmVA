# orchestrator.py:  Orchestrator (LangGraph 배선)
########################################################
# 모든 에이전트 간 통신은 반드시 이 그래프(Orchestrator)를 거침
# LangGraph 의 StateGraph로 노드(=에이전트)와 엣지(=전달 경로)를 연결

# 동작 흐름(다이어그램과 1:1 대응):

#  START
#    │ (1) 펌웨어 .bin
#    ▼
#  analysis ──(2)──▶ static ──(3)──┐
#                                   │                
#                     ┌─────────────┴─────────────┐ 
#                     ▼ (4-1, 병렬실행1)           ▼ (4-2, 병렬실행1)
#             candidate_static                surface
#                     │                            │ (5)
#                     │                            ▼
#                     │                         dynamic
#                     │                            │ (6, 병렬실행2)
#                     │                            ▼
#                     │                      candidate_dynamic
#                     │                            │
#                     └──────────┬─────────────────┘
#                                ▼ (7)
#                             report
#                                │ (8)
#                                ▼
#                               END

# candidate_static 과 (surface→dynamic→candidate_dynamic) 는 병렬로 진행,
# 둘 다 끝나야 report 가 실행 (LangGraph 가 자동으로 합류 지점을 관리)
# findings 는 candidate_static / candidate_dynamic 양쪽에서 누적(state.py 의 reducer).
########################################################

from langgraph.graph import StateGraph, START, END
from . import config
from .state import FirmState
from .agents import analysis, static, surface, dynamic, report
from .agents import candidates


def build_graph(enable_dynamic: bool | None = None):
    """FirmVA 그래프를 구성한다.

    ``enable_dynamic=False``는 QEMU 노드만 제외한다. Attack Surface는 정적
    관찰 데이터로 생성되는 FirmVA 산출물이므로 두 모드 모두 유지한다.
    """
    config.validate_runtime()
    if enable_dynamic is None:
        enable_dynamic = config.ENABLE_DYNAMIC_ANALYSIS

    g = StateGraph(FirmState)

    # 노드(에이전트) 등록
    g.add_node("analysis", analysis.run)                     # 2
    g.add_node("static", static.run)                         # 3
    g.add_node("candidate_static", candidates.run_static)    # 4(1)
    g.add_node("surface", surface.run)                       # 4(2)
    if enable_dynamic:
        g.add_node("dynamic", dynamic.run)                       # 5
        g.add_node("candidate_dynamic", candidates.run_dynamic)  # 6

    # defer=True: 정적/동적 두 갈래는 길이가 달라 끝나는 시점이 다름
    # 이 옵션을 주면 report 는 '모든 갈래가 끝날 때까지 기다렸다가' 딱 한 번만 실행
    g.add_node("report", report.run, defer=True)             # 7

    # 엣지(전달 경로) 연결
    g.add_edge(START, "analysis")
    g.add_edge("analysis", "static")

    # static 이후 병렬 분기: candidate_static과 surface 동시 실행 (병렬실행1)
    g.add_edge("static", "candidate_static")
    g.add_edge("static", "surface")

    # 정적 후보는 항상 보고서로 전달
    g.add_edge("candidate_static", "report")

    if enable_dynamic:
        # 공격표면 -> 동적 분석 -> 동적 후보
        g.add_edge("surface", "dynamic")
        g.add_edge("dynamic", "candidate_dynamic")
        g.add_edge("candidate_dynamic", "report")
    else:
        # 정적 전용 모드에서도 Attack Surface 생성 완료 후 보고서를 작성
        g.add_edge("surface", "report")

    g.add_edge("report", END)

    return g.compile()
