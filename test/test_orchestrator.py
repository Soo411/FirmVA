from unittest.mock import patch

from src import config
from src.orchestrator import build_graph


def _edges(graph):
    return {(edge.source, edge.target) for edge in graph.get_graph().edges}


def test_static_only_graph_excludes_qemu_nodes():
    graph = build_graph(enable_dynamic=False)
    nodes = graph.get_graph().nodes
    edges = _edges(graph)

    assert "dynamic" not in nodes
    assert "candidate_dynamic" not in nodes
    assert ("static", "candidate_static") in edges
    assert ("static", "surface") in edges
    assert ("candidate_static", "report") in edges
    assert ("surface", "report") in edges


def test_full_graph_keeps_dynamic_pipeline():
    graph = build_graph(enable_dynamic=True)
    nodes = graph.get_graph().nodes
    edges = _edges(graph)

    assert "dynamic" in nodes
    assert "candidate_dynamic" in nodes
    assert ("surface", "dynamic") in edges
    assert ("dynamic", "candidate_dynamic") in edges


def test_real_graph_requires_openai_key():
    with patch.object(config, "DEMO_MODE", False):
        with patch.object(config, "OPENAI_API_KEY", ""):
            try:
                build_graph(enable_dynamic=False)
            except config.ConfigurationError:
                pass
            else:
                raise AssertionError("ConfigurationError was not raised")
