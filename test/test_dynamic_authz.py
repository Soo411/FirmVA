import importlib.util
import json
from pathlib import Path


def _load_authz_module():
    root = Path(__file__).resolve().parents[1]
    authz_path = root / "src" / "agents" / "candidates" / "dynamic" / "authz.py"

    spec = importlib.util.spec_from_file_location(
        "dynamic_authz_under_test",
        authz_path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


authz = _load_authz_module()

def _observed(items: list[dict]) -> str:
    return json.dumps(items)


def test_unauthenticated_access_is_collected():
    observed = _observed([
        {
            "ep_id": "ep1",
            "target": "/nd-bin/netdetect.cgi",
            "reproduced": True,
            "result": "Unauthenticated request succeeded with HTTP 200",
            "trace": "No session cookie; privileged configuration returned",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert len(evidence["unauthorized_access"]) == 1
    assert evidence["privilege_escalation"] == []


def test_root_privilege_escalation_is_collected():
    observed = _observed([
        {
            "ep_id": "ep2",
            "target": "/nd-bin/netdetect.cgi?commit=payload",
            "reproduced": True,
            "result": "Command injection succeeded; id: uid=0(root) gid=0(root)",
            "trace": "spawned /bin/sh",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert len(evidence["privilege_escalation"]) == 1


def test_crash_alone_is_not_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep3",
            "target": "/nd-bin/netdetect.cgi",
            "reproduced": True,
            "result": "SIGSEGV, si_addr=0x42424242 (PC overwrite observed)",
            "trace": "process crashed",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["unauthorized_access"] == []
    assert evidence["privilege_escalation"] == []


def test_invalid_json_returns_no_evidence():
    evidence = authz.collect_authz_evidence("not-json")

    assert evidence == {
        "unauthorized_access": [],
        "privilege_escalation": [],
    }