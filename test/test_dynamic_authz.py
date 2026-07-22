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


def test_http_200_login_page_is_not_unauthorized_access():
    observed = _observed([
        {
            "ep_id": "ep-login",
            "target": "/admin",
            "reproduced": True,
            "result": "Unauthenticated request returned HTTP 200 login page",
            "trace": "Authentication is still required",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["unauthorized_access"] == []


def test_negated_authentication_bypass_is_not_unauthorized_access():
    observed = _observed([
        {
            "ep_id": "ep-auth-failed",
            "target": "/admin/config",
            "reproduced": True,
            "result": "No authentication bypass detected; HTTP 200",
            "trace": "Protected configuration was not returned",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["unauthorized_access"] == []


def test_root_privilege_escalation_is_collected():
    observed = _observed([
        {
            "ep_id": "ep2",
            "target": "/nd-bin/netdetect.cgi?commit=payload",
            "reproduced": True,
            "result": "Command injection succeeded; id: uid=0(root) gid=0(root)",
            "trace": "spawned /bin/sh",
            "input_privilege": "low",
            "exploit_succeeded": True,
            "uid_before": 1000,
            "uid_after": 0,
            "root_shell_obtained": True,
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert len(evidence["privilege_escalation"]) == 1


def test_gid_zero_alone_is_not_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep-gid-only",
            "target": "/service",
            "reproduced": True,
            "result": "Process started with uid=1000 gid=0",
            "trace": "Process remained unprivileged",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["privilege_escalation"] == []


def test_uid_zero_without_exploit_success_is_not_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep-root-service",
            "target": "/sbin/httpd",
            "reproduced": True,
            "result": "Service process identity: uid=0(root)",
            "trace": "Service started normally",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["privilege_escalation"] == []


def test_original_root_process_is_not_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep-original-root",
            "target": "/admin/exec",
            "reproduced": True,
            "result": "Command injection succeeded; uid=0(root)",
            "trace": "Command ran in the existing service process",
            "input_privilege": "root",
            "exploit_succeeded": True,
            "uid_before": 0,
            "uid_after": 0,
            "root_shell_obtained": False,
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["privilege_escalation"] == []


def test_non_root_to_non_root_is_not_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep-non-root",
            "target": "/admin/exec",
            "reproduced": True,
            "result": "Command injection succeeded",
            "trace": "Payload remained unprivileged",
            "input_privilege": "low",
            "exploit_succeeded": True,
            "uid_before": 1000,
            "uid_after": 1000,
            "root_shell_obtained": False,
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["privilege_escalation"] == []


def test_unauthenticated_input_to_root_command_is_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep-unauth-root",
            "target": "/admin/exec",
            "reproduced": True,
            "result": "Command injection succeeded; root command executed",
            "trace": "Service process uid=0(root)",
            "input_privilege": "unauthenticated",
            "exploit_succeeded": True,
            "uid_before": 0,
            "uid_after": 0,
            "root_shell_obtained": False,
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert len(evidence["privilege_escalation"]) == 1


def test_explicit_low_privilege_text_keeps_legacy_observation_compatible():
    observed = _observed([
        {
            "ep_id": "ep-legacy",
            "target": "/admin/exec",
            "reproduced": True,
            "result": "Command injection succeeded; uid=0(root)",
            "trace": "initial uid=1000; root shell obtained",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert len(evidence["privilege_escalation"]) == 1


def test_negated_root_shell_is_not_privilege_escalation():
    observed = _observed([
        {
            "ep_id": "ep-failed-exploit",
            "target": "/admin/exec",
            "reproduced": True,
            "result": "Exploit succeeded, but no root shell obtained",
            "trace": "Process remained unprivileged",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence["privilege_escalation"] == []


def test_string_false_reproduced_value_is_ignored():
    observed = _observed([
        {
            "ep_id": "ep-invalid-bool",
            "target": "/admin/exec",
            "reproduced": "false",
            "result": "Command injection succeeded; uid=0(root)",
            "trace": "root shell obtained",
        }
    ])

    evidence = authz.collect_authz_evidence(observed)

    assert evidence == {
        "unauthorized_access": [],
        "privilege_escalation": [],
    }


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


def test_run_routes_authz_001_with_entrypoint_location():
    calls = []
    original_001 = authz.check_authz_001
    original_002 = authz.check_authz_002
    authz.check_authz_001 = lambda observed, location: calls.append(
        ("001", observed, location)
    ) or "finding-001"
    authz.check_authz_002 = lambda observed, location: calls.append(
        ("002", observed, location)
    ) or "finding-002"

    try:
        findings = authz.run(_observed([
            {
                "ep_id": "ep1",
                "target": "/admin/config",
                "reproduced": True,
                "result": "Unauthenticated request succeeded with HTTP 200",
                "trace": "Privileged configuration returned",
            }
        ]))
    finally:
        authz.check_authz_001 = original_001
        authz.check_authz_002 = original_002

    assert findings == ["finding-001"]
    assert len(calls) == 1
    assert calls[0][0] == "001"
    assert calls[0][2] == "ep1: /admin/config"


def test_run_routes_authz_002_with_entrypoint_location():
    calls = []
    original_001 = authz.check_authz_001
    original_002 = authz.check_authz_002
    authz.check_authz_001 = lambda observed, location: calls.append(
        ("001", observed, location)
    ) or "finding-001"
    authz.check_authz_002 = lambda observed, location: calls.append(
        ("002", observed, location)
    ) or "finding-002"

    try:
        findings = authz.run(_observed([
            {
                "ep_id": "ep2",
                "target": "/admin/exec",
                "reproduced": True,
                "result": "Command injection succeeded; uid=0(root)",
                "trace": "root shell obtained",
                "input_privilege": "low",
                "exploit_succeeded": True,
                "uid_before": 1000,
                "uid_after": 0,
                "root_shell_obtained": True,
            }
        ]))
    finally:
        authz.check_authz_001 = original_001
        authz.check_authz_002 = original_002

    assert findings == ["finding-002"]
    assert len(calls) == 1
    assert calls[0][0] == "002"
    assert calls[0][2] == "ep2: /admin/exec"
