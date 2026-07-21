import importlib.util
import json
from pathlib import Path


def _load_scrt_module():
    root = Path(__file__).resolve().parents[1]
    scrt_path = root / "src" / "agents" / "candidates" / "static" / "scrt.py"
    spec = importlib.util.spec_from_file_location("static_scrt_under_test", scrt_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scrt = _load_scrt_module()


def _observed(static_raw: dict) -> str:
    return json.dumps(static_raw)


def test_collects_public_storage_secret_file():
    static_raw = {
        "binaries": [],
        "files": ["/home/httpd/secret.key"],
        "configs": [],
        "services": [],
    }

    evidence = scrt.collect_secret_evidence(_observed(static_raw))

    assert evidence["public_storage"][0]["matched_value"] == "/home/httpd/secret.key"
    assert evidence["unencrypted_storage"][0]["matched_value"] == "/home/httpd/secret.key"


def test_does_not_flag_generic_config_path_as_secret():
    static_raw = {
        "binaries": [],
        "files": ["/etc/config/network.json"],
        "configs": [],
        "services": [],
    }

    evidence = scrt.collect_secret_evidence(_observed(static_raw))

    assert evidence["public_storage"] == []
    assert evidence["unencrypted_storage"] == []
    assert evidence["hardcoded_secrets"] == []


def test_collects_and_redacts_secret_assignments():
    static_raw = {
        "binaries": [
            {
                "path": "/bin/httpd",
                "stripped": True,
                "imports": [],
                "strings": ["admin_pass=123456"],
                "dangerous_calls": [],
            }
        ],
        "files": [],
        "configs": ["api_key=abcdef1234567890"],
        "services": [],
    }

    evidence = scrt.collect_secret_evidence(_observed(static_raw))
    unencrypted_values = {item["matched_value"] for item in evidence["unencrypted_storage"]}
    hardcoded_values = {item["matched_value"] for item in evidence["hardcoded_secrets"]}

    assert "api_key=ab...90" in unencrypted_values
    assert "admin_pass=12...56" in unencrypted_values
    assert "admin_pass=12...56" in hardcoded_values
    assert "api_key=abcdef1234567890" not in unencrypted_values


def test_redacts_private_key_material():
    private_key = "-----BEGIN PRIVATE KEY-----abc123secret-----END PRIVATE KEY-----"
    static_raw = {
        "binaries": [
            {
                "path": "/bin/httpd",
                "stripped": True,
                "imports": [],
                "strings": [private_key],
                "dangerous_calls": [],
            }
        ],
        "files": [],
        "configs": [],
        "services": [],
    }

    evidence = scrt.collect_secret_evidence(_observed(static_raw))
    values = {item["matched_value"] for item in evidence["hardcoded_secrets"]}

    assert "-----BEGIN PRIVATE KEY-----<redacted>-----END PRIVATE KEY-----" in values
    assert private_key not in values


def test_collects_bare_high_entropy_backdoor_key():
    static_raw = {
        "binaries": [
            {
                "path": "/bin/timepro.cgi",
                "stripped": True,
                "imports": [],
                "strings": ["aaksjdkfj=#notenoughmineral^"],
                "dangerous_calls": [],
            }
        ],
        "files": [],
        "configs": [],
        "services": [],
    }

    evidence = scrt.collect_secret_evidence(_observed(static_raw))

    assert evidence["hardcoded_secrets"][0]["matched_value"] == "aa...l^"


def test_invalid_json_returns_empty_evidence():
    evidence = scrt.collect_secret_evidence("not json")

    assert evidence == {
        "public_storage": [],
        "unencrypted_storage": [],
        "hardcoded_secrets": [],
    }


if __name__ == "__main__":
    test_collects_public_storage_secret_file()
    test_does_not_flag_generic_config_path_as_secret()
    test_collects_and_redacts_secret_assignments()
    test_redacts_private_key_material()
    test_collects_bare_high_entropy_backdoor_key()
    test_invalid_json_returns_empty_evidence()
