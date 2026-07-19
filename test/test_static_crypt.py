import importlib.util
import json
from pathlib import Path


def _load_crypt_module():
    root = Path(__file__).resolve().parents[1]
    crypt_path = root / "src" / "agents" / "candidates" / "static" / "crypt.py"
    spec = importlib.util.spec_from_file_location("static_crypt_under_test", crypt_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crypt = _load_crypt_module()


def _observed(static_raw: dict) -> str:
    return json.dumps(static_raw)


def test_collects_weak_crypto_from_static_raw():
    static_raw = {
        "binaries": [
            {
                "path": "/bin/httpd",
                "stripped": True,
                "imports": ["MD5_Init", "strcpy"],
                "strings": ["EVP_aes_128_ecb", "TLSv1_client_method"],
                "dangerous_calls": ["RC4_set_key(ctx, key)"],
            }
        ],
        "files": [],
        "configs": [],
        "services": [],
    }

    evidence = crypt.collect_crypto_evidence(_observed(static_raw))
    rules = {item["rule"] for item in evidence}

    assert "weak_hash_md5" in rules
    assert "weak_mode_ecb" in rules
    assert "obsolete_tls" in rules
    assert "weak_stream_cipher_rc4" in rules


def test_does_not_flag_tls12_as_tlsv1():
    static_raw = {
        "binaries": [
            {
                "path": "/bin/httpd",
                "stripped": True,
                "imports": [],
                "strings": ["TLSv1.2"],
                "dangerous_calls": [],
            }
        ],
        "files": [],
        "configs": [],
        "services": [],
    }

    evidence = crypt.collect_crypto_evidence(_observed(static_raw))

    assert evidence == []


def test_deduplicates_same_evidence():
    static_raw = {
        "binaries": [
            {
                "path": "/bin/httpd",
                "stripped": True,
                "imports": ["MD5_Init", "MD5_Init"],
                "strings": [],
                "dangerous_calls": [],
            }
        ],
        "files": [],
        "configs": [],
        "services": [],
    }

    evidence = crypt.collect_crypto_evidence(_observed(static_raw))
    md5_hits = [item for item in evidence if item["rule"] == "weak_hash_md5"]

    assert len(md5_hits) == 1


def test_invalid_json_returns_no_evidence():
    evidence = crypt.collect_crypto_evidence("not json")

    assert evidence == []


if __name__ == "__main__":
    test_collects_weak_crypto_from_static_raw()
    test_does_not_flag_tls12_as_tlsv1()
    test_deduplicates_same_evidence()
    test_invalid_json_returns_no_evidence()
