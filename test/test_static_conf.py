import importlib.util
import sys
import types
from pathlib import Path


def _make_package(name: str) -> None:
    package = types.ModuleType(name)
    package.__path__ = []
    sys.modules[name] = package


def _load_conf_module():
    root = Path(__file__).resolve().parents[1]
    conf_path = root / "src" / "agents" / "candidates" / "static" / "conf.py"

    # 실제 src 패키지를 import하지 않고, 테스트 전용 가짜 패키지 구조를 만든다.
    package_root = "conf_test_pkg"
    _make_package(package_root)
    _make_package(f"{package_root}.agents")
    _make_package(f"{package_root}.agents.candidates")
    _make_package(f"{package_root}.agents.candidates.static")

    # conf.py의 `from ..base import judge`를 위한 테스트용 가짜 base 모듈
    base_module = types.ModuleType(f"{package_root}.agents.candidates.base")
    base_module.judge = lambda *args, **kwargs: None
    sys.modules[base_module.__name__] = base_module

    module_name = f"{package_root}.agents.candidates.static.conf"
    spec = importlib.util.spec_from_file_location(module_name, conf_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


conf = _load_conf_module()


def test_finds_outdated_busybox():
    data = {
        "binaries": [
            {
                "path": "/bin/busybox",
                "strings": ["BusyBox v1.29.3"],
            }
        ]
    }

    evidence = conf._find_outdated_software(data)

    assert len(evidence) == 1
    assert "busybox 1.29.3" in evidence[0]["reason"]


def test_does_not_flag_current_busybox():
    data = {
        "binaries": [
            {
                "path": "/bin/busybox",
                "strings": ["BusyBox v1.30.0"],
            }
        ]
    }

    assert conf._find_outdated_software(data) == []


def test_excludes_build_toolchain_strings():
    data = {
        "binaries": [
            {
                "path": "/bin/httpd",
                "strings": ["Sourcery GCC 4.4.1"],
            }
        ]
    }

    assert conf._find_outdated_software(data) == []


def test_finds_enabled_exposed_telnet():
    data = {
        "services": ["telnetd"],
        "configs": [
            "telnetd=enabled",
            "telnetd listen 0.0.0.0:23",
        ],
    }

    evidence = conf._find_risky_enabled_services(data)

    assert len(evidence) == 1
    assert "telnet" in evidence[0]["reason"]


def test_ignores_telnet_without_exposure_evidence():
    data = {
        "services": ["telnetd"],
        "configs": ["telnetd=enabled"],
    }

    assert conf._find_risky_enabled_services(data) == []