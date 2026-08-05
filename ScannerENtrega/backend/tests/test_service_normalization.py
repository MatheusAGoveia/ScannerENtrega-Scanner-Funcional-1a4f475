import pytest
from govsec_scanner.intelligence.normalization import (
    normalize_service_name,
    normalize_product,
    normalize_version,
    extract_or_build_cpe,
    normalize_service_observation,
)

def test_normalize_service_name_aliases():
    assert normalize_service_name("ssl/http") == "https"
    assert normalize_service_name("ms-wbt-server") == "rdp"
    assert normalize_service_name("microsoft-ds") == "smb"
    assert normalize_service_name("http") == "http"
    assert normalize_service_name(None) is None

def test_normalize_product_conservative():
    assert normalize_product("Microsoft IIS httpd") == "iis"
    assert normalize_product("OpenSSH sshd") == "openssh"
    assert normalize_product("unknown") is None
    assert normalize_product("") is None
    assert normalize_product(None) is None

def test_normalize_version():
    assert normalize_version("8.2p1 Ubuntu 4ubuntu0.5") == "8.2p1 Ubuntu 4ubuntu0.5"
    assert normalize_version("unknown") is None
    assert normalize_version(None) is None

def test_cpe_is_never_invented_from_product_and_version():
    assert extract_or_build_cpe("OpenSSH sshd", "8.2") is None
    assert extract_or_build_cpe("Microsoft IIS httpd", None) is None
    assert extract_or_build_cpe("unknown", "1.0") is None

def test_normalize_service_observation():
    data = normalize_service_observation(
        "ssl/http", "Microsoft IIS httpd", "10.0", cpe_raw="cpe:/a:microsoft:iis:10.0"
    )
    assert data.service_name_normalized == "https"
    assert data.product_normalized == "iis"
    assert data.version_normalized == "10.0"
    assert data.cpe == "cpe:/a:microsoft:iis:10.0"


def test_normalization_keeps_unknown_cpe_empty():
    data = normalize_service_observation("ssh", "OpenSSH", "9.6")
    assert data.cpe is None
