import pytest
from govsec_scanner.intelligence.catalog import ServiceCatalog

def test_service_catalog_resolution_by_name():
    catalog = ServiceCatalog()
    item = catalog.resolve(service_name="ssh")
    assert item is not None
    assert item.key == "ssh"
    assert item.category == "remote_access"
    assert item.is_remote_access is True

def test_service_catalog_resolution_by_product():
    catalog = ServiceCatalog()
    item = catalog.resolve(service_name="unknown-svc", product="OpenSSH")
    assert item is not None
    assert item.key == "ssh"

def test_service_catalog_resolution_non_standard_port():
    catalog = ServiceCatalog()
    item = catalog.resolve(service_name="ssh", port=2222)
    assert item is not None
    assert item.key == "ssh"

def test_service_catalog_resolution_fallback_port():
    catalog = ServiceCatalog()
    item = catalog.resolve(service_name=None, product=None, port=3389)
    assert item is not None
    assert item.key == "rdp"
    assert item.category == "remote_access"

def test_service_catalog_18_services():
    catalog = ServiceCatalog()
    assert len(catalog.items) >= 18
