import pytest
from govsec_scanner.intelligence.catalog import default_catalog
from govsec_scanner.intelligence.context import evaluate_context
from govsec_scanner.intelligence.risk import evaluate_service_risk, RiskResult

def test_evaluate_service_risk_rdp_public():
    item = default_catalog.resolve(service_name="rdp")
    ctx = evaluate_context(ip_address="200.100.50.25", category=item.category, is_remote_access=item.is_remote_access, is_encrypted=item.is_encrypted)
    
    result = evaluate_service_risk(service_name="rdp", catalog_item=item, context=ctx)
    
    assert isinstance(result, RiskResult)
    assert result.score >= 50
    assert result.level in ("HIGH", "CRITICAL")
    assert len(result.reasons) > 0
    assert any("acesso remoto" in r for r in result.reasons)
    assert any("público" in r or "público" in r.lower() for r in result.reasons)

def test_evaluate_service_risk_reasons_non_empty_when_score_positive():
    item = default_catalog.resolve(service_name="http")
    ctx = evaluate_context(ip_address="10.0.0.1", category=item.category, is_remote_access=item.is_remote_access, is_encrypted=item.is_encrypted)
    
    result = evaluate_service_risk(service_name="http", catalog_item=item, context=ctx)
    
    if result.score > 0:
        assert len(result.reasons) > 0

def test_evaluate_service_risk_with_critical_finding():
    item = default_catalog.resolve(service_name="http")
    ctx = evaluate_context(ip_address="10.0.0.1", category=item.category, is_remote_access=item.is_remote_access, is_encrypted=item.is_encrypted)
    findings = [{"severity": "critical", "name": "CVE-2023-XXXX"}]
    
    result = evaluate_service_risk(service_name="http", catalog_item=item, context=ctx, findings=findings)
    
    assert result.level in ("HIGH", "CRITICAL")
    assert any("CRITICAL" in r for r in result.reasons)
