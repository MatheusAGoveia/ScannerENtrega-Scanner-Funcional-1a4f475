from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from govsec_scanner.intelligence.context import ServiceContext
from govsec_scanner.intelligence.catalog import ServiceCatalogItem

@dataclass
class RiskResult:
    score: int # 0 to 100
    level: str # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    reasons: list[str] = field(default_factory=list)

def calculate_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"

def evaluate_service_risk(
    service_name: str | None,
    catalog_item: ServiceCatalogItem | None,
    context: ServiceContext,
    findings: list[dict[str, Any]] | None = None,
) -> RiskResult:
    score = 0
    reasons: list[str] = []

    # Base risk from catalog
    if catalog_item:
        base_map = {"low": 15, "medium": 30, "high": 50, "critical": 75}
        base_val = base_map.get(catalog_item.base_risk.lower(), 15)
        score += base_val
        reasons.append(f"Serviço catalogado como '{catalog_item.name}' (Risco base: {catalog_item.base_risk.upper()})")
    else:
        score += 10
        reasons.append("Serviço não catalogado ou desconhecido detectado")

    # Remote access risk
    if context.is_remote_access or (catalog_item and catalog_item.is_remote_access):
        score += 20
        reasons.append("Serviço de acesso remoto detectado")

    # Unencrypted communication risk
    if not context.is_encrypted and (catalog_item and not catalog_item.is_encrypted):
        score += 15
        reasons.append("Comunicação não criptografada em trânsito")

    # Network Exposure
    if context.is_public_ip:
        score += 20
        reasons.append("Exposição direta em IP público")

    # Associated findings/vulnerabilities
    if findings:
        max_severity = "low"
        for finding in findings:
            sev = finding.get("severity", "low").lower()
            if sev == "critical":
                max_severity = "critical"
            elif sev == "high" and max_severity != "critical":
                max_severity = "high"
            elif sev == "medium" and max_severity not in ("critical", "high"):
                max_severity = "medium"

        if max_severity == "critical":
            score += 40
            reasons.append("Vulnerabilidade CRITICAL associada ao serviço")
        elif max_severity == "high":
            score += 25
            reasons.append("Vulnerabilidade HIGH associada ao serviço")
        elif max_severity == "medium":
            score += 15
            reasons.append("Vulnerabilidade MEDIUM associada ao serviço")

    # Cap score at 100
    final_score = min(100, score)
    level = calculate_level(final_score)

    if final_score > 0 and not reasons:
        reasons.append("Fatores gerais de risco identificados no ativo")

    return RiskResult(score=final_score, level=level, reasons=reasons)
