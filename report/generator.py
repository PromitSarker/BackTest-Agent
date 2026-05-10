import json
import os
from datetime import datetime
from jsonschema import validate

def generate_report(findings: list[dict], base_url: str, spec: dict, endpoints: list[dict], tested_endpoints_list: list[str], duration_seconds: float, output_file: str = "report.json"):
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {}
    
    for f in findings:
        severity = f.get("severity", "low").lower()
        if severity in by_severity:
            by_severity[severity] += 1
        
        category = f.get("category", "status_code")
        by_category[category] = by_category.get(category, 0) + 1
    
    # Coverage calculation based on unique paths tested
    total_endpoints = len(endpoints) if endpoints else 1
    tested_count = len(set(tested_endpoints_list))
    coverage = (tested_count / total_endpoints * 100) if total_endpoints > 0 else 0
    coverage = min(coverage, 100.0)

    spec_version = spec.get("info", {}).get("version", "1.0.0")

    report = {
        "target": {
            "base_url": base_url,
            "tested_at": datetime.utcnow().isoformat() + "Z",
            "spec_version": spec_version,
            "agent_name": "QA-Agent",
            "duration_seconds": float(duration_seconds)
        },
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "endpoints_tested": tested_count,
            "endpoints_total": total_endpoints,
            "coverage_percent": round(coverage, 2)
        },
        "findings": findings
    }
    
    # Validate against actual schema file
    schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "report.schema.json")
    if os.path.exists(schema_path):
        with open(schema_path, "r") as sf:
            schema = json.load(sf)
        validate(instance=report, schema=schema)
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    
    return report
