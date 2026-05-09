import json
from datetime import datetime
from jsonschema import validate, ValidationError

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "object"},
        "summary": {"type": "object"},
        "findings": {"type": "array"}
    },
    "required": ["target", "summary", "findings"]
}

def generate_report(findings: list[dict], base_url: str, test_results: list[dict], all_endpoints: list[dict], output_file: str = "report.json"):
    """
    Consolidates findings and metadata into a final JSON report and validates it against a schema.
    
    Args:
        findings: List of identified bugs/issues.
        base_url: The base URL of the target API.
        test_results: The raw results from all executed tests.
        all_endpoints: The full list of endpoints discovered from the spec.
        output_file: Path where the report should be saved.
        
    Returns:
        The generated report dictionary.
    """
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {}
    
    for f in findings:
        severity = f.get("severity", "low").lower()
        if severity in by_severity:
            by_severity[severity] += 1
        
        category = f.get("category", "unknown")
        by_category[category] = by_category.get(category, 0) + 1
    
    # Calculate coverage
    tested_endpoints = set()
    for tr in test_results:
        tested_endpoints.add((tr["method"], tr["endpoint"]))
    
    total_endpoints = len(all_endpoints)
    tested_count = len(tested_endpoints)
    coverage = (tested_count / total_endpoints * 100) if total_endpoints > 0 else 0

    report = {
        "target": {
            "base_url": base_url,
            "tested_at": datetime.utcnow().isoformat() + "Z",
            "agent_name": "QA-Agent",
            "duration_seconds": 0
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
    
    validate(instance=report, schema=REPORT_SCHEMA)
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    
    return report
