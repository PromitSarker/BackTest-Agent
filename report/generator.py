import json
from jsonschema import validate, ValidationError

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string"},
        "summary": {
            "type": "object",
            "properties": {
                "total_findings": {"type": "integer"},
                "by_severity": {
                    "type": "object",
                    "properties": {
                        "high": {"type": "integer"},
                        "medium": {"type": "integer"},
                        "low": {"type": "integer"}
                    },
                    "additionalProperties": False,
                    "required": ["high", "medium", "low"]
                }
            },
            "required": ["total_findings", "by_severity"]
        },
        "findings": {
            "type": "array",
            "items": {"type": "object"}
        }
    },
    "required": ["target", "summary", "findings"]
}

def generate_report(findings: list[dict], base_url: str, output_file: str = "report.json"):
    by_severity = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity = f.get("severity", "low").lower()
        if severity in by_severity:
            by_severity[severity] += 1
            
    report = {
        "target": base_url,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity
        },
        "findings": findings
    }
    
    validate(instance=report, schema=REPORT_SCHEMA)
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    return report
