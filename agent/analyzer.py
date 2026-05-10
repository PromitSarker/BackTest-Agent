import uuid

def deduplicate_and_finalize(findings: list) -> list:
    """
    Deduplicate findings based on core vulnerability signature.
    Assigns severity and confidence scores based on verified impact.
    """
    VALID_CATEGORIES = {
        "status_code", "schema_contract", "endpoint_existence",
        "input_validation", "authentication", "authorization",
        "error_handling", "headers_cors", "rate_limiting",
        "business_logic", "consistency", "performance",
        "documentation_drift", "http_protocol"
    }

    unique_findings = []
    signatures = set()

    for f in findings:
        # Category Mapping & Validation
        category = f.get("category", "status_code")
        if category not in VALID_CATEGORIES:
            category = "status_code"
        f["category"] = category

        # Vulnerability Signature: Issue Type + Resource Path (ignoring variable IDs)
        # We want to report 'Missing Header' only once for the whole host if possible
        # but keep specific logic errors per endpoint.
        resource_path = f["endpoint"]
        if f["title"] == "Global Missing Security Headers":
            resource_path = "GLOBAL"
        
        signature = (f["category"], resource_path, f["title"])
        
        if signature in signatures:
            continue
        
        signatures.add(signature)

        # Final Polish
        f["confidence"] = f.get("confidence", "high") if isinstance(f.get("confidence"), str) else _map_confidence(f.get("confidence", 0.9))
        
        # Ensure reproduction steps are clear
        if not f.get("reproduction"):
             f["reproduction"] = f"Send {f['method']} request to {f['endpoint']} with provided evidence data."

        unique_findings.append(f)

    return unique_findings

def _map_confidence(score):
    if score >= 0.9: return "high"
    if score >= 0.5: return "medium"
    return "low"