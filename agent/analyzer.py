def deduplicate_and_finalize(findings: list) -> list:
    """
    Deduplicate findings based on category, endpoint, method, and title.
    Group similar findings (e.g., missing headers) and ensure all categories are valid.
    """
    VALID_CATEGORIES = {
        "status_code", "schema_contract", "endpoint_existence",
        "input_validation", "authentication", "authorization",
        "error_handling", "headers_cors", "rate_limiting",
        "business_logic", "consistency", "performance",
        "documentation_drift", "http_protocol"
    }

    seen = set()
    final_findings = []

    for f in findings:
        # Map legacy categories just in case
        cat = f.get("category", "")
        if cat == "security": cat = "headers_cors"
        elif cat == "normal": cat = "status_code"
        elif cat == "concurrency": cat = "business_logic"
        elif cat == "idor": cat = "authorization"
        elif cat == "stability": cat = "error_handling"
        
        if cat not in VALID_CATEGORIES:
            cat = "status_code" # Fallback
        
        f["category"] = cat

        key = (f["category"], f["endpoint"], f["method"], f["title"])
        if key in seen:
            continue
        
        seen.add(key)
        final_findings.append(f)

    return final_findings