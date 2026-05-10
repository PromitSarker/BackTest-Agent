from typing import TypedDict, Optional
from langgraph.graph import StateGraph, END
import time

from agent.spec_loader import load_spec, extract_endpoints
from agent.api_client import login, register_and_login
from agent.test_runner import run_all_tests
from agent.analyzer import deduplicate_and_finalize
from report.generator import generate_report
from agent.logger import logger


class AgentState(TypedDict):
    base_url: str
    username: str
    password: str
    spec_path: str
    spec: Optional[dict]
    endpoints: Optional[list]
    # User A — the "owner"
    user_a_token: Optional[str]
    user_a_id: Optional[int]
    # User B — the "attacker"
    user_b_token: Optional[str]
    user_b_id: Optional[int]
    # Dynamically created resource IDs
    created_post_id: Optional[int]
    created_comment_id: Optional[int]
    # Timing
    start_time: Optional[float]
    # Results
    raw_findings: Optional[list]
    tested_endpoints: Optional[list]
    findings: Optional[list]
    report: Optional[dict]


def load_spec_node(state: AgentState):
    spec = load_spec(state.get("spec_path", "openapi.json"))
    endpoints = extract_endpoints(spec)
    logger.info(f"Loaded spec: {len(endpoints)} endpoints")
    return {"spec": spec, "endpoints": endpoints, "start_time": time.time()}


def setup_users_node(state: AgentState):
    """Register two unique users (A=owner, B=attacker) and login seeded user."""
    base_url = state["base_url"]
    logger.info("Setting up User A (owner)...")
    try:
        token_a, id_a = register_and_login(base_url)
    except Exception as e:
        logger.error(f"User A setup failed: {e}")
        token_a, id_a = None, None

    logger.info("Setting up User B (attacker)...")
    try:
        token_b, id_b = register_and_login(base_url)
    except Exception as e:
        logger.error(f"User B setup failed: {e}")
        token_b, id_b = None, None

    logger.info(f"UserA id={id_a}, UserB id={id_b}")
    return {
        "user_a_token": token_a,
        "user_a_id": id_a,
        "user_b_token": token_b,
        "user_b_id": id_b,
    }


def create_resources_node(state: AgentState):
    """User A creates a post and comment so we have real IDs for tests."""
    from agent.api_client import call_api
    base_url = state["base_url"]
    token_a = state.get("user_a_token")
    post_id = None
    comment_id = None

    if not token_a:
        logger.warning("No User A token; skipping resource creation")
        return {"created_post_id": None, "created_comment_id": None}

    headers = {"Authorization": f"Bearer {token_a}"}

    # Create post
    resp = call_api("POST", f"{base_url}/posts", headers=headers,
                    json={"body": "Test post created by QA Agent"})
    if resp["status_code"] in (200, 201):
        data = resp["json"] or {}
        post_id = data.get("id")
        logger.info(f"Created post id={post_id}")
    else:
        logger.warning(f"Post creation failed: {resp['status_code']} {resp['text']}")

    # Create comment on that post
    if post_id:
        resp = call_api("POST", f"{base_url}/posts/{post_id}/comments",
                        headers=headers, json={"body": "Test comment by QA Agent"})
        if resp["status_code"] in (200, 201):
            data = resp["json"] or {}
            comment_id = data.get("id")
            logger.info(f"Created comment id={comment_id}")

    return {"created_post_id": post_id, "created_comment_id": comment_id}


def run_tests_node(state: AgentState):
    results = run_all_tests(state)
    return {
        "raw_findings": results["findings"],
        "tested_endpoints": results["tested_endpoints"]
    }


def analyze_node(state: AgentState):
    findings = deduplicate_and_finalize(state.get("raw_findings", []))
    return {"findings": findings}


def generate_report_node(state: AgentState):
    elapsed = time.time() - (state.get("start_time") or time.time())
    report = generate_report(
        findings=state["findings"],
        base_url=state["base_url"],
        spec=state.get("spec", {}),
        endpoints=state.get("endpoints", []),
        tested_endpoints_list=state.get("tested_endpoints", []),
        duration_seconds=round(elapsed, 2),
        output_file="report.json",
    )
    return {"report": report}


def build_graph():
    builder = StateGraph(AgentState)
    builder.add_node("load_spec", load_spec_node)
    builder.add_node("setup_users", setup_users_node)
    builder.add_node("create_resources", create_resources_node)
    builder.add_node("run_tests", run_tests_node)
    builder.add_node("analyze", analyze_node)
    builder.add_node("generate_report", generate_report_node)

    builder.set_entry_point("load_spec")
    builder.add_edge("load_spec", "setup_users")
    builder.add_edge("setup_users", "create_resources")
    builder.add_edge("create_resources", "run_tests")
    builder.add_edge("run_tests", "analyze")
    builder.add_edge("analyze", "generate_report")
    builder.add_edge("generate_report", END)
    return builder.compile()
