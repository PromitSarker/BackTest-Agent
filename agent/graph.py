from typing import TypedDict, Optional
from langgraph.graph import StateGraph, END
import os

from agent.spec_loader import load_spec, extract_endpoints
from agent.api_client import login
from agent.test_runner import run_tests
from agent.analyzer import analyze
from report.generator import generate_report
from agent.logger import logger

class AgentState(TypedDict):
    base_url: str
    username: str
    password: str
    spec_path: str
    spec: Optional[dict]
    endpoints: Optional[list[dict]]
    token: Optional[str]
    test_results: Optional[list[dict]]
    findings: Optional[list[dict]]
    report: Optional[dict]

def load_spec_node(state: AgentState):
    spec = load_spec(state.get("spec_path", "openapi.json"))
    endpoints = extract_endpoints(spec)
    return {"spec": spec, "endpoints": endpoints}

def login_node(state: AgentState):
    try:
        token = login(state["base_url"], state["username"], state["password"])
        logger.info(f"Login successful")
    except Exception as e:
        logger.error(f"Login/Register failed: {e}")
        token = None
    return {"token": token}

def run_tests_node(state: AgentState):
    results = run_tests(state["base_url"], state["endpoints"], state["token"])
    return {"test_results": results}

def analyze_node(state: AgentState):
    findings = analyze(state["test_results"], state["endpoints"])
    return {"findings": findings}

def generate_report_node(state: AgentState):
    report = generate_report(
        state["findings"], 
        state["base_url"], 
        state["test_results"], 
        state["endpoints"], 
        "report.json"
    )
    return {"report": report}

def build_graph():
    builder = StateGraph(AgentState)
    
    builder.add_node("load_spec", load_spec_node)
    builder.add_node("login", login_node)
    builder.add_node("run_tests", run_tests_node)
    builder.add_node("analyze", analyze_node)
    builder.add_node("generate_report", generate_report_node)

    builder.set_entry_point("load_spec")
    builder.add_edge("load_spec", "login")
    builder.add_edge("login", "run_tests")
    builder.add_edge("run_tests", "analyze")
    builder.add_edge("analyze", "generate_report")
    builder.add_edge("generate_report", END)
    
    return builder.compile()
