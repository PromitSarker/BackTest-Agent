from dotenv import load_dotenv
import os

from agent.graph import build_graph
from agent.logger import logger

def main():
    # Load environment variables
    load_dotenv()

    base_url = os.getenv("BASE_URL")
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")

    # Basic validation (fail fast)
    if not base_url:
        raise ValueError("BASE_URL is missing in .env")
    if "localhost" in base_url:
        raise ValueError("Do not use localhost. Use the provided remote API.")

    if not username or not password:
        raise ValueError("USERNAME or PASSWORD missing in .env")

    logger.info("Agent started")
    logger.info("Running workflow...")

    # Initial state passed into LangGraph
    initial_state = {
        "base_url": base_url,
        "username": username,
        "password": password
    }

    # Build and run graph
    workflow = build_graph()
    final_state = workflow.invoke(initial_state)

    # Save report
    report = final_state.get("report")

    if report:
        os.makedirs("results", exist_ok=True)
        with open("results/report.json", "w", encoding="utf-8") as f:
            import json
            json.dump(report, f, indent=2)
        logger.info("Workflow completed. Report saved to results/report.json")
    else:
        logger.warning("Workflow completed, but no report generated.")


if __name__ == "__main__":
    main()

