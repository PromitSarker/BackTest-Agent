import os
import json
from groq import Groq
from dotenv import load_dotenv
from agent.logger import logger

load_dotenv()

class LLMClient:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            logger.warning("GROQ_API_KEY not found in environment. LLM generation will be disabled.")
            self.client = None
        else:
            self.client = Groq(api_key=self.api_key)
        
        self.model = "llama-3.3-70b-versatile"

    def generate_payload(self, operation_spec: dict, test_type: str = "normal") -> dict:
        """
        Generates a JSON payload based on the OpenAPI operation spec and test type.
        """
        if not self.client:
            return {}

        prompt = self._build_prompt(operation_spec, test_type)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a specialized QA automation expert. Your task is to generate JSON request bodies for API testing based on OpenAPI specifications. Output ONLY valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.7 if test_type == "fuzzing" else 0.2
            )
            
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            logger.error(f"Error generating payload with LLM: {e}")
            return {}

    def _build_prompt(self, spec: dict, test_type: str) -> str:
        spec_str = json.dumps(spec, indent=2)
        
        if test_type == "fuzzing":
            instruction = (
                "Generate a 'fuzzing' payload designed to break the API or reveal vulnerabilities. "
                "This should include boundary cases, incorrect types, extremely long strings, "
                "SQL injection-like patterns, or missing required fields. Be creative but keep it in JSON format."
            )
        else:
            instruction = (
                "Generate a valid, realistic JSON payload that satisfies the requirements of this API operation. "
                "Use appropriate data types and realistic values."
            )
            
        return f"Operation Specification:\n{spec_str}\n\nTask: {instruction}\n\nReturn the payload as a JSON object."

# Singleton instance
llm_client = LLMClient()
