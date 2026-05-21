"""
ai/rewriter.py
Takes vulnerable Python code + vulnerability list and returns a fully
rewritten, secure version with a diff-style explanation.
"""
import json
from ai.groq_llm import groq_chat, _api_key as groq_api_key

SYSTEM = """You are an expert Python security engineer.
Given vulnerable Python code and a list of vulnerabilities, rewrite the ENTIRE code
to be secure. Apply all fixes simultaneously — don't just patch one thing.

Rules:
- Preserve all original functionality
- Add type annotations where helpful
- Add a short docstring noting what was fixed
- Do NOT change the function signatures unless required for security

Respond ONLY with valid JSON (no backticks):
{
  "rewritten_code": "full secure Python code here",
  "changes": [
    {
      "type": "Fixed|Added|Removed|Replaced",
      "description": "What changed and why (one sentence)"
    }
  ],
  "security_score_before": 0-100,
  "security_score_after": 0-100
}"""


async def rewrite_secure(code: str, vulnerabilities: list[dict]) -> dict:
    """
    Returns rewritten code + explanation of changes.
    """
    if not groq_api_key():
        score = max(0, 100 - len(vulnerabilities) * 20)
        return {
            "rewritten_code": code,
            "changes": [
                {
                    "type": "Added",
                    "description": "Configure GROQ_API_KEY to generate an AI secure rewrite.",
                }
            ],
            "security_score_before": score,
            "security_score_after": score,
        }

    vuln_summary = json.dumps(
        [{"title": v.get("title"), "severity": v.get("severity"), "line": v.get("line")}
         for v in vulnerabilities],
        indent=2,
    )

    user = (
        f"Vulnerabilities to fix:\n{vuln_summary}\n\n"
        f"Original code:\n```python\n{code}\n```"
    )

    text = groq_chat(system=SYSTEM, user=user, max_tokens=2048)
    return json.loads(text.replace("```json", "").replace("```", "").strip())
