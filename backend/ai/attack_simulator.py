"""
ai/attack_simulator.py
Generates a step-by-step attacker walkthrough for a given vulnerability.
"""
import json
from ai.groq_llm import groq_chat, _api_key as groq_api_key

SYSTEM = """You are a senior penetration tester writing educational attack walkthroughs.
Given a vulnerability, produce a step-by-step explanation of how a real attacker would exploit it.
Keep it educational — no actual malware, just enough detail to help developers understand the risk.

Respond ONLY with valid JSON (no backticks):
{
  "attack_name": "Short name e.g. SQL injection bypass",
  "difficulty": "Easy|Medium|Hard",
  "steps": [
    {
      "number": 1,
      "title": "Reconnaissance",
      "description": "What the attacker does and why",
      "payload": "Optional: example payload or command"
    }
  ],
  "impact": "One sentence on what the attacker gains",
  "mitigations": ["Fix 1", "Fix 2"]
}"""


async def simulate_attack(vulnerability: dict) -> dict:
    """
    vulnerability: dict with keys title, severity, explanation, owasp, fix
    """
    if not groq_api_key():
        return {
            "attack_name": vulnerability.get("title", "Security finding walkthrough"),
            "difficulty": "Medium",
            "steps": [
                {
                    "number": 1,
                    "title": "Identify the vulnerable behavior",
                    "description": vulnerability.get("explanation", "Review the finding and locate the unsafe code path."),
                },
                {
                    "number": 2,
                    "title": "Trace attacker-controlled input",
                    "description": "Follow how user input reaches the affected line and what trust boundary it crosses.",
                },
                {
                    "number": 3,
                    "title": "Apply and verify the mitigation",
                    "description": vulnerability.get("fix", "Apply the recommended fix and rerun the scanner."),
                },
            ],
            "impact": "Impact depends on the vulnerable code path and the data or privileges it can reach.",
            "mitigations": [vulnerability.get("fix", "Apply the recommended secure coding fix.")],
        }

    user = f"Vulnerability:\n{json.dumps(vulnerability, indent=2)}"

    text = groq_chat(system=SYSTEM, user=user, max_tokens=1024)
    
    # Extract JSON from response (handle markdown formatting)
    text = text.strip()
    if text.startswith("```"):
        # Remove leading ```json or ```
        text = text.lstrip("`").lstrip("json").strip()
    if text.endswith("```"):
        text = text.rstrip("`").strip()
    
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # Fallback if LLM returns invalid JSON
        return {
            "attack_name": vulnerability.get("title", "Attack walkthrough"),
            "difficulty": "Medium",
            "steps": [{"number": 1, "title": "Error", "description": f"Failed to parse LLM response: {str(e)}"}],
            "impact": "Unable to generate attack walkthrough",
            "mitigations": [vulnerability.get("fix", "Apply the recommended fix")]
        }
