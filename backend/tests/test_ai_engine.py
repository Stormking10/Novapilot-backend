import asyncio
import json
import os
import sys
from unittest.mock import AsyncMock, patch

# Add the current directory to sys.path so we can import 'ai' and 'models'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.explainer import explain_vulnerabilities

# Sample vulnerable code
TEST_CODE = """
import sqlite3

def get_user_data(username):
    db = sqlite3.connect("users.db")
    # VULNERABLE
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query).fetchone()
"""

# Mocked LLM response
MOCK_RESPONSE = {
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "line": "7",
            "owasp": "A03:2021",
            "explanation": "f-string interpolation used for SQL query.",
            "fix": "query = 'SELECT * FROM users WHERE username = ?'"
        }
    ],
    "risk_score": 90,
    "summary": "Critical SQLi found."
}

async def run_test():
    print("Starting AI Engine Logic Test...")
    
    # We mock the internal calls to ensure we're testing our logic, not the API connectivity
    with patch("ai.explainer._call_anthropic", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = json.dumps(MOCK_RESPONSE)
        
        # Patch the module-level constants directly
        with patch("ai.explainer.ANTHROPIC_API_KEY", "test-key"):
            print("--- Analysing Python Code ---")
            result = await explain_vulnerabilities(TEST_CODE, [], language="python")
            
            print(f"DONE Risk Score: {result.get('risk_score')}")
            print(f"DONE Summary: {result.get('summary')}")
            print(f"DONE Findings Count: {len(result.get('vulnerabilities', []))}")
            
            # Verify the structure
            if result.get("risk_score") == 90:
                print("\nTEST PASSED: JSON parsing and validation logic is correct.")
            else:
                print("\nTEST FAILED: Risk score mismatch.")

if __name__ == "__main__":
    asyncio.run(run_test())
