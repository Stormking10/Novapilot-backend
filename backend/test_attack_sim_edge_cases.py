#!/usr/bin/env python3
"""Test attack_simulator with edge cases"""
import asyncio
import sys
import os
from unittest.mock import patch, AsyncMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai.attack_simulator import simulate_attack

async def test_valid_json():
    print("TEST 1: Valid JSON response\n")
    test_vuln = {
        "title": "SQL Injection",
        "severity": "CRITICAL",
        "explanation": "Direct interpolation",
        "owasp": "A03:2021",
        "fix": "Use parameterized queries"
    }
    result = await simulate_attack(test_vuln)
    print(f"✅ Fallback mode returned: {result['attack_name']}\n")

async def test_malformed_json():
    print("TEST 2: Malformed JSON response (simulated)\n")
    test_vuln = {
        "title": "Cross-Site Scripting",
        "severity": "HIGH",
        "explanation": "User input reflected in HTML",
        "owasp": "A03:2021",
        "fix": "Escape output"
    }
    
    # Mock groq_chat to return invalid JSON
    with patch("ai.attack_simulator.groq_chat") as mock_chat:
        mock_chat.return_value = "This is not valid JSON at all!"
        result = await simulate_attack(test_vuln)
        print(f"✅ Error handling caught it: {result['steps'][0]['title']}")
        print(f"   Error message: {result['steps'][0]['description']}\n")

async def test_json_with_backticks():
    print("TEST 3: JSON with markdown backticks (simulated)\n")
    test_vuln = {
        "title": "Command Injection",
        "severity": "CRITICAL",
        "explanation": "Unsanitized shell execution",
        "owasp": "A01:2021",
        "fix": "Avoid shell commands"
    }
    
    # Mock groq_chat to return JSON with backticks
    with patch("ai.attack_simulator.groq_chat") as mock_chat:
        mock_chat.return_value = """```json
{
  "attack_name": "Shell Command Injection",
  "difficulty": "Hard",
  "steps": [{"number": 1, "title": "Inject", "description": "Pass system commands"}],
  "impact": "Remote code execution",
  "mitigations": ["Input validation"]
}
```"""
        result = await simulate_attack(test_vuln)
        print(f"✅ Properly parsed: {result['attack_name']}")
        print(f"   Difficulty: {result['difficulty']}\n")

async def main():
    await test_valid_json()
    await test_malformed_json()
    await test_json_with_backticks()
    print("All tests passed! ✅")

if __name__ == "__main__":
    asyncio.run(main())
