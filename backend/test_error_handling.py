#!/usr/bin/env python3
"""Test attack_simulator error handling more precisely"""
import asyncio
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai.attack_simulator import simulate_attack

async def test_json_error_handling():
    print("TEST: JSON parsing error handling\n")
    test_vuln = {
        "title": "XSS Vulnerability",
        "severity": "HIGH",
        "explanation": "Unescaped user input",
        "owasp": "A07:2021",
        "fix": "Escape HTML"
    }
    
    # Mock BOTH groq_api_key AND groq_chat to force the JSON parsing path
    with patch("ai.attack_simulator.groq_api_key") as mock_key:
        mock_key.return_value = "dummy-key"  # Pretend key exists
        
        with patch("ai.attack_simulator.groq_chat") as mock_chat:
            # Return invalid JSON
            mock_chat.return_value = "{ broken json without proper quotes }"
            
            result = await simulate_attack(test_vuln)
            print(f"Response attack_name: {result['attack_name']}")
            print(f"First step: {result['steps'][0]['title']}")
            
            if "Error" in result['steps'][0]['title'] or "Failed" in result['steps'][0]['description']:
                print("✅ Error handling works! Invalid JSON triggered fallback.\n")
            else:
                print("❌ Error not properly handled\n")

async def test_markdown_stripping():
    print("TEST: Markdown backtick stripping\n")
    
    with patch("ai.attack_simulator.groq_api_key") as mock_key:
        mock_key.return_value = "dummy-key"
        
        with patch("ai.attack_simulator.groq_chat") as mock_chat:
            # Return valid JSON with markdown
            mock_chat.return_value = """```json
{
  "attack_name": "CORS Bypass",
  "difficulty": "Medium",
  "steps": [{"number": 1, "title": "Test", "description": "desc"}],
  "impact": "Unauthorized access",
  "mitigations": ["Fix CORS policy"]
}
```"""
            
            result = await simulate_attack(test_vuln)
            if result['attack_name'] == "CORS Bypass":
                print("✅ Markdown stripping works! Correctly parsed JSON\n")
            else:
                print(f"❌ Got: {result['attack_name']}\n")

if __name__ == "__main__":
    test_vuln = {"title": "Test", "severity": "HIGH", "explanation": "test", "owasp": "A01", "fix": "fix"}
    asyncio.run(test_json_error_handling())
    asyncio.run(test_markdown_stripping())
