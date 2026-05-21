#!/usr/bin/env python3
"""Quick test of attack_simulator.py"""
import asyncio
import sys
import os

# Add backend dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai.attack_simulator import simulate_attack

async def main():
    # Test vulnerability
    test_vuln = {
        "title": "SQL Injection in User Login",
        "severity": "CRITICAL",
        "explanation": "User input is directly interpolated into SQL query without parameterization",
        "owasp": "A03:2021 – Injection",
        "fix": "Use parameterized queries with placeholders (?). Example: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
    }
    
    print("🔍 Testing attack_simulator.simulate_attack()...\n")
    print(f"Input vulnerability: {test_vuln['title']}\n")
    
    result = await simulate_attack(test_vuln)
    
    print("📋 Attack Walkthrough:\n")
    print(f"Attack Name: {result.get('attack_name')}")
    print(f"Difficulty: {result.get('difficulty')}")
    print(f"Impact: {result.get('impact')}\n")
    
    print("Steps:")
    for step in result.get('steps', []):
        print(f"  {step.get('number')}. {step.get('title')}")
        print(f"     {step.get('description')}")
        if step.get('payload'):
            print(f"     Payload: {step.get('payload')}")
    
    print(f"\nMitigations:")
    for mitigation in result.get('mitigations', []):
        print(f"  • {mitigation}")

if __name__ == "__main__":
    asyncio.run(main())
