#!/usr/bin/env python3
"""Test the running OWASPilot backend API"""
import asyncio
import httpx
import json

BASE_URL = "http://localhost:8000/api"

async def test_endpoints():
    async with httpx.AsyncClient() as client:
        # Test 1: Health check
        print("=" * 50)
        print("TEST 1: Health Check")
        print("=" * 50)
        try:
            response = await client.get(f"{BASE_URL}/health")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.json()}\n")
        except Exception as e:
            print(f"❌ Error: {e}\n")
        
        # Test 2: Scan endpoint
        print("=" * 50)
        print("TEST 2: Scan Python Code for Vulnerabilities")
        print("=" * 50)
        payload = {
            "code": """
import sqlite3

def get_user(username):
    db = sqlite3.connect("app.db")
    # VULNERABLE: Direct string interpolation in SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query).fetchone()
            """,
            "language": "python"
        }
        try:
            response = await client.post(f"{BASE_URL}/scan", json=payload)
            print(f"Status: {response.status_code}")
            result = response.json()
            print(f"Risk Score: {result.get('risk_score')}")
            print(f"Summary: {result.get('summary')}")
            if result.get('vulnerabilities'):
                print(f"Findings: {len(result['vulnerabilities'])} vulnerabilities detected")
                for vuln in result['vulnerabilities'][:2]:
                    print(f"  - {vuln.get('title')} ({vuln.get('severity')})")
            print()
        except Exception as e:
            print(f"❌ Error: {e}\n")

if __name__ == "__main__":
    asyncio.run(test_endpoints())
