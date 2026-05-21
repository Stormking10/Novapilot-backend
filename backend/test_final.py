#!/usr/bin/env python3
"""Final comprehensive test of OWASPilot backend"""
import asyncio
import httpx

BASE_URL = "http://localhost:8000/api"

async def test_final():
    async with httpx.AsyncClient() as client:
        print("\n" + "=" * 70)
        print("OWASPILOT BACKEND - COMPREHENSIVE TEST SUITE")
        print("=" * 70 + "\n")
        
        results = []
        
        # 1. Health Check
        print("[1/7] Health Check...", end="")
        try:
            r = await client.get(f"{BASE_URL}/health")
            results.append(("Health Check", r.status_code == 200))
            print(f" ✅ (200)")
        except Exception as e:
            results.append(("Health Check", False))
            print(f" ❌ {e}")
        
        # 2. Code Scan
        print("[2/7] Code Vulnerability Scan...", end="")
        try:
            r = await client.post(f"{BASE_URL}/scan", json={
                "code": "import sqlite3\nquery = f'SELECT * FROM users WHERE id = {id}'",
                "language": "python"
            })
            ok = r.status_code == 200 and r.json().get('risk_score')
            results.append(("Code Scan", ok))
            print(f" ✅ (Risk: {r.json().get('risk_score')})" if ok else f" ❌ ({r.status_code})")
        except Exception as e:
            results.append(("Code Scan", False))
            print(f" ❌ {e}")
        
        # 3. Vulnerability Chat
        print("[3/7] Vulnerability-Specific Chat...", end="")
        try:
            r = await client.post(f"{BASE_URL}/chat", json={
                "code": "query = f'SELECT * FROM {table}'",
                "vulnerability_details": "SQL injection",
                "user_question": "How do I fix this?",
                "language": "python"
            }, timeout=30)
            ok = r.status_code == 200 and r.json().get('answer')
            results.append(("Vulnerability Chat", ok))
            print(f" ✅" if ok else f" ❌ ({r.status_code})")
        except Exception as e:
            results.append(("Vulnerability Chat", False))
            print(f" ❌ {e}")
        
        # 4. General Security Chat
        print("[4/7] General Security Assistant...", end="")
        try:
            r = await client.post(f"{BASE_URL}/assistant-chat", json={
                "user_question": "What's the best way to validate input?",
                "include_recent_scans": True
            }, timeout=30)
            ok = r.status_code == 200 and r.json().get('answer')
            results.append(("Security Chat", ok))
            print(f" ✅" if ok else f" ❌ ({r.status_code})")
        except Exception as e:
            results.append(("Security Chat", False))
            print(f" ❌ {e}")
        
        # 5. Scan History
        print("[5/7] Scan History...", end="")
        try:
            r = await client.get(f"{BASE_URL}/history")
            data = r.json()
            # History endpoint returns {"scans": [...]} or a list directly
            scans = data.get('scans', data) if isinstance(data, dict) else data
            ok = r.status_code == 200 and isinstance(scans, list)
            results.append(("Scan History", ok))
            print(f" ✅ ({len(scans)} scans)" if ok else f" ❌ ({r.status_code})")
        except Exception as e:
            results.append(("Scan History", False))
            print(f" ❌ {e}")
        
        # 6. Attack Simulation
        print("[6/7] Attack Walkthrough Simulation...", end="")
        try:
            r = await client.post(f"{BASE_URL}/attack-simulate", json={
                "vulnerability": {
                    "title": "XSS Vulnerability",
                    "severity": "HIGH",
                    "explanation": "Unescaped user input in HTML",
                    "owasp": "A03:2021",
                    "fix": "Escape output"
                }
            }, timeout=30)
            ok = r.status_code == 200 and r.json().get('attack_name')
            results.append(("Attack Simulation", ok))
            print(f" ✅" if ok else f" ❌ ({r.status_code})")
        except Exception as e:
            results.append(("Attack Simulation", False))
            print(f" ❌ {e}")
        
        # 7. Dependency Scanner
        print("[7/7] Dependency CVE Scanner...", end="")
        try:
            r = await client.post(f"{BASE_URL}/dep-scan", json={
                "content": "requests==2.25.0\nflask==1.1.0",
                "filename": "requirements.txt"
            }, timeout=30)
            ok = r.status_code == 200
            results.append(("Dependency Scanner", ok))
            print(f" ✅" if ok else f" ❌ ({r.status_code})")
        except Exception as e:
            results.append(("Dependency Scanner", False))
            print(f" ❌ {e}")
        
        # Summary
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        passed = sum(1 for _, ok in results if ok)
        total = len(results)
        
        for name, ok in results:
            status = "✅ PASS" if ok else "❌ FAIL"
            print(f"{status} | {name}")
        
        print("-" * 70)
        print(f"Total: {passed}/{total} tests passed ({100*passed//total}%)")
        print("=" * 70)
        
        if passed == total:
            print("\n🎉 SUCCESS! OWASPilot backend is fully operational!\n")
        else:
            print(f"\n⚠️  {total - passed} test(s) failed. Check the output above.\n")

if __name__ == "__main__":
    asyncio.run(test_final())
