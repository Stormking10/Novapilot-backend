#!/usr/bin/env python3
"""Debug the Scan History endpoint"""
import asyncio
import httpx
import json

BASE_URL = "http://localhost:8000/api"

async def debug_history():
    async with httpx.AsyncClient() as client:
        print("Testing Scan History endpoint...\n")
        r = await client.get(f"{BASE_URL}/history")
        print(f"Status: {r.status_code}")
        print(f"Response type: {type(r.json())}")
        print(f"Response: {json.dumps(r.json(), indent=2)[:500]}")

if __name__ == "__main__":
    asyncio.run(debug_history())
