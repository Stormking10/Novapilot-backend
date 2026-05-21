"""
ai/explainer.py
Uses Groq LLM to explain vulnerabilities and generate secure fixes.
Set GROQ_API_KEY in your .env
"""
import os
import json
import logging
from typing import Optional, List
from pydantic import ValidationError
from models.scan import Vulnerability, Severity, Language
from ai.groq_llm import groq_chat, _api_key as groq_api_key

# Setup logging
logger = logging.getLogger("novapilot.ai")

SYSTEM_PROMPT = """You are Novapilot, a world-class security researcher and secure-code reviewer.
Your goal is to perform a deep analysis of the provided source code and Semgrep findings.

### MISSION:
1. Identify all security vulnerabilities, including those Semgrep might have missed.
2. For each vulnerability, provide a clear, technical explanation of the root cause and the potential impact.
3. Provide a production-ready, secure code fix that follows best practices for the specific language.
4. Assign an overall Risk Score (0-100) based on the most critical findings.

### RESPONSE FORMAT:
You MUST respond with valid JSON only. Do not include any conversational text, markdown, or backticks outside the JSON.
Follow this schema:
{
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "title": "Short descriptive title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "line": "line number or range",
      "owasp": "OWASP category e.g. A03:2021",
      "explanation": "Detailed technical explanation",
      "fix": "Corrected code snippet"
    }
  ],
  "risk_score": 85,
  "summary": "One-line high-level summary of the security state"
}"""

# Language-specific security contexts to guide the LLM
SECURITY_CONTEXTS = {
    "python": "Focus on: SQL injection in f-strings, insecure deserialization (pickle), hardcoded secrets, and unsafe subprocess calls.",
    "javascript": "Focus on: DOM-based XSS, prototype pollution, insecure dependencies, and hardcoded JWT secrets.",
    "typescript": "Focus on: Type-safety bypasses, XSS in React/Angular components, and insecure API handling.",
    "go": "Focus on: Proper error handling in security-critical paths, goroutine leaks, and SQL injection in database/sql.",
    "java": "Focus on: Log4Shell-style injection, XML External Entity (XXE), and insecure Spring Security configurations.",
    "csharp": "Focus on: ASP.NET Core security misconfigurations, insecure deserialization, and SQL injection in Entity Framework."
}

async def explain_vulnerabilities(
    code: str,
    semgrep_findings: List[dict],
    language: str = "python",
) -> dict:
    """
    Calls Groq LLM to explain vulnerabilities and returns a parsed response.
    """
    context = SECURITY_CONTEXTS.get(language, "General security audit.")
    user_content = _build_user_message(code, semgrep_findings, language, context)

    try:
        if not groq_api_key():
            return _fallback_response(semgrep_findings)

        raw_response = await _call_groq(user_content)

        # Basic JSON parsing
        data = _parse_llm_response(raw_response)
        
        # Validation (Optional: we could validate individual vulns here)
        return data

    except Exception as e:
        logger.error(f"AI Analysis failed: {str(e)}")
        return _fallback_response(semgrep_findings, error=str(e))


def _build_user_message(code: str, findings: List[dict], language: str, context: str) -> str:
    findings_block = json.dumps(findings, indent=2) if findings else "[]"
    return (
        f"Language: {language}\n"
        f"Security Context: {context}\n\n"
        f"Semgrep Findings:\n{findings_block}\n\n"
        f"Source Code:\n```{language}\n{code}\n```"
    )


async def _call_groq(user_content: str) -> str:
    """Call Groq API synchronously."""
    return groq_chat(system=SYSTEM_PROMPT, user=user_content, max_tokens=4096)





def _parse_llm_response(text: str) -> dict:
    """Robust JSON extraction."""
    # Attempt to find JSON block if LLM included conversational text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        text = text[start:end+1]
    
    return json.loads(text)


def _fallback_response(findings: List[dict], error: str = None) -> dict:
    """Used when LLM fails or no key is configured."""
    vulns = []
    for i, f in enumerate(findings):
        vulns.append({
            "id": f"vuln-{i+1}",
            "title": f.get("rule_id", "Security Finding"),
            "severity": f.get("severity", "INFO"),
            "line": f.get("line", "?"),
            "owasp": f.get("owasp"),
            "explanation": f.get("message", "AI analysis unavailable."),
            "fix": "# Configure GROQ_API_KEY for AI-generated fixes.",
        })
    
    summary = "Semgrep analysis complete."
    if error:
        summary = f"AI analysis failed: {error[:50]}..."
    elif not groq_api_key():
        summary = "No Groq API key configured. Using static analysis only."

    return {
        "vulnerabilities": vulns,
        "risk_score": len(findings) * 10 if findings else 0,
        "summary": summary
    }

async def chat_about_vulnerability(
    code: str,
    vulnerability_details: str,
    user_question: str,
    language: str = "python"
) -> str:
    """
    Handles conversational follow-ups about a specific vulnerability.
    """
    if not groq_api_key():
        return "AI Chat is unavailable. Please configure GROQ_API_KEY in the backend environment."

    system_prompt = (
        "You are Novapilot, an expert security mentor. "
        "A user is asking a question about a security vulnerability found in their code. "
        "Be technical, clear, and educational. Help them understand the risk and the solution."
    )
    
    user_content = (
        f"Context (Original Code):\n```{language}\n{code}\n```\n\n"
        f"Vulnerability being discussed:\n{vulnerability_details}\n\n"
        f"User Question: {user_question}"
    )

    try:
        return groq_chat(system=system_prompt, user=user_content, max_tokens=1024)

    except Exception as e:
        logger.error(f"AI Chat failed: {str(e)}")
        return f"I'm sorry, I encountered an error while trying to process your request: {str(e)}"


async def general_security_chat(
    user_question: str,
    recent_scans: list[dict] | None = None,
) -> str:
    """
    Handles general app-wide security assistant questions.
    """
    if not groq_api_key():
        return (
            "I can help as a local security guide, but live AI is not configured yet. "
            "Add GROQ_API_KEY to the backend .env file for full chatbot answers. "
            "For now, paste code into Scanner, review high-severity findings first, and use parameterized queries, safe auth checks, and dependency scanning as your baseline."
        )

    system_prompt = (
        "You are Novapilot, an AI security copilot for mobile developers and app security learners. "
        "Answer practical secure-coding, OWASP, dependency, and code-review questions. "
        "Be concise, actionable, and educational. If recent scan context is supplied, use it to tailor advice."
    )
    scan_context = json.dumps((recent_scans or [])[:3], indent=2)
    user_content = (
        f"Recent scan context:\n{scan_context}\n\n"
        f"User question: {user_question}"
    )

    try:
        return groq_chat(system=system_prompt, user=user_content, max_tokens=1200)

    except Exception as e:
        logger.error(f"General AI Chat failed: {str(e)}")
        return f"I'm sorry, I could not reach the AI assistant: {str(e)}"
