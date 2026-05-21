"""
Shared Groq chat helper — keeps model name and API shape in one place.
"""
import os
from groq import Groq

DEFAULT_MODEL = "llama-3.3-70b-versatile"


def _api_key() -> str:
    return os.getenv("GROQ_API_KEY", "").strip()


def _model() -> str:
    return os.getenv("GROQ_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def groq_chat(
    *,
    system: str,
    user: str,
    max_tokens: int = 4096,
    temperature: float = 0,
) -> str:  # Return type: str
    client = Groq(api_key=_api_key())
    message = client.chat.completions.create(
        model=_model(),
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return message.choices[0].message.content or ""
