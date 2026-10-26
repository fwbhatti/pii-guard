"""Optional LLM-based PII detection for free text, using a local Ollama model.

Running the model locally means sensitive data never leaves the machine.
If Ollama is not running, detection falls back to rules only.
"""

import json

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"

PROMPT = """You are a data privacy tool. Find personally identifiable information (PII) in the text below.
Return ONLY a JSON list. Each item must have "type" (NAME, ADDRESS, EMAIL, PHONE, SSN, DATE_OF_BIRTH, or OTHER) and "value" (the exact text).
Return [] if there is no PII.

Text: {text}
"""


def is_available(timeout: float = 2.0) -> bool:
    """Return True if a local Ollama server is reachable."""
    try:
        return requests.get("http://localhost:11434/api/tags", timeout=timeout).ok
    except requests.RequestException:
        return False


def parse_response(raw: str) -> list[dict]:
    """Pull a JSON list out of the model's reply, ignoring extra text."""
    start, end = raw.find("["), raw.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        items = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return []
    return [i for i in items if isinstance(i, dict) and "type" in i and "value" in i]


def find_pii_llm(text: str, model: str = "llama3.2", timeout: float = 60.0) -> list[dict]:
    """Ask the local model which parts of the text are PII."""
    if not isinstance(text, str) or not text.strip():
        return []
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": model, "prompt": PROMPT.format(text=text), "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException:
        return []
    return [i for i in parse_response(response.json().get("response", "")) if i["value"] in text]
