"""Optional LLM-based PII detection for free text, using a local Ollama model.

Running the model locally means sensitive data never leaves the machine.
If Ollama is not running, detection falls back to rules only.

Debug a single sentence:
    python -m pii_guard.llm "Hi, this is Jane Doe. Call me at 703-555-1234."
"""

import json
import sys

import requests

OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.2"

SYSTEM = (
    "You are the detection step of a data-masking tool. You read text and list every piece of "
    "personally identifiable information (PII) so it can be redacted. PII types: NAME (any person's "
    "name), ADDRESS, EMAIL, PHONE, SSN, DATE_OF_BIRTH, OTHER. Copy each value exactly as written. "
    "If there is no PII, return an empty list."
)

EXAMPLE_IN = "Thanks, this is John Smith. Ship it to 12 Oak St, Fairfax, VA or call 571-555-0199."
EXAMPLE_OUT = json.dumps({"entities": [
    {"type": "NAME", "value": "John Smith"},
    {"type": "ADDRESS", "value": "12 Oak St, Fairfax, VA"},
    {"type": "PHONE", "value": "571-555-0199"},
]})

SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"type": {"type": "string"}, "value": {"type": "string"}},
                "required": ["type", "value"],
            },
        }
    },
    "required": ["entities"],
}


def is_available(timeout: float = 2.0) -> bool:
    """Return True if a local Ollama server is reachable."""
    try:
        return requests.get("http://localhost:11434/api/tags", timeout=timeout).ok
    except requests.RequestException:
        return False


def parse_response(raw: str) -> list[dict]:
    """Pull PII entities out of the model's reply.

    Accepts {"entities": [...]}, any object holding a list, or a bare list.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        start, end = (raw or "").find("["), (raw or "").rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            data = json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            return []
    if isinstance(data, dict):
        data = data.get("entities") or next((v for v in data.values() if isinstance(v, list)), [])
    if not isinstance(data, list):
        return []
    items = []
    for item in data:
        if isinstance(item, dict) and item.get("type") and item.get("value"):
            items.append({"type": str(item["type"]).upper(), "value": str(item["value"]).strip()})
    return items


def query(text: str, model: str = DEFAULT_MODEL, timeout: float = 180.0) -> str:
    """Send one request to Ollama and return the raw text reply."""
    response = requests.post(
        OLLAMA_CHAT_URL,
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": EXAMPLE_IN},
                {"role": "assistant", "content": EXAMPLE_OUT},
                {"role": "user", "content": text},
            ],
            "stream": False,
            "format": SCHEMA,
            "options": {"temperature": 0},
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json().get("message", {}).get("content", "")


def find_pii_llm(text: str, model: str = DEFAULT_MODEL) -> list[dict]:
    """Ask the local model which parts of the text are PII. Keeps only values found in the text."""
    if not isinstance(text, str) or not text.strip():
        return []
    try:
        raw = query(text, model)
    except requests.RequestException as err:
        print(f"[pii-guard] LLM request failed: {err}", file=sys.stderr)
        return []
    return [i for i in parse_response(raw) if i["value"] and i["value"] in text]


if __name__ == "__main__":
    sample = " ".join(sys.argv[1:]) or "Hi, this is Jane Doe. Please call me at 703-555-1234."
    print("Ollama running:", is_available())
    raw = query(sample)
    print("Raw model reply:", raw)
    print("Parsed findings:", find_pii_llm(sample))
