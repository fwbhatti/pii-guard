"""Ways to protect detected PII: full redaction, partial masking, or realistic fake values."""

from faker import Faker

fake = Faker()
Faker.seed(42)

SYNTHETIC = {
    "NAME": fake.name,
    "EMAIL": fake.email,
    "PHONE": fake.phone_number,
    "SSN": fake.ssn,
    "ADDRESS": lambda: fake.address().replace("\n", ", "),
    "DATE_OF_BIRTH": lambda: fake.date_of_birth().isoformat(),
    "CREDIT_CARD": fake.credit_card_number,
    "IP_ADDRESS": fake.ipv4,
}


def redact(value: str, pii_type: str) -> str:
    return f"[{pii_type}]"


def partial(value: str, pii_type: str) -> str:
    """Keep the last 4 characters, mask the rest."""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def synthetic(value: str, pii_type: str) -> str:
    """Replace with a realistic fake value so test data still looks real."""
    generator = SYNTHETIC.get(pii_type)
    return generator() if generator else redact(value, pii_type)


STRATEGIES = {"redact": redact, "partial": partial, "synthetic": synthetic}


def mask_text(text: str, findings: list[dict], strategy: str = "synthetic") -> str:
    """Replace every finding in the text using the chosen strategy."""
    if not isinstance(text, str):
        return text
    fn = STRATEGIES[strategy]
    for f in sorted(findings, key=lambda f: len(f["value"]), reverse=True):
        text = text.replace(f["value"], fn(f["value"], f["type"]))
    return text
