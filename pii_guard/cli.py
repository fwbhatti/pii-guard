"""Command-line interface: python -m pii_guard.cli scan|sanitize ..."""

import argparse
import json

from . import llm
from .scanner import sanitize, scan


def main(argv=None):
    parser = argparse.ArgumentParser(description="Find and protect PII in SQLite databases.")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Report which columns contain PII")
    s.add_argument("db")
    s.add_argument("--llm", action="store_true", help="Also use a local Ollama model for free text")
    s.add_argument("--out", help="Save the report as JSON")

    z = sub.add_parser("sanitize", help="Write a copy of the database with PII masked")
    z.add_argument("db")
    z.add_argument("out")
    z.add_argument("--strategy", choices=["redact", "partial", "synthetic"], default="synthetic")
    z.add_argument("--llm", action="store_true")

    args = parser.parse_args(argv)
    use_llm = args.llm and llm.is_available()
    if args.llm and not use_llm:
        print("Ollama not reachable at localhost:11434, using rules only.")

    if args.command == "scan":
        report = scan(args.db, use_llm=use_llm)
        text = json.dumps(report, indent=2)
        print(text)
        if args.out:
            with open(args.out, "w") as f:
                f.write(text)
    else:
        n = sanitize(args.db, args.out, strategy=args.strategy, use_llm=use_llm)
        print(f"Masked {n} values. Sanitized copy saved to {args.out}")


if __name__ == "__main__":
    main()
