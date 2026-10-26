"""Create a sample SQLite database full of FAKE customer data for testing."""

import random
import sqlite3
import sys

from faker import Faker

fake = Faker()
Faker.seed(7)
random.seed(7)


def build(path: str, n: int = 50) -> None:
    conn = sqlite3.connect(path)
    conn.executescript("""
        DROP TABLE IF EXISTS customers;
        DROP TABLE IF EXISTS support_tickets;
        CREATE TABLE customers (id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT,
                                ssn TEXT, dob TEXT, address TEXT, plan TEXT);
        CREATE TABLE support_tickets (id INTEGER PRIMARY KEY, customer_id INTEGER, subject TEXT, message TEXT);
    """)
    for i in range(1, n + 1):
        name = fake.name()
        email = fake.email()
        phone = fake.numerify("###-###-####")
        conn.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?,?,?,?)",
            (i, name, email, phone, fake.ssn(), fake.date_of_birth().isoformat(),
             fake.address().replace("\n", ", "), random.choice(["basic", "pro", "enterprise"])),
        )
        message = random.choice([
            f"Hi, this is {name}. Please call me back at {phone} about my bill.",
            f"I can't log in. My email is {email}.",
            f"Card {fake.credit_card_number(card_type='visa16')} was charged twice.",
            "The app crashes when I open settings.",
        ])
        conn.execute("INSERT INTO support_tickets VALUES (?,?,?,?)", (i, i, "Help request", message))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.db"
    build(out)
    print(f"Created {out} with fake data")
