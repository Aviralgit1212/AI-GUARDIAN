from pathlib import Path

from extraction.extraction import extract_text


pdf_path = Path("AI_Guardian_Test.pdf")
pdf_bytes = pdf_path.read_bytes()

text = extract_text(
    pdf_bytes,
    pdf_path.name,
)

print("=== EXTRACTED TEXT ===")
print(text)

print("\n=== CHECKS ===")

required_values = [
    "john@example.com",
    "555-123-4567",
    "4111 1111 1111 1111",
    "234-56-7890",
]

for value in required_values:
    status = "FOUND" if value in text else "MISSING"
    print(f"{value}: {status}")
