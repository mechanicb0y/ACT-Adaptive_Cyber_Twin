from pathlib import Path

from app.ingestion.parsers.linux_parser import LinuxParser
from app.utils.json_printer import print_json

parser = LinuxParser()

log_file = Path("tests/logs/ssh_failed_login.log")

with log_file.open("r", encoding="utf-8") as file:
    log = file.read().strip()

result = parser.parse(log)

print("=" * 60)
print("Linux Parser Test")
print("=" * 60)

print_json(result)