import json
import csv
from pathlib import Path

DIR = Path(__file__).parent
rows = []

for name in ["flask", "django", "fastapi"]:
    data = json.loads((DIR / f"{name}-report.json").read_text(encoding="utf-8"))
    for r in data["results"]:
        rows.append({
            "framework": name,
            "rule_id": r["check_id"],
            "file": r["path"],
            "line": r["start"]["line"],
            "severity": r["extra"]["severity"],
            "message": r["extra"]["message"][:150].replace("\n", " "),
        })

with open(DIR / "semgrep_summary.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["framework", "rule_id", "file", "line", "severity", "message"])
    w.writeheader()
    w.writerows(rows)

print(f"Збережено {len(rows)} знахідок")
