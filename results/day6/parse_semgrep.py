
import json
import csv
from pathlib import Path

DIR = Path(__file__).parent / "semgrep"
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

custom_path = DIR / "custom-safe-rule.json"
if custom_path.exists():
    data = json.loads(custom_path.read_text(encoding="utf-8"))
    for r in data["results"]:
        framework = "flask" if "flask-app" in r["path"] else "django" if "django-app" in r["path"] else "fastapi"
        rows.append({
            "framework": framework,
            "rule_id": r["check_id"],
            "file": r["path"],
            "line": r["start"]["line"],
            "severity": r["extra"]["severity"],
            "message": "|safe filter in string-literal template",
        })

with open(DIR.parent / "semgrep_summary.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["framework", "rule_id", "file", "line", "severity", "message"])
    w.writeheader()
    w.writerows(rows)

print(f"Збережено {len(rows)} знахідок")