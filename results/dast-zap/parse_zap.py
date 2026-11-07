import json
from pathlib import Path
import csv

ZAP_DIR = Path(__file__).parent / "zap"
OUT_CSV = Path(__file__).parent / "zap_summary.csv"

TARGETS = ["flask-v", "flask-p", "django-v", "django-p", "fastapi-v", "fastapi-p"]

rows = []
for name in TARGETS:
    path = ZAP_DIR / f"{name}-api.json"
    if not path.exists():
        print(f"немає звіту для {name}, пропускаю")
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            rows.append({
                "target": name,
                "alert": alert["name"],
                "risk": alert["riskdesc"].split(" ")[0],  # "High (Medium)" -> "High"
                "confidence": alert.get("confidence", ""),
                "count": int(alert.get("count", len(alert.get("instances", [])))),
                "cwe_id": alert.get("cweid", ""),
            })

with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["target", "alert", "risk", "confidence", "count", "cwe_id"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Збережено {len(rows)} знахідок у {OUT_CSV}")