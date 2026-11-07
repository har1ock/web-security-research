import json
from pathlib import Path

DIR = Path(__file__).parent

for app in ["flask-app", "django-app", "fastapi-app"]:
    data = json.load(open(DIR / f"{app}.json"))
    deps = data.get("dependencies", [])
    seen = set()
    print(f"== {app} ==")
    for d in deps:
        for v in d.get("vulns", []):
            key = (d["name"], d["version"], v["id"])
            if key in seen:
                continue
            seen.add(key)
            desc = v.get("description", "")[:100]
            print(f"  {d['name']} {d['version']}: {v['id']} — {desc}")
