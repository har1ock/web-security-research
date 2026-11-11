import glob
import json
import re
import numpy as np
import pandas as pd

# Патерн файлів: наприклад, test_greet_k6django-p-greet-run1.json
# Зверніть увагу: якщо у вас є й інші метрики (CPU/RAM), їх можна додати за аналогією
file_pattern = "*.json"

# Словник для групування прогонів по (target, endpoint)
data_groups = {}

for filepath in glob.glob(file_pattern):
    # Приклад зчитування назв із імені файлу:
    # Очікується ім'я типу: test_greet_k6django-p-greet-run1.json або подібне
    # Витягуємо target та endpoint за допомогою регулярного виразу або парсингу назви:
    filename = filepath.replace("\\", "/")
    
    # Спроба витягти target (наприклад, django-p) та endpoint (наприклад, greet)
    match = re.search(r"k6([a-z0-9-]+)-([a-z0-9]+)-run\d+\.json", filename)
    if not match:
        continue
    
    target, endpoint = match.group(1), match.group(2)
    key = (target, endpoint)

    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception:
            continue

    metrics = data.get("metrics", {})
    
    # Витягуємо метрики k6
    rps = metrics.get("http_reqs", {}).get("rate", 0)
    p95 = metrics.get("http_req_duration", {}).get("p(95)", 0)
    avg_ms = metrics.get("http_req_duration", {}).get("avg", 0)
    
    # fail_rate
    fail_rate = metrics.get("http_req_failed", {}).get("value", 0)
    
    # CPU та Memory (якщо ви їх вигружаєте в k6 json як custom metrics)
    # Якщо ні — залишаться 0.0 або додайте інтеграцію з docker stats
    cpu_pct = metrics.get("cpu_pct", {}).get("value", 0.0)
    mem_mb = metrics.get("mem_mb", {}).get("value", 0.0)

    if key not in data_groups:
        data_groups[key] = {
            "rps": [],
            "p95": [],
            "avg_ms": [],
            "fail_rate": [],
            "cpu_pct": [],
            "mem_mb": []
        }

    data_groups[key]["rps"].append(rps)
    data_groups[key]["p95"].append(p95)
    data_groups[key]["avg_ms"].append(avg_ms)
    data_groups[key]["fail_rate"].append(fail_rate)
    data_groups[key]["cpu_pct"].append(cpu_pct)
    data_groups[key]["mem_mb"].append(mem_mb)

# Формуємо підсумкові рядки
rows = []
for (target, endpoint), values in data_groups.items():
    rows.append({
        "target": target,
        "endpoint": endpoint,
        "rps_avg": round(np.mean(values["rps"]), 3),
        "rps_std": round(np.std(values["rps"], ddof=1) if len(values["rps"]) > 1 else 0.0, 3),
        "p95_ms_avg": round(np.mean(values["p95"]), 3),
        "p95_ms_std": round(np.std(values["p95"], ddof=1) if len(values["p95"]) > 1 else 0.0, 3),
        "avg_ms_avg": round(np.mean(values["avg_ms"]), 3),
        "fail_rate_avg": round(np.mean(values["fail_rate"]), 3),
        "cpu_pct_avg": round(np.mean(values["cpu_pct"]), 3),
        "mem_mb_avg": round(np.mean(values["mem_mb"]), 3)
    })

df = pd.DataFrame(rows)

# Вивід у консоль CSV-формату
print(df.to_csv(index=False))

# Збереження у файл summary.csv
df.to_csv("summary.csv", index=False)