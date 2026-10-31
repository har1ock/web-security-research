import json
import csv
import statistics
from pathlib import Path

K6_DIR = Path("results/day7/k6")
STATS_DIR = Path("results/day7/stats")
OUT = Path("results/day7/performance.csv")

TARGETS = ["flask-v", "flask-p", "django-v", "django-p", "fastapi-v", "fastapi-p"]
ENDPOINTS = ["search", "greet"]
RUNS_TO_KEEP = [2, 3, 4, 5]  # прогін 1 відкидаємо як прогрів


def parse_mem(mem_usage: str):
    # формат docker stats: "123.4MiB / 512MiB" -> беремо перше число
    used = mem_usage.split("/")[0].strip()
    try:
        if "GiB" in used:
            return float(used.replace("GiB", "")) * 1024
        if "MiB" in used:
            return float(used.replace("MiB", ""))
        if "KiB" in used:
            return float(used.replace("KiB", "")) / 1024
    except ValueError:
        return None
    return None


def avg(lst):
    return round(statistics.mean(lst), 3) if lst else None


def std(lst):
    return round(statistics.stdev(lst), 3) if len(lst) > 1 else None


rows = []
for target in TARGETS:
    for endpoint in ENDPOINTS:
        rps_vals, p95_vals, avg_ms_vals, fail_vals = [], [], [], []
        cpu_vals, mem_vals = [], []

        for run in RUNS_TO_KEEP:
            summary_path = K6_DIR / f"{target}-{endpoint}-run{run}.json"
            if not summary_path.exists():
                print(f"немає {summary_path}, пропускаю")
                continue
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            m = data.get("metrics", {})
            try:
                rps_vals.append(m["http_reqs"]["rate"])
                p95_vals.append(m["http_req_duration"]["p(95)"])
                avg_ms_vals.append(m["http_req_duration"]["avg"])
                fail_vals.append(m["http_req_failed"]["value"])
            except KeyError as e:
                print(f"!! несподівана структура JSON у {summary_path}: немає ключа {e}")
                continue

            stats_path = STATS_DIR / f"{target}-{endpoint}-run{run}.csv"
            if stats_path.exists():
                with open(stats_path, encoding="utf-8") as f:
                    for r in csv.DictReader(f):
                        try:
                            cpu_vals.append(float(r["cpu_perc"].strip().rstrip("%")))
                        except (ValueError, KeyError):
                            pass
                        mem_mb = parse_mem(r.get("mem_usage", ""))
                        if mem_mb is not None:
                            mem_vals.append(mem_mb)

        rows.append({
            "target": target,
            "endpoint": endpoint,
            "rps_avg": avg(rps_vals), "rps_std": std(rps_vals),
            "p95_ms_avg": avg(p95_vals), "p95_ms_std": std(p95_vals),
            "avg_ms_avg": avg(avg_ms_vals),
            "fail_rate_avg": avg(fail_vals),
            "cpu_pct_avg": avg(cpu_vals),
            "mem_mb_avg": avg(mem_vals),
        })

with open(OUT, "w", newline="", encoding="utf-8") as f:
    fieldnames = list(rows[0].keys())
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)

print(f"Записано {len(rows)} рядків у {OUT}")
