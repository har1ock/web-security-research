import pandas as pd
from pathlib import Path

# Налаштування шляхів
ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"

print("=== 1. Завантаження даних ===")
security = pd.read_csv(RESULTS / "day4" / "security.csv")
zap = pd.read_csv(RESULTS / "day6" / "zap_summary.csv")
semgrep = pd.read_csv(RESULTS / "day6" / "semgrep_summary.csv")
performance = pd.read_csv(RESULTS / "day7" / "performance.csv")

print("=== 2. Базова перевірка security.csv ===")
print("Shape:", security.shape)
print("Verdicts:", security['verdict'].unique())

if 'error' in security['verdict'].unique():
    print("УВАГА: Знайдено 'error' у вердиктах! Зупиніться та перевірте дані.")

# Відділяємо атаки від легітимних перевірок
is_legit = security["test_id"].str.startswith("LEGIT-")
attacks = security[~is_legit].copy()
legit = security[is_legit].copy()

print("\n=== 3. Розрахунок ASR / PR ===")
def asr_pr_table(df, group_cols):
    g = df.groupby(group_cols)["verdict"].value_counts().unstack(fill_value=0)
    for col in ["success", "blocked"]:
        if col not in g.columns:
            g[col] = 0
    total = g["success"] + g["blocked"]
    g["ASR_%"] = (g["success"] / total * 100).round(1)
    g["PR_%"] = (g["blocked"] / total * 100).round(1)
    g["n"] = total
    return g.reset_index()

asr_by_attack = asr_pr_table(attacks, ["framework", "mode", "attack"])
asr_by_attack.to_csv(RESULTS / "day8_asr_by_attack.csv", index=False)

asr_by_mode = asr_pr_table(attacks, ["framework", "mode"])
print(asr_by_mode.to_string(index=False))
asr_by_mode.to_csv(RESULTS / "day8_asr_by_mode.csv", index=False)

print("\n=== 4. Розрахунок FPR для легітимних запитів ===")
def fpr_table(df, group_cols):
    g = df.groupby(group_cols)["verdict"].value_counts().unstack(fill_value=0)
    for col in ["ok", "broken"]:
        if col not in g.columns:
            g[col] = 0
    total = g["ok"] + g["broken"]
    g["FPR_%"] = (g["broken"] / total * 100).round(1)
    g["n"] = total
    return g.reset_index()

fpr_by_mode = fpr_table(legit, ["framework", "mode"])
print(fpr_by_mode.to_string(index=False))
fpr_by_mode.to_csv(RESULTS / "day8_fpr.csv", index=False)

broken_legit = legit[legit["verdict"] == "broken"]
if not broken_legit.empty:
    print("\nЗнайдено зламані легітимні запити:")
    print(broken_legit[["framework", "mode", "test_id"]])

print("\n=== 5. Зведення ZAP і Semgrep ===")
zap_counts = zap.groupby(["target", "risk"]).size().unstack(fill_value=0)
for col in ["High", "Medium", "Low", "Informational"]:
    if col not in zap_counts.columns:
        zap_counts[col] = 0
zap_counts = zap_counts[["High", "Medium", "Low", "Informational"]]
print(zap_counts)
zap_counts.to_csv(RESULTS / "day8_zap_counts.csv")

semgrep_counts = semgrep.groupby(["framework", "severity"]).size().unstack(fill_value=0)
print(semgrep_counts)
semgrep_counts.to_csv(RESULTS / "day8_semgrep_counts.csv")

print("\n=== 6. Розрахунок продуктивності (Performance Overhead) ===")
perf = performance.copy()
perf["framework"] = perf["target"].str.replace("-v", "").str.replace("-p", "")
perf["mode"] = perf["target"].apply(lambda t: "vulnerable" if t.endswith("-v") else "secure")

pivot = perf.pivot_table(index=["framework", "endpoint"], columns="mode",
                           values=["rps_avg", "p95_ms_avg"])

pivot["RPS_overhead_%"] = (
    (pivot[("rps_avg", "secure")] - pivot[("rps_avg", "vulnerable")]) 
    / pivot[("rps_avg", "vulnerable")] * 100
).round(1)

pivot["p95_overhead_%"] = (
    (pivot[("p95_ms_avg", "secure")] - pivot[("p95_ms_avg", "vulnerable")]) 
    / pivot[("p95_ms_avg", "vulnerable")] * 100
).round(1)

print(pivot[["RPS_overhead_%", "p95_overhead_%"]])
pivot.to_csv(RESULTS / "day8_performance_overhead.csv")

print("\nУсі розрахунки завершено, звіти збережено у папці results/!")