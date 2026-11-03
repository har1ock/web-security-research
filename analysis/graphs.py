import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

RESULTS = Path(__file__).parent.parent / "results"
GRAPHS = Path(__file__).parent / "graphs"
GRAPHS.mkdir(exist_ok=True)

plt.rcParams["figure.dpi"] = 120

#Перший графік
bypass_data = {
    "flask":   {"absent": 4, "bypassed": 2, "weakened": 1},
    "django":  {"absent": 2, "bypassed": 4, "weakened": 1},
    "fastapi": {"absent": 4, "bypassed": 2, "weakened": 1},
}
frameworks = ["flask", "django", "fastapi"]
categories = ["absent", "bypassed", "weakened"]
colors = {"absent": "#7f7f7f", "bypassed": "#d62728", "weakened": "#ff9800"}

fig, ax = plt.subplots(figsize=(7, 4.5))
bottom = [0] * len(frameworks)
for cat in categories:
    vals = [bypass_data[f][cat] for f in frameworks]
    bars = ax.bar(frameworks, vals, bottom=bottom, label=cat, color=colors[cat])
    for i, (v, b) in enumerate(zip(vals, bottom)):
        if v > 0:
            ax.text(i, b + v / 2, str(v), ha="center", va="center", color="white", fontweight="bold")
    bottom = [b + v for b, v in zip(bottom, vals)]

ax.set_ylabel("Кількість вразливостей")
ax.set_title("Як саме створено вразливість у Vulnerable-режимі")
ax.set_xticks(range(len(frameworks)))
ax.set_xticklabels([f.capitalize() for f in frameworks])
ax.legend(title="Тип", loc="upper right")
plt.tight_layout()
plt.savefig(GRAPHS / "01_bypass_type.png")
plt.close()

# Другий графік
# Другий графік (виправлений)
asr_attack = pd.read_csv(RESULTS / "day8_asr_by_attack.csv")

categories = sorted(asr_attack["attack"].unique())
fig, ax = plt.subplots(figsize=(10, 5))

x = range(len(categories))
width = 0.12
# 6 комбінацій: 3 фреймворки * 2 режими
combos = [
    ("flask", "vulnerable"), ("flask", "secure"),
    ("django", "vulnerable"), ("django", "secure"),
    ("fastapi", "vulnerable"), ("fastapi", "secure")
]
offsets = [-2.5, -1.5, -0.5, 0.5, 1.5, 2.5]

colors_combo = {"vulnerable": "#d62728", "secure": "#2ca02c"}
hatches = {"flask": "", "django": "//", "fastapi": ".."}

for (fw, mode), off in zip(combos, offsets):
    vals = []
    for cat in categories:
        row = asr_attack[
            (asr_attack.framework == fw) & 
            (asr_attack["mode"] == mode) & 
            (asr_attack.attack == cat)
        ]
        # Якщо значення 0, ставимо трохи більше 0 (наприклад, 0.5), 
        # щоб стовпчик був видимим на графіку біля осі X
        val = row["ASR_%"].iloc[0] if not row.empty else 0
        if val == 0 and mode == "secure":
            val = 0.5  # Візуальна підказка для нульового ASR
        vals.append(val)
    
    ax.bar(
        [i + off * width for i in x], vals, width,
        color=colors_combo[mode], 
        hatch=hatches[fw],
        label=f"{fw}/{mode}"
    )

ax.set_xticks(list(x))
ax.set_xticklabels(categories, rotation=30, ha="right")
ax.set_ylabel("Attack Success Rate, %")
ax.set_title("ASR за категоріями атак: Vulnerable vs Secure, усі фреймворки")

# Легенда компактно збоку
ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", fontsize=8)
plt.tight_layout()
plt.savefig(GRAPHS / "02_asr_by_attack_both_modes.png")
plt.close()

# Третій графік
perf = pd.read_csv(RESULTS / "day7" / "performance.csv")
perf["framework"] = perf["target"].str.replace("-v", "").str.replace("-p", "")
perf["mode"] = perf["target"].apply(lambda t: "vulnerable" if t.endswith("-v") else "secure")

fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharey=False)
for ax, endpoint in zip(axes, ["search", "greet"]):
    sub = perf[perf["endpoint"] == endpoint]
    pv = sub.pivot(index="framework", columns="mode", values="p95_ms_avg")
    pv = pv.reindex(["flask", "django", "fastapi"])
    pv.plot(kind="bar", ax=ax, color=["#2ca02c", "#d62728"])
    ax.set_title(f"/{endpoint}")
    ax.set_ylabel("p95 затримка, мс")
    ax.set_xlabel("")
    ax.tick_params(axis="x", rotation=0)
plt.suptitle("Затримка відповіді (p95): Secure vs Vulnerable")
plt.tight_layout()
plt.savefig(GRAPHS / "03_p95_latency.png")
plt.close()

# Четвертий графік
fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharey=False)
for ax, endpoint in zip(axes, ["search", "greet"]):
    sub = perf[perf["endpoint"] == endpoint]
    pv = sub.pivot(index="framework", columns="mode", values="rps_avg")
    pv = pv.reindex(["flask", "django", "fastapi"])
    pv.plot(kind="bar", ax=ax, color=["#2ca02c", "#d62728"])
    ax.set_title(f"/{endpoint}")
    ax.set_ylabel("Запитів/с (RPS)")
    ax.set_xlabel("")
    ax.tick_params(axis="x", rotation=0)
plt.suptitle("Пропускна здатність: Secure vs Vulnerable")
plt.tight_layout()
plt.savefig(GRAPHS / "04_rps_throughput.png")
plt.close()

# П'ятий графік
zap_counts = pd.read_csv(RESULTS / "day8_zap_counts.csv").set_index("target")
semgrep_counts = pd.read_csv(RESULTS / "day8_semgrep_counts.csv").set_index("framework")
asr_mode = pd.read_csv(RESULTS / "day8_asr_by_mode.csv")

fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))

# Наші атаки: кількість success (успішних атак) по framework, V-режим
sub = asr_mode[asr_mode["mode"] == "vulnerable"].set_index("framework")["success"]
sub = sub.reindex(["flask", "django", "fastapi"])
axes[0].bar(sub.index, sub.values, color="#9467bd")
axes[0].set_title("Власні тести:\nуспішних атак (V-режим)")
axes[0].set_ylabel("Кількість")

# ZAP: High+Medium по V-цілях
zap_v = zap_counts.loc[["flask-v", "django-v", "fastapi-v"]]
zap_risk = zap_v["High"] + zap_v["Medium"]
axes[1].bar(["flask", "django", "fastapi"], zap_risk.values, color="#17becf")
axes[1].set_title("ZAP:\nHigh+Medium (V-ціль)")

# Semgrep: усі знахідки (однакові для V і P, бо Semgrep бачить увесь код одразу)
semgrep_total = semgrep_counts.reindex(["flask", "django", "fastapi"]).sum(axis=1)
axes[2].bar(semgrep_total.index, semgrep_total.values, color="#e377c2")
axes[2].set_title("Semgrep:\nвсі знахідки (код V+P разом)")

for ax in axes:
    ax.set_xlabel("")
plt.suptitle("Порівняння трьох незалежних джерел виявлення вразливостей")
plt.tight_layout()
plt.savefig(GRAPHS / "05_cross_tool_comparison.png")
plt.close()

print("Усі 5 графіків збережено в analysis/graphs/")