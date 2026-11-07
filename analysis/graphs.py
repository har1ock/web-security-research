"""
Побудова графіків для розділу "Результати" на основі зведених таблиць
із results/final-analysis/ та docs/bypass_matrix.json.

Запуск: python analysis/graphs.py
Передумова: analysis/analysis.py вже виконано, усі final-analysis/*.csv існують.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

# --------------------------------------------------------------------------
# Конфігурація
# --------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"
FINAL_ANALYSIS_DIR = RESULTS_DIR / "final-analysis"
DOCS_DIR = ROOT_DIR / "docs"
GRAPHS_DIR = Path(__file__).resolve().parent / "graphs"

FRAMEWORK_ORDER = ["flask", "django", "fastapi"]
FRAMEWORK_LABELS = {"flask": "Flask", "django": "Django", "fastapi": "FastAPI"}

MODE_COLORS = {"vulnerable": "#d62728", "secure": "#2ca02c"}
MODE_LABELS = {"vulnerable": "Vulnerable (V)", "secure": "Secure (P)"}

BYPASS_TYPE_COLORS = {"absent": "#7f7f7f", "bypassed": "#d62728", "weakened": "#ff9800"}
BYPASS_TYPE_LABELS = {
    "absent": "Absent (фреймворк не захищає)",
    "bypassed": "Bypassed (свідомо обійдено)",
    "weakened": "Weakened (послаблена конфігурація)",
}

FRAMEWORK_HATCHES = {"flask": "", "django": "//", "fastapi": ".."}

FIGURE_DPI = 120
FIGSIZE_SINGLE = (7, 4.5)
FIGSIZE_WIDE = (10, 5)
FIGSIZE_DOUBLE = (11, 4.5)
FIGSIZE_TRIPLE = (14, 4.5)


# --------------------------------------------------------------------------
# Утиліти
# --------------------------------------------------------------------------

def load_csv(relative_path: str) -> pd.DataFrame:
    """Завантажує CSV із results/final-analysis/ або results/, з читабельною помилкою."""
    path = RESULTS_DIR / relative_path
    if not path.exists():
        raise FileNotFoundError(
            f"Не знайдено {path}. Спершу запустіть analysis/analysis.py."
        )
    return pd.read_csv(path)


def save_figure(fig: plt.Figure, filename: str) -> None:
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = GRAPHS_DIR / filename
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  збережено: {out_path.relative_to(ROOT_DIR)}")


def framework_mode_from_target(df: pd.DataFrame, target_col: str = "target") -> pd.DataFrame:
    """Додає колонки framework/mode, виведені з назви цілі на кшталт 'flask-v'."""
    df = df.copy()
    df["framework"] = df[target_col].str.replace("-v", "", regex=False).str.replace("-p", "", regex=False)
    df["mode"] = df[target_col].apply(lambda t: "vulnerable" if t.endswith("-v") else "secure")
    return df


# --------------------------------------------------------------------------
# Графік 1 — тип походження вразливостей (absent/bypassed/weakened)
# --------------------------------------------------------------------------

def plot_bypass_type() -> None:
    """Стовпчикова діаграма: скільки вразливостей кожного типу довелося
    створити в кожному фреймворку (джерело: docs/bypass_matrix.json)."""
    matrix_path = DOCS_DIR / "bypass_matrix.json"
    if not matrix_path.exists():
        raise FileNotFoundError(f"Не знайдено {matrix_path}")
    bypass_data = json.loads(matrix_path.read_text(encoding="utf-8"))

    categories = ["absent", "bypassed", "weakened"]
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)

    bottom = [0.0] * len(FRAMEWORK_ORDER)
    for category in categories:
        values = [bypass_data[fw][category] for fw in FRAMEWORK_ORDER]
        ax.bar(
            FRAMEWORK_ORDER, values, bottom=bottom,
            label=BYPASS_TYPE_LABELS[category], color=BYPASS_TYPE_COLORS[category],
        )
        for i, (value, base) in enumerate(zip(values, bottom)):
            if value > 0:
                ax.text(i, base + value / 2, str(value), ha="center", va="center",
                         color="white", fontweight="bold")
        bottom = [b + v for b, v in zip(bottom, values)]

    ax.set_ylabel("Кількість вразливостей")
    ax.set_title("Як саме створено вразливість у Vulnerable-режимі")
    ax.set_xticks(range(len(FRAMEWORK_ORDER)))
    ax.set_xticklabels([FRAMEWORK_LABELS[fw] for fw in FRAMEWORK_ORDER])
    ax.legend(title="Тип походження", loc="upper center",
              bbox_to_anchor=(0.5, -0.15), ncol=1, fontsize=8)

    save_figure(fig, "01_bypass_type.png")


# --------------------------------------------------------------------------
# Графік 2 — ASR за категоріями атак, V та P одночасно
# --------------------------------------------------------------------------

def plot_asr_by_attack() -> None:
    """Групована стовпчикова діаграма: ASR для кожної категорії атаки,
    усі 6 комбінацій framework×mode поруч."""
    asr_attack = load_csv("final-analysis/asr_by_attack.csv")

    attack_categories = sorted(asr_attack["attack"].unique())
    combos = [(fw, mode) for fw in FRAMEWORK_ORDER for mode in ["vulnerable", "secure"]]

    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)
    bar_width = 0.12
    x_positions = range(len(attack_categories))
    offsets = [i - (len(combos) - 1) / 2 for i in range(len(combos))]

    for (framework, mode), offset in zip(combos, offsets):
        values = []
        for category in attack_categories:
            row = asr_attack[
                (asr_attack["framework"] == framework)
                & (asr_attack["mode"] == mode)
                & (asr_attack["attack"] == category)
            ]
            values.append(row["ASR_%"].iloc[0] if not row.empty else 0.0)

        ax.bar(
            [x + offset * bar_width for x in x_positions], values, bar_width,
            color=MODE_COLORS[mode], hatch=FRAMEWORK_HATCHES[framework],
            edgecolor="black", linewidth=0.3,
            label=f"{FRAMEWORK_LABELS[framework]} / {MODE_LABELS[mode]}",
        )

    ax.set_xticks(list(x_positions))
    ax.set_xticklabels(attack_categories, rotation=30, ha="right")
    ax.set_ylabel("Attack Success Rate, %")
    ax.set_ylim(0, 110)
    ax.set_title("ASR за категоріями атак: Vulnerable vs Secure, усі фреймворки")
    ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", fontsize=8, title="Фреймворк / режим")

    save_figure(fig, "02_asr_by_attack_both_modes.png")


# --------------------------------------------------------------------------
# Графіки 3-4 — продуктивність (p95 та RPS)
# --------------------------------------------------------------------------

def _plot_performance_metric(metric_col: str, ylabel: str, title: str, filename: str) -> None:
    perf = load_csv("load-testing/performance.csv")
    perf = framework_mode_from_target(perf)

    endpoints = sorted(perf["endpoint"].unique())
    fig, axes = plt.subplots(1, len(endpoints), figsize=FIGSIZE_DOUBLE, sharey=False)
    if len(endpoints) == 1:
        axes = [axes]

    for ax, endpoint in zip(axes, endpoints):
        subset = perf[perf["endpoint"] == endpoint]
        pivot = subset.pivot(index="framework", columns="mode", values=metric_col)
        pivot = pivot.reindex(FRAMEWORK_ORDER)
        pivot = pivot.rename(columns=MODE_LABELS)
        pivot.plot(
            kind="bar", ax=ax,
            color=[MODE_COLORS["secure"], MODE_COLORS["vulnerable"]],
        )
        ax.set_title(f"/{endpoint}")
        ax.set_ylabel(ylabel)
        ax.set_xlabel("")
        ax.set_xticklabels([FRAMEWORK_LABELS[fw] for fw in FRAMEWORK_ORDER], rotation=0)
        ax.legend(title="")

    fig.suptitle(title)
    save_figure(fig, filename)


def plot_latency() -> None:
    _plot_performance_metric(
        metric_col="p95_ms_avg", ylabel="p95 затримка, мс",
        title="Затримка відповіді (p95): Secure vs Vulnerable",
        filename="03_p95_latency.png",
    )


def plot_throughput() -> None:
    _plot_performance_metric(
        metric_col="rps_avg", ylabel="Запитів/с (RPS)",
        title="Пропускна здатність: Secure vs Vulnerable",
        filename="04_rps_throughput.png",
    )


# --------------------------------------------------------------------------
# Графік 5 — порівняння трьох незалежних джерел виявлення вразливостей
# --------------------------------------------------------------------------

def plot_cross_tool_comparison() -> None:
    """Три панелі поруч: кількість знахідок за власними тестами, ZAP і Semgrep.
    Джерела різні за природою (атаки / DAST / SAST), тому навмисно не зводяться
    в одну шкалу чи один стовпчик."""
    zap_counts = load_csv("final-analysis/zap_counts.csv").set_index("target")
    semgrep_counts = load_csv("final-analysis/semgrep_counts.csv").set_index("framework")
    asr_mode = load_csv("final-analysis/asr_by_mode.csv")

    fig, axes = plt.subplots(1, 3, figsize=FIGSIZE_TRIPLE)

    own_tests = asr_mode[asr_mode["mode"] == "vulnerable"].set_index("framework")["success"]
    own_tests = own_tests.reindex(FRAMEWORK_ORDER)
    axes[0].bar(FRAMEWORK_ORDER, own_tests.values, color="#9467bd")
    axes[0].set_title("Власні тести:\nуспішних атак (V-режим)")
    axes[0].set_ylabel("Кількість")

    zap_targets = [f"{fw}-v" for fw in FRAMEWORK_ORDER]
    zap_high_medium = zap_counts.loc[zap_targets, "High"] + zap_counts.loc[zap_targets, "Medium"]
    axes[1].bar(FRAMEWORK_ORDER, zap_high_medium.values, color="#17becf")
    axes[1].set_title("ZAP (DAST):\nHigh+Medium (V-ціль)")

    semgrep_total = semgrep_counts.reindex(FRAMEWORK_ORDER).sum(axis=1)
    axes[2].bar(FRAMEWORK_ORDER, semgrep_total.values, color="#e377c2")
    axes[2].set_title("Semgrep (SAST):\nусі знахідки (код V+P разом)")

    for ax in axes:
        ax.set_xlabel("")
        ax.set_xticks(range(len(FRAMEWORK_ORDER)))
        ax.set_xticklabels([FRAMEWORK_LABELS[fw] for fw in FRAMEWORK_ORDER])

    fig.suptitle("Порівняння трьох незалежних джерел виявлення вразливостей")
    save_figure(fig, "05_cross_tool_comparison.png")


# --------------------------------------------------------------------------
# Точка входу
# --------------------------------------------------------------------------

GRAPH_BUILDERS = [
    ("Графік 1 — тип походження вразливостей", plot_bypass_type),
    ("Графік 2 — ASR за категоріями атак", plot_asr_by_attack),
    ("Графік 3 — затримка p95", plot_latency),
    ("Графік 4 — пропускна здатність", plot_throughput),
    ("Графік 5 — порівняння інструментів", plot_cross_tool_comparison),
]


def main() -> None:
    plt.rcParams["figure.dpi"] = FIGURE_DPI
    for description, builder in GRAPH_BUILDERS:
        print(description)
        try:
            builder()
        except FileNotFoundError as exc:
            print(f"  ПРОПУЩЕНО: {exc}", file=sys.stderr)
    print(f"\nГотово. Графіки у {GRAPHS_DIR.relative_to(ROOT_DIR)}/")


if __name__ == "__main__":
    main()
