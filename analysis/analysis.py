"""
Розрахунок зведених метрик (ASR, PR, FPR, Performance Overhead) та
зведених таблиць ZAP/Semgrep для розділу "Результати".

Джерела:
    results/security-tests/security.csv   — власні контрольовані атаки
    results/dast-zap/zap_summary.csv      — знахідки OWASP ZAP
    results/sast-semgrep/semgrep_summary.csv — знахідки Semgrep
    results/load-testing/performance.csv  — результати k6

Виводить у results/final-analysis/:
    asr_by_attack.csv, asr_by_mode.csv, fpr.csv,
    zap_counts.csv, semgrep_counts.csv, performance_overhead.csv

Запуск: python analysis/analysis.py
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

# --------------------------------------------------------------------------
# Конфігурація
# --------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"
FINAL_ANALYSIS_DIR = RESULTS_DIR / "final-analysis"

SECURITY_CSV = RESULTS_DIR / "security-tests" / "security.csv"
ZAP_CSV = RESULTS_DIR / "dast-zap" / "zap_summary.csv"
SEMGREP_CSV = RESULTS_DIR / "sast-semgrep" / "semgrep_summary.csv"
PERFORMANCE_CSV = RESULTS_DIR / "load-testing" / "performance.csv"

LEGIT_PREFIX = "LEGIT-"
ATTACK_VERDICT_COLUMNS = ["success", "blocked"]
LEGIT_VERDICT_COLUMNS = ["ok", "broken"]
RISK_LEVELS = ["High", "Medium", "Low", "Informational"]


# --------------------------------------------------------------------------
# Утиліти вводу/виводу
# --------------------------------------------------------------------------

def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Не знайдено {path}")
    return pd.read_csv(path)


def save_csv(df: pd.DataFrame, filename: str, index: bool = False) -> None:
    FINAL_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FINAL_ANALYSIS_DIR / filename
    df.to_csv(out_path, index=index)
    print(f"  збережено: {out_path.relative_to(ROOT_DIR)}")


# --------------------------------------------------------------------------
# Валідація вхідних даних
# --------------------------------------------------------------------------

def validate_security_verdicts(security: pd.DataFrame) -> None:
    """Перевіряє, що вердикти не містять 'error' — такі рядки означають
    збій тестового скрипта, а не результат атаки, і псують ASR/PR, якщо
    потраплять у знаменник."""
    verdicts = security["verdict"].unique()
    print(f"  shape={security.shape}, verdicts={list(verdicts)}")
    if "error" in verdicts:
        raise ValueError(
            "У security.csv є вердикт 'error'. Це означає збій тестового "
            "скрипта (мережева помилка, таймаут), а не результат атаки. "
            "Виправте їх джерело (run_attacks.py) і перезапустіть збір "
            "даних, перш ніж рахувати метрики."
        )


# --------------------------------------------------------------------------
# ASR / PR — ефективність атак і захисту
# --------------------------------------------------------------------------

def split_attacks_and_legit(security: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Розділяє рядки на атаки (test_id без префіксу LEGIT-) та легітимні
    перевірки (для розрахунку FPR окремо від ASR/PR)."""
    is_legit = security["test_id"].str.startswith(LEGIT_PREFIX)
    return security[~is_legit].copy(), security[is_legit].copy()


def compute_asr_pr(df: pd.DataFrame, group_cols: list[str]) -> pd.DataFrame:
    """ASR = success / (success + blocked); PR = blocked / (success + blocked)."""
    grouped = df.groupby(group_cols)["verdict"].value_counts().unstack(fill_value=0)
    for col in ATTACK_VERDICT_COLUMNS:
        if col not in grouped.columns:
            grouped[col] = 0

    total = grouped["success"] + grouped["blocked"]
    grouped["ASR_%"] = (grouped["success"] / total * 100).round(1)
    grouped["PR_%"] = (grouped["blocked"] / total * 100).round(1)
    grouped["n"] = total
    return grouped.reset_index()


# --------------------------------------------------------------------------
# FPR — чи не ламає захист легітимні запити
# --------------------------------------------------------------------------

def compute_fpr(legit: pd.DataFrame, group_cols: list[str]) -> pd.DataFrame:
    """FPR = broken / (ok + broken). За задумом має бути 0% в обох режимах;
    ненульове значення — важлива знахідка, а не помилка розрахунку."""
    grouped = legit.groupby(group_cols)["verdict"].value_counts().unstack(fill_value=0)
    for col in LEGIT_VERDICT_COLUMNS:
        if col not in grouped.columns:
            grouped[col] = 0

    total = grouped["ok"] + grouped["broken"]
    grouped["FPR_%"] = (grouped["broken"] / total * 100).round(1)
    grouped["n"] = total
    return grouped.reset_index()


def report_broken_legit(legit: pd.DataFrame) -> None:
    broken = legit[legit["verdict"] == "broken"]
    if not broken.empty:
        print("  УВАГА: знайдено зламані легітимні запити:")
        print(broken[["framework", "mode", "test_id"]].to_string(index=False))


# --------------------------------------------------------------------------
# ZAP і Semgrep — незалежні зведені таблиці (не змішуємо з ASR/PR)
# --------------------------------------------------------------------------

def compute_zap_counts(zap: pd.DataFrame) -> pd.DataFrame:
    counts = zap.groupby(["target", "risk"]).size().unstack(fill_value=0)
    for level in RISK_LEVELS:
        if level not in counts.columns:
            counts[level] = 0
    return counts[RISK_LEVELS]


def compute_semgrep_counts(semgrep: pd.DataFrame) -> pd.DataFrame:
    return semgrep.groupby(["framework", "severity"]).size().unstack(fill_value=0)


# --------------------------------------------------------------------------
# Performance Overhead
# --------------------------------------------------------------------------

def compute_performance_overhead(performance: pd.DataFrame) -> pd.DataFrame:
    """PO = (T_secure - T_vulnerable) / T_vulnerable * 100.
    Додатний RPS_overhead/від'ємний p95_overhead — секьюр-версія швидша;
    типово очікується невеликий негативний RPS і позитивний p95 (захист
    коштує трохи продуктивності)."""
    perf = performance.copy()
    perf["framework"] = perf["target"].str.replace("-v", "", regex=False).str.replace("-p", "", regex=False)
    perf["mode"] = perf["target"].apply(lambda t: "vulnerable" if t.endswith("-v") else "secure")

    pivot = perf.pivot_table(
        index=["framework", "endpoint"], columns="mode",
        values=["rps_avg", "p95_ms_avg"],
    )

    pivot["RPS_overhead_%"] = (
        (pivot[("rps_avg", "vulnerable")] - pivot[("rps_avg", "secure")])
        / pivot[("rps_avg", "vulnerable")] * 100
    ).round(1)
    pivot["p95_overhead_%"] = (
        (pivot[("p95_ms_avg", "secure")] - pivot[("p95_ms_avg", "vulnerable")])
        / pivot[("p95_ms_avg", "vulnerable")] * 100
    ).round(1)

    return pivot


# --------------------------------------------------------------------------
# Точка входу
# --------------------------------------------------------------------------

def main() -> None:
    print("1. Завантаження та перевірка security.csv")
    security = load_csv(SECURITY_CSV)
    validate_security_verdicts(security)
    attacks, legit = split_attacks_and_legit(security)

    print("\n2. ASR / PR")
    asr_by_attack = compute_asr_pr(attacks, ["framework", "mode", "attack"])
    save_csv(asr_by_attack, "asr_by_attack.csv")

    asr_by_mode = compute_asr_pr(attacks, ["framework", "mode"])
    print(asr_by_mode.to_string(index=False))
    save_csv(asr_by_mode, "asr_by_mode.csv")

    print("\n3. FPR (легітимні запити)")
    fpr_by_mode = compute_fpr(legit, ["framework", "mode"])
    print(fpr_by_mode.to_string(index=False))
    save_csv(fpr_by_mode, "fpr.csv")
    report_broken_legit(legit)

    print("\n4. Зведення ZAP")
    zap = load_csv(ZAP_CSV)
    zap_counts = compute_zap_counts(zap)
    print(zap_counts)
    save_csv(zap_counts, "zap_counts.csv", index=True)

    print("\n5. Зведення Semgrep")
    semgrep = load_csv(SEMGREP_CSV)
    semgrep_counts = compute_semgrep_counts(semgrep)
    print(semgrep_counts)
    save_csv(semgrep_counts, "semgrep_counts.csv", index=True)

    print("\n6. Performance Overhead")
    performance = load_csv(PERFORMANCE_CSV)
    overhead = compute_performance_overhead(performance)
    print(overhead[["RPS_overhead_%", "p95_overhead_%"]])
    save_csv(overhead, "performance_overhead.csv", index=True)

    print(f"\nГотово. Усі зведені таблиці у {FINAL_ANALYSIS_DIR.relative_to(ROOT_DIR)}/")


if __name__ == "__main__":
    main()
