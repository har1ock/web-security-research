"""
Демонстраційний скрипт для захисту магістерської.
Не замінює results/* — пише окремо в results/demo/.
Швидкий (секунди), перевіряє 3 показові атаки замість повного набору.

Запуск (з кореня репозиторію, усі 6 контейнерів мають бути підняті):
    python demo/run_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "attacks"))

import requests  # noqa: E402
from targets import TARGETS, LOGIN_USER  # noqa: E402  (перевикористовуємо конфігурацію з attacks/)

RESULTS_DIR = ROOT_DIR / "results" / "demo"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RED = "\033[91m"
GREEN = "\033[92m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def colored_status(success: bool) -> str:
    if success:
        return f"{RED}{BOLD}✘ АТАКА ПРОЙШЛА{RESET}"
    return f"{GREEN}{BOLD}✔ ЗАБЛОКОВАНО{RESET}"


def demo_sqli(target: dict) -> tuple[bool, str, int | str]:
    payload = f"zzz' UNION SELECT id, {target['pwd_col']}, email FROM {target['table']} --"
    resp = requests.get(f"{target['base_url']}/search", params={"q": payload}, timeout=5)
    row_count = resp.text.count("<li>")
    success = row_count > 0
    detail = (
        f"Отримано {row_count} чужих рядків (можливо, з хешами паролів)"
        if success else "Пошук повернув 0 рядків — ін'єкція нейтралізована"
    )
    return success, detail, resp.status_code


def demo_xss(target: dict) -> tuple[bool, str, int | str]:
    marker = "DEMO-XSS-MARK"
    payload = f"<img src=x onerror=alert('{marker}')>"
    requests.post(f"{target['base_url']}/comments",
                   data={"author": "demo", "text": payload}, timeout=5)
    resp = requests.get(f"{target['base_url']}/comments", timeout=5)
    success = payload in resp.text
    detail = (
        "Payload повернувся без екранування — виконається у браузері"
        if success else "Payload екранований (&lt;img ...&gt;) — JS не виконається"
    )
    return success, detail, resp.status_code


def demo_idor(target: dict) -> tuple[bool, str, int | str]:
    session = requests.Session()
    session.post(f"{target['base_url']}/login", data=LOGIN_USER, timeout=5)
    resp = session.get(f"{target['base_url']}/notes/3", timeout=5)  # нотатка Боба
    success = resp.status_code == 200
    detail = (
        f"Отримано чужу нотатку: \"{resp.json().get('text', '')[:50]}\""
        if success else f"Доступ заборонено (статус {resp.status_code})"
    )
    return success, detail, resp.status_code


CHECKS = [
    ("SQL Injection", demo_sqli),
    ("XSS (stored)", demo_xss),
    ("IDOR", demo_idor),
]


def reset_all() -> None:
    for t in TARGETS:
        try:
            requests.post(f"{t['base_url']}/__reset", timeout=5)
        except requests.RequestException:
            print(f"{RED}!! не вдалося скинути {t['base_url']} — контейнер запущено?{RESET}")


def run() -> None:
    print(f"{BOLD}Скидання стану всіх цілей...{RESET}")
    reset_all()

    results = []
    for t in TARGETS:
        label = f"{t['framework'].capitalize()} ({'Secure' if t['mode'] == 'secure' else 'Vulnerable'})"
        print(f"\n{BOLD}{'=' * 60}\n{label}  —  {t['base_url']}\n{'=' * 60}{RESET}")
        for name, fn in CHECKS:
            try:
                success, detail, status = fn(t)
            except Exception as e:  # noqa: BLE001 — демо-скрипт має пережити будь-яку мережеву помилку
                success, detail, status = None, f"Помилка запиту: {e}", "-"

            if success is None:
                print(f"  {DIM}{name}: не вдалося перевірити ({detail}){RESET}")
            else:
                print(f"  {name:20} {colored_status(success)}   {DIM}{detail}{RESET}")

            results.append({
                "framework": t["framework"], "mode": t["mode"],
                "attack": name, "success": success, "detail": detail, "status": status,
            })

    write_html(results)
    write_txt(results)
    print(f"\n{BOLD}{GREEN}Готово.{RESET} Звіти: "
          f"{RESULTS_DIR / 'demo_report.html'}  і  {RESULTS_DIR / 'demo_report.txt'}")


def write_html(results: list[dict]) -> None:
    frameworks = ["flask", "django", "fastapi"]
    cards = []
    for fw in frameworks:
        cards.append(f'<h2>{fw.capitalize()}</h2><div class="row">')
        for mode, mode_label in [("vulnerable", "Vulnerable (V)"), ("secure", "Secure (P)")]:
            cards.append(f'<div class="col"><h3>{mode_label}</h3>')
            for r in results:
                if r["framework"] == fw and r["mode"] == mode:
                    if r["success"] is None:
                        cls, icon, text = "unknown", "?", "Помилка перевірки"
                    elif r["success"]:
                        cls, icon, text = "fail", "✘", "АТАКА ПРОЙШЛА"
                    else:
                        cls, icon, text = "ok", "✔", "ЗАБЛОКОВАНО"
                    cards.append(f'''
                    <div class="card {cls}">
                        <div class="card-head"><span class="icon">{icon}</span>
                            <span class="attack">{r["attack"]}</span>
                            <span class="verdict">{text}</span></div>
                        <div class="detail">{r["detail"]}</div>
                    </div>''')
            cards.append('</div>')
        cards.append('</div>')

    html = f"""<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="utf-8">
<title>Демонстрація: захист веб-застосунків</title>
<style>
  :root {{
    --bg: #0f1117; --fg: #e8e8ea;
    --ok: #1f9d55; --ok-bg: #0d2818; --fail: #e23e3e; --fail-bg: #2c1212;
  }}
  body {{ background: var(--bg); color: var(--fg); font-family: "Segoe UI", system-ui, sans-serif;
          max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
  h1 {{ font-size: 1.8rem; border-bottom: 2px solid #333; padding-bottom: 12px; }}
  h2 {{ margin-top: 40px; font-size: 1.4rem; color: #8ab4f8; }}
  h3 {{ font-size: 1.05rem; color: #aaa; font-weight: 600; }}
  .row {{ display: flex; gap: 24px; flex-wrap: wrap; }}
  .col {{ flex: 1; min-width: 320px; }}
  .card {{ border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; border: 1px solid #333; }}
  .card.ok {{ background: var(--ok-bg); border-color: var(--ok); }}
  .card.fail {{ background: var(--fail-bg); border-color: var(--fail); }}
  .card-head {{ display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.05rem; }}
  .card.ok .icon, .card.ok .verdict {{ color: var(--ok); }}
  .card.fail .icon, .card.fail .verdict {{ color: var(--fail); }}
  .attack {{ flex: 1; }}
  .detail {{ margin-top: 6px; color: #bbb; font-size: 0.92rem; }}
</style>
</head>
<body>
<h1>Демонстрація: вразливі (V) та захищені (P) версії застосунків</h1>
<p style="color:#999">Згенеровано для живої демонстрації на захисті. Повні результати дослідження — у results/.</p>
{''.join(cards)}
</body>
</html>"""
    (RESULTS_DIR / "demo_report.html").write_text(html, encoding="utf-8")


def write_txt(results: list[dict]) -> None:
    lines = ["ДЕМОНСТРАЦІЯ: вразливі (V) та захищені (P) версії застосунків", "=" * 60]
    for fw in ["flask", "django", "fastapi"]:
        lines.append(f"\n{fw.upper()}")
        for mode in ["vulnerable", "secure"]:
            lines.append(f"  [{mode}]")
            for r in results:
                if r["framework"] == fw and r["mode"] == mode:
                    verdict = ("? ПОМИЛКА" if r["success"] is None
                               else "АТАКА ПРОЙШЛА" if r["success"] else "ЗАБЛОКОВАНО")
                    lines.append(f"    {r['attack']:18} {verdict:18} {r['detail']}")
    (RESULTS_DIR / "demo_report.txt").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    run()
