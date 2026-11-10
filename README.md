# Web Security Research — Flask vs Django vs FastAPI

> Master's thesis research stand: comparative study of built-in security
> mechanisms across Flask, Django, and FastAPI against SQL Injection, XSS,
> CSRF, IDOR, and brute-force attacks, with automated attack testing,
> independent DAST/SAST/SCA tools (OWASP ZAP, Semgrep, pip-audit), and
> performance impact measurement.

## ⚠️ Security notice

This repository intentionally contains **deliberately vulnerable code**
(the "Vulnerable" / `V` configuration of each application) for controlled,
local research purposes only. **Never deploy any part of this stand to a
public network.** Test-only endpoints such as `/__reset` must never exist
in production code.

## Quick start

```bash
git clone <this-repo>
cd web-security-research
docker compose up -d --build
```

All six application instances (Flask/Django/FastAPI × Vulnerable/Secure)
will be available at `localhost:5001`–`localhost:5103` (see port table
below). For the full reproduction pipeline (attacks, scanners, load
testing, analysis), see the Ukrainian section below.

---

## 🇺🇦 Опис проєкту

Дослідницький стенд для магістерської роботи «Порівняння методів захисту вебзастосунків від XSS, 
SQL-ін'єкцій, CSRF та IDOR у сучасних Python-фреймворках».

**Дослідницьке питання:** як вбудовані механізми безпеки сучасних
вебфреймворків (Flask, Django, FastAPI) та типові помилки їх
використання впливають на стійкість вебзастосунків до поширених атак,
кількість виявлених вразливостей за даними незалежних інструментів
аналізу, а також на продуктивність застосунку.

## Архітектура

Три функціонально ідентичні застосунки (однаковий контракт ендпоінтів),
кожен у двох конфігураціях — **Vulnerable (V)** та **Secure (P)** —
керованих змінною середовища `SECURE`. Усі шість інстансів запущені як
окремі Docker-контейнери з однаковими обмеженнями ресурсів
(`cpus: 1`, `mem_limit: 512m`) для коректності порівняння продуктивності.

### Порти

| Застосунок | Vulnerable (V) | Secure (P) |
|---|---|---|
| Flask | `localhost:5001` | `localhost:5101` |
| Django | `localhost:5002` | `localhost:5102` |
| FastAPI | `localhost:5003` | `localhost:5103` |

Додатково — «чисті» базові застосунки без жодного власного налаштування
безпеки (для вимірювання поведінки фреймворків за замовчуванням, Дeнь 5):
`baseline/flask-plain`, `baseline/django-plain`, `baseline/fastapi-plain`
(порти 5201–5203).

### Функціональний контракт

| Ендпоінт | Призначення | Досліджувана атака |
|---|---|---|
| `GET /search?q=` | пошук користувачів | SQL Injection, reflected XSS |
| `GET /greet?name=` | вітання (без БД) | reflected XSS (`Markup`/`mark_safe`) |
| `POST /comments`, `GET /comments` | коментарі | stored XSS |
| `POST /login`, `GET /profile` | автентифікація | brute force |
| `POST /profile/email` | зміна email | CSRF |
| `GET /notes/<id>` | перегляд нотатки | IDOR / Broken Access Control |
| `POST /__reset` (лише `TEST_MODE=1`) | скидання стану БД | службовий, для тестів |

## Структура репозиторію
web-security-research/
├── flask-app/ django-app/ fastapi-app/ # застосунки (V/P через SECURE)
├── baseline/ # "чисті" застосунки без налаштувань
│ ├── flask-plain/ django-plain/ fastapi-plain/
├── attacks/ # автоматизовані атаки
│ ├── targets.py # конфігурація 6 цілей
│ ├── run_attacks.py # основний тестовий скрипт
│ ├── payloads/sqli.json, xss.json # корпуси payload'ів
│ ├── csrf_site/ # сторінки для браузерного CSRF-тесту
│ └── semgrep-rules/ # власні правила Semgrep
├── perf/ # навантажувальне тестування (k6)
│ ├── search.js, greet.js, run_all.sh, parse_performance.py
├── analysis/ # розрахунок метрик і графіки
│ ├── analysis.py, graphs.py, graphs/
├── demo/ # демонстраційний скрипт (для захисту)
│ └── run_demo.py
├── docs/ # методологія та документація
│ ├── criteria.md # критерії успіху/блокування атак
│ ├── vulns.md # матриця absent/bypassed/weakened
│ ├── baseline.md # поведінка фреймворків за замовчуванням
│ └── bypass_matrix.json # дані для Графіка 1
├── results/ # сирі та проміжні результати
│ ├── security-tests/ # власні атаки: security.csv, raw_log.jsonl, sqlmap/
│ ├── csrf-browser-test/ # ручний браузерний CSRF-тест
│ ├── dast-zap/ # звіти OWASP ZAP
│ ├── sast-semgrep/ # звіти Semgrep
│ ├── sca-pip-audit/ # звіти pip-audit
│ ├── load-testing/ # k6: сирі дані та зведення
│ └── final-analysis/ # зведені CSV для тексту роботи
├── reports/ # фінальні матеріали (графіки, таблиці) для вставки в роботу
├── docker-compose.yml
└── README.md
## Передумови

- Docker + Docker Compose
- Python 3.10+ з пакетами: `requests`, `pandas`, `matplotlib`
- [k6](https://k6.io/) — навантажувальне тестування
- [Semgrep](https://semgrep.dev/) — статичний аналіз
- [pip-audit](https://pypi.org/project/pip-audit/) — аналіз залежностей
- `sqlmap` (опційно, для незалежного підтвердження SQLi)
- Docker-образ `zaproxy/zap-stable` (OWASP ZAP, тягнеться автоматично)

## Повний пайплайн відтворення дослідження

Виконувати з кореня репозиторію, у вказаному порядку:

```bash
# 1. Піднімаємо стенд
docker compose up -d --build

# 2. Автоматизовані атаки (контрольовані тести, ~1-2 хв)
cd attacks && python run_attacks.py && cd ..

# 3. Сканування OWASP ZAP (по черзі, ~30-60 хв на всі 6 цілей)
./results/dast-zap/run_scan.sh
cd results/dast-zap && python parse_zap.py && cd ../..

# 4. Статичний аналіз Semgrep
cd results/sast-semgrep && python parse_semgrep.py && cd ../..

# 5. Аналіз залежностей pip-audit
cd results/sca-pip-audit && python parse_pip_audit.py && cd ../..

# 6. Навантажувальне тестування (k6, ~35-45 хв)
./perf/run_all.sh
python perf/parse_performance.py

# 7. Зведений аналіз і графіки
python analysis/analysis.py
python analysis/graphs.py

# 8. Демонстраційний звіт (швидкий, для живої демонстрації)
python demo/run_demo.py
```

## Перевірка відтворюваності з чистого стану

```bash
docker compose down -v
docker compose up -d --build
```

Після цього всі БД ініціалізуються заново (seed-дані: користувачі `alice`,
`bob`, `admin`), і повний пайплайн вище можна виконати з нуля.

## Відомі обмеження дослідження

- **СУБД:** SQLite замість production-СУБД — спрощення для контрольованого
  експерименту.
- **Rate limiting:** лічильники зберігаються в пам'яті окремо на кожен
  із 2 воркерів застосунку, тому фактичний поріг блокування може
  відрізнятися від номінального.
- **WSGI vs ASGI:** Flask/Django (gunicorn, синхронний) і FastAPI
  (uvicorn, асинхронний event loop) мають різні моделі виконання запитів,
  тому порівняння продуктивності відображає конкретні реалізації, а не
  фреймворки в ізоляції від моделі виконання.
- **ZAP API Scan:** методологічно не перевіряє XSS та IDOR за дизайном
  (офіційна документація ZAP) — ці категорії підтверджені власним
  тестовим набором і статичним аналізом.
- **Продуктивність:** 5 прогонів на комбінацію (перший відкидається як
  прогрів); одна аномалія (`django`/`greet`) залишається в межах
  статистичного шуму при такій кількості повторів.
- **CSRF-звільнення `/login` і `/comments`** — свідоме лабораторне
  спрощення для контрольованого тестування, неприпустиме для production.

## Автор

Гордов Михайло, РДГУ, 2026
Магістерська робота: «Порівняння методів захисту везастосунків від XSS, SQL-ін'єкцій,
CSRF та IDOR у сучасних Python-фреймворках»
