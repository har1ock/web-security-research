import csv
import json
import re
import time
import uuid
from pathlib import Path

import requests

from targets import CSRF_FIELD, LOGIN_USER, TARGETS

ATTACKS_DIR = Path(__file__).parent
RESULTS_DIR = ATTACKS_DIR.parent / "results" / "day4"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
RAW_LOG = RESULTS_DIR / "raw_log.jsonl"
SUMMARY_CSV = RESULTS_DIR / "security.csv"


HASH_PATTERN = re.compile(r"[0-9a-f]{16,}\$[0-9a-f]{20,}|pbkdf2_sha256\$")


def timed(method, url, session=None, **kwargs):
    caller = session or requests
    fn = caller.get if method == "GET" else caller.post
    t0 = time.monotonic()
    try:
        resp = fn(url, timeout=5, **kwargs)
    except requests.RequestException:
        return None, None
    return resp, round((time.monotonic() - t0) * 1000, 1)


def log_raw(rec):
    with open(RAW_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def record(target, test_id, category, attack, payload, resp, ms, verdict):
    rec = {
        "framework": target["framework"], "mode": target["mode"],
        "test_id": test_id, "category": category, "attack": attack,
        "payload": payload, "status": resp.status_code if resp is not None else None,
        "elapsed_ms": ms, "verdict": verdict,
        "snippet": resp.text[:300] if resp is not None else None,
    }
    log_raw(rec)
    return {k: rec[k] for k in ("framework", "mode", "test_id", "category", "attack", "verdict")}


def classify_sqli(resp):
    if resp is None:
        return "error"
    if resp.status_code >= 500:
        return "success" if "sql error" in resp.text.lower() else "error"
    row_count = resp.text.count("<li>")
    hash_leak = bool(HASH_PATTERN.search(resp.text))
    return "success" if (row_count > 0 or hash_leak) else "blocked"


def classify_reflected_xss(resp, payload):
    if resp is None:
        return "error"
    if resp.status_code >= 400:
        return "error"
    return "success" if payload in resp.text else "blocked"



def run_sqli(target):
    payloads = json.loads((ATTACKS_DIR / "payloads" / "sqli.json").read_text(encoding="utf-8"))
    out = []
    for p in payloads:
        payload = p["payload"].format(table=target["table"], pwd=target["pwd_col"])
        resp, ms = timed("GET", f"{target['base_url']}/search", params={"q": payload})
        verdict = classify_sqli(resp)
        out.append(record(target, p["id"], p["category"], "sqli", payload, resp, ms, verdict))
    return out


def run_xss(target):
    payloads = json.loads((ATTACKS_DIR / "payloads" / "xss.json").read_text(encoding="utf-8"))
    out = []
    for p in payloads:
        payload = p["payload"]

        resp, ms = timed("GET", f"{target['base_url']}/search", params={"q": payload})
        out.append(record(target, p["id"] + "-R-search", p["category"], "xss-reflected",
                           payload, resp, ms, classify_reflected_xss(resp, payload)))

        resp, ms = timed("GET", f"{target['base_url']}/greet", params={"name": payload})
        out.append(record(target, p["id"] + "-R-greet", p["category"], "xss-reflected",
                           payload, resp, ms, classify_reflected_xss(resp, payload)))

        author = f"xss-{uuid.uuid4().hex[:8]}"
        post_resp, post_ms = timed("POST", f"{target['base_url']}/comments",
                                    data={"author": author, "text": payload})
        if post_resp is not None and post_resp.status_code == 201:
            resp, ms = timed("GET", f"{target['base_url']}/comments")
            verdict = classify_reflected_xss(resp, payload)
        else:
            resp, ms, verdict = post_resp, post_ms, "error"
        out.append(record(target, p["id"] + "-S", p["category"], "xss-stored",
                           payload, resp, ms, verdict))
    return out


def run_csrf(target, session):
    out = []
    field = CSRF_FIELD[target["framework"]]
    base = target["base_url"]

    resp, ms = timed("POST", f"{base}/profile/email", session=session,
                      data={"email": "hacker-no-token@evil.com"})
    v = "success" if resp and resp.status_code == 200 else ("blocked" if resp and resp.status_code in (401, 403, 400, 422) else "error")
    out.append(record(target, "CSRF-01", "missing-token", "csrf", None, resp, ms, v))

    resp, ms = timed("POST", f"{base}/profile/email", session=session,
                      data={"email": "hacker-bad-token@evil.com", field: "not-a-real-token"})
    v = "success" if resp and resp.status_code == 200 else ("blocked" if resp and resp.status_code in (401, 403, 400, 422) else "error")
    out.append(record(target, "CSRF-02", "invalid-token", "csrf", None, resp, ms, v))

    tok_resp, _ = timed("GET", f"{base}/csrf-token", session=session)
    token = tok_resp.json().get("csrf_token") if tok_resp and tok_resp.status_code == 200 else None
    data = {"email": "legit-owner@example.com"}
    if token:
        data[field] = token
    resp, ms = timed("POST", f"{base}/profile/email", session=session, data=data)
    v = "ok" if resp and resp.status_code == 200 else "broken"
    out.append(record(target, "LEGIT-CSRF-01", "legit", "csrf", None, resp, ms, v))
    return out


def run_idor(target, session):
    out = []
    base = target["base_url"]

    resp, ms = timed("GET", f"{base}/notes/3", session=session)  # нотатка Боба
    v = "success" if resp and resp.status_code == 200 else ("blocked" if resp and resp.status_code in (403, 401, 404) else "error")
    out.append(record(target, "IDOR-01", "foreign-object", "idor", "3", resp, ms, v))

    resp, ms = timed("GET", f"{base}/notes/1", session=session)  # своя нотатка
    v = "ok" if resp and resp.status_code == 200 else "broken"
    out.append(record(target, "LEGIT-IDOR-01", "legit", "idor", "1", resp, ms, v))
    return out


def run_legit_search(target):
    out = []
    for test_id, q, min_rows in [("LEGIT-SEARCH-01", "alice", 1), ("LEGIT-SEARCH-02", "a", 2), ("LEGIT-SEARCH-03", "", 3)]:
        resp, ms = timed("GET", f"{target['base_url']}/search", params={"q": q})
        row_count = resp.text.count("<li>") if resp is not None else 0
        v = "ok" if row_count >= min_rows else "broken"
        out.append(record(target, test_id, "legit", "sqli", q, resp, ms, v))
    return out


def main():
    RAW_LOG.unlink(missing_ok=True)
    all_rows = []

    for target in TARGETS:
        print(f"== {target['framework']} / {target['mode']} ==")
        requests.post(f"{target['base_url']}/__reset", timeout=5)

        session = requests.Session()
        session.post(f"{target['base_url']}/login", data=LOGIN_USER, timeout=5)

        all_rows += run_sqli(target)
        all_rows += run_xss(target)
        all_rows += run_csrf(target, session)
        all_rows += run_idor(target, session)
        all_rows += run_legit_search(target)

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["framework", "mode", "test_id", "category", "attack", "verdict"])
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Готово: {len(all_rows)} тестів. {RAW_LOG.name}, {SUMMARY_CSV.name} у {RESULTS_DIR}")


if __name__ == "__main__":
    main()