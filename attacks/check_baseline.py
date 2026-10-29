import requests

TARGETS = {
    "flask-plain": "http://localhost:5201",
    "django-plain": "http://localhost:5202",
    "fastapi-plain": "http://localhost:5203",
}

for name, url in TARGETS.items():
    r = requests.post(f"{url}/login", data={"username": "x", "password": "y"})
    cookie_header = r.headers.get("Set-Cookie", "")
    print(name)
    print("  HttpOnly:", "HttpOnly" in cookie_header)
    print("  SameSite:", "samesite=lax" in cookie_header.lower() or "samesite=strict" in cookie_header.lower())
    print("  CSP:", "Content-Security-Policy" in r.headers)
    print("  X-Frame-Options:", r.headers.get("X-Frame-Options"))
    print("  X-Content-Type-Options:", r.headers.get("X-Content-Type-Options"))