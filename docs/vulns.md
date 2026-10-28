    ID  |   Flask V   |    Django V   |   FastAPI V   |
        |             |               |
SQLI-01 |   absent    | bypassed (ORM)|    bypassed (SQLAlchemy; сам FastAPI БД-шару не має)
        |             |               |
XSS-01  |   bypassed  |    bypassed   |    bypassed
        |             |               |
XSS-02  |   bypassed  |    bypassed   |    bypassed      
        |             |               |
XSS-03  |   bypassed  |    bypassed   |    bypassed (Markup)
(/greet)|   (Markup)  |   (mark_safe) |
CSRF-01 |   absent    |    bypassed   |    absent
        |             |               |
IDOR-01 |   absent    |    absent     |    absent
        |             |               |
CFG-01  |   weakened  |    weakened   |    absent (дефолт set_cookie без HttpOnly)
(cookie)|             |               |
CFG-02  |   n/a       |     n/a       |    absent (увімкнено за замовчуванням)
(/docs) |             |               |
