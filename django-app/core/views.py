from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.db import DatabaseError, connection
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.template import Context, Template
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from django_ratelimit.decorators import ratelimit

from .models import Comment, Note

SECURE = settings.SECURE

# У V вимикаємо CSRF-перевірку на в'юсі (типова "помилка розробника").
# У P декоратор нічого не робить, тому діє CsrfViewMiddleware.
maybe_exempt = (lambda f: f) if SECURE else csrf_exempt

# {% if raw %} {{ q|safe }} — вимикає автоекранування (як у Flask V)
SEARCH_HTML = """
<h1>Результати дня: {% if raw %}{{ q|safe }}{% else %}{{ q }}{% endif %}</h1>
<ul>
{% for r in rows %}<li>{{ r.id }} | {{ r.username }} | {{ r.email }}</li>
{% endfor %}
</ul>
"""

COMMENTS_HTML = """
<h1>Коментарі</h1>
{% for r in rows %}
<p><b>{{ r.author }}</b>: {% if raw %}{{ r.text|safe }}{% else %}{{ r.text }}{% endif %}</p>
{% endfor %}
"""

_search_tmpl = Template(SEARCH_HTML)
_comments_tmpl = Template(COMMENTS_HTML)
_greet_tmpl = Template("<h1>Hello {{ n }}</h1>")


def render(tmpl, **ctx):
    return HttpResponse(tmpl.render(Context(ctx)))


@require_GET
def index(request):
    return JsonResponse({"app": "django", "mode": "secure" if SECURE else "vulnerable"})


@csrf_exempt
@require_POST
@ratelimit(key="ip", rate="5/m", block=False)
def login_view(request):
    if getattr(request, "limited", False) and SECURE:
        return JsonResponse({"error": "too many requests"}, status=429)

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({"error": "invalid credentials"}, status=401)
    login(request, user)
    return JsonResponse({"message": "ok", "user": user.username})


@require_GET
def search(request):
    q = request.GET.get("q", "")
    try:
        if SECURE:
            # P: ORM. Django сам параметризує запит і екранує % та _ у q
            rows = list(
                User.objects.filter(username__icontains=q).values("id", "username", "email")
            )
        else:
            # V: сирий SQL із f-рядком. Це те саме, що й у Flask V
            with connection.cursor() as cur:
                cur.execute(
                    f"SELECT id, username, email FROM auth_user WHERE username LIKE '%{q}%'"
                )
                cols = [c[0] for c in cur.description]
                rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    except DatabaseError as e:
        if SECURE:
            return HttpResponse("search error", status=400)
        return HttpResponse(f"SQL error: {e}", status=500)  # V: витік деталей
    return render(_search_tmpl, q=q, rows=rows, raw=not SECURE)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def comments(request):
    if request.method == "POST":
        Comment.objects.create(
            author=request.POST.get("author", "anon"),
            text=request.POST.get("text", ""),
        )
        return JsonResponse({"message": "saved"}, status=201)
    rows = Comment.objects.values("author", "text")
    return render(_comments_tmpl, rows=rows, raw=not SECURE)


@require_GET
def csrf_token(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "login required"}, status=401)
    # get_token створює токен і ставить cookie csrftoken
    return JsonResponse({"csrf_token": get_token(request)})


@maybe_exempt
@require_POST
def change_email(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "login required"}, status=401)
    email = request.POST.get("email", "")
    User.objects.filter(pk=request.user.pk).update(email=email)
    return JsonResponse({"message": "email updated", "email": email})


@require_GET
def get_note(request, note_id):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "login required"}, status=401)
    note = Note.objects.filter(pk=note_id).first()
    if note is None:
        return JsonResponse({"error": "not found"}, status=404)
    if SECURE and note.owner_id != request.user.pk:
        return JsonResponse({"error": "forbidden"}, status=403)
    return JsonResponse({"id": note.pk, "owner_id": note.owner_id, "text": note.text})


@require_GET
def greet(request):
    name = request.GET.get("name", "")
    return render(_greet_tmpl, n=name if SECURE else mark_safe(name))


@require_GET
def profile(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "login required"}, status=401)
    return JsonResponse({"username": request.user.username, "email": request.user.email})


@csrf_exempt
@require_POST
def reset_state(request):
    if not getattr(settings, "TEST_MODE", False):
        return JsonResponse({"error": "not found"}, status=404)
    Comment.objects.all().delete()
    for u in User.objects.all():
        u.email = f"{u.username}@example.com"
        u.save(update_fields=["email"])
    return JsonResponse({"message": "reset"})