from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.urls import path

@csrf_exempt # щоб запит без токена не повертав 403 одразу, а показав дефолтну поведінку сесії
def login_view(request):
    request.session["x"] = 1
    return HttpResponse("Logged in (Django Plain)")

urlpatterns = [
    path('login', login_view),
]