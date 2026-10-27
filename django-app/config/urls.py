
from django.urls import path
from core import views

urlpatterns = [
    path("", views.index),
    path("login", views.login_view),
    path("search", views.search),
    path("comments", views.comments),
    path("csrf-token", views.csrf_token),
    path("profile/email", views.change_email),
    path("notes/<int:note_id>", views.get_note),
    path("profile", views.profile),
    path("__reset", views.reset_state),
]
