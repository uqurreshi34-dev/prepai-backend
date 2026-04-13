from django.urls import path
from . import views

urlpatterns = [
    path("auth/register/", views.register),
    path("auth/login/", views.login),
    path("auth/logout/", views.logout),
    path("auth/me/", views.me),
    path("auth/google/", views.google_auth),
    path("auth/forgot-password/", views.forgot_password),
    path("auth/reset-password/", views.reset_password),
]
