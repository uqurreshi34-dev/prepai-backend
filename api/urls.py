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
    path("sessions/create/", views.create_session),
    path("sessions/<int:session_id>/", views.get_session),
    path("sessions/<int:session_id>/questions/<int:question_id>/evaluate/",
         views.evaluate_answer),
    path("sessions/<int:session_id>/complete/", views.complete_session),
]
