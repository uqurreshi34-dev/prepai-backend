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
    path("dashboard/stats/", views.dashboard_stats),
    path("auth/profile/", views.update_profile),
    path("sessions/history/", views.session_history),
    path("auth/verify-email/", views.verify_email),
    path("auth/resend-verification/", views.resend_verification),
    path("admin-stats/", views.admin_stats),
    path("waitlist/", views.join_waitlist),
    path("auth/microsoft/", views.microsoft_auth),
]
