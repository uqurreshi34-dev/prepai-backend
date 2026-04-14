from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, PasswordResetToken, Session, Question, EmailVerificationToken


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        ("PrepAI", {"fields": ("target_role", "experience_level",
         "is_pro", "is_email_verified", "google_id")}),
    )


admin.site.register(PasswordResetToken)
admin.site.register(Session)
admin.site.register(Question)
admin.site.register(EmailVerificationToken)
