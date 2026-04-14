from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, PasswordResetToken, Session, Question

admin.site.register(User, UserAdmin)
admin.site.register(PasswordResetToken)
admin.site.register(Session)
admin.site.register(Question)
