from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    target_role = models.CharField(max_length=100, blank=True)
    experience_level = models.CharField(
        max_length=20,
        choices=[("junior", "Junior"), ("mid", "Mid"), ("senior", "Senior")],
        default="junior"
    )
    is_pro = models.BooleanField(default=False)
    google_id = models.CharField(
        max_length=100, blank=True, null=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email
