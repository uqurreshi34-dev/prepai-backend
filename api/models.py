import uuid
from datetime import timedelta
from django.utils import timezone
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


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)

    def is_valid(self):
        return not self.used and self.created_at >= timezone.now() - timedelta(hours=1)


class Session(models.Model):
    ROLE_CHOICES = [
        ("junior_developer", "Junior Developer"),
        ("marketing_graduate", "Marketing Graduate"),
        ("finance_analyst", "Finance Analyst"),
        ("nursing", "Nursing"),
        ("general", "General"),
    ]
    INTERVIEW_TYPE_CHOICES = [
        ("behavioural", "Behavioural"),
        ("technical", "Technical"),
        ("mixed", "Mixed"),
    ]
    EXPERIENCE_CHOICES = [
        ("junior", "Junior"),
        ("mid", "Mid-level"),
        ("senior", "Senior"),
    ]
    INPUT_MODE_CHOICES = [
        ("text", "Text"),
        ("voice", "Voice"),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sessions")
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)
    interview_type = models.CharField(
        max_length=20, choices=INTERVIEW_TYPE_CHOICES)
    experience_level = models.CharField(
        max_length=20, choices=EXPERIENCE_CHOICES)
    input_mode = models.CharField(max_length=10, choices=INPUT_MODE_CHOICES)
    question_count = models.IntegerField(default=5)
    overall_score = models.FloatField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} — {self.role} ({self.created_at.date()})"


class Question(models.Model):
    session = models.ForeignKey(
        Session, on_delete=models.CASCADE, related_name="questions")
    question_number = models.IntegerField()
    question_text = models.TextField()
    answer_text = models.TextField(blank=True)
    clarity_score = models.IntegerField(null=True, blank=True)
    relevance_score = models.IntegerField(null=True, blank=True)
    depth_score = models.IntegerField(null=True, blank=True)
    feedback_tip = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["question_number"]

    def __str__(self):
        return f"Q{self.question_number} — Session {self.session.id}"
