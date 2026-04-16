import os
import json
from datetime import timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import anthropic

from .models import (User, PasswordResetToken, Session,
                     Question, EmailVerificationToken,
                     WaitlistEntry)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


def send_reset_email(to_email, reset_url):
    message = Mail(
        from_email=os.getenv("FROM_EMAIL"),
        to_emails=to_email,
        subject="Reset your RehearsAI password",
        html_content=f"""
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
            <h2 style="color: #059669;">RehearsAI</h2>
            <p>You requested a password reset. Click the button below to choose a new password.</p>
            <a href="{reset_url}"
               style="display: inline-block; background: #059669; color: white;
                      padding: 12px 24px; border-radius: 8px; text-decoration: none;
                      font-weight: bold; margin: 16px 0;">
                Reset password
            </a>
            <p style="color: #888; font-size: 13px;">
                This link expires in 1 hour. If you didn't request this, ignore this email.
            </p>
        </div>
        """
    )
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        sg.send(message)
    except Exception as e:
        print(f"SendGrid error: {e}")


def send_verification_email(to_email, verify_url):
    message = Mail(
        from_email=os.getenv("FROM_EMAIL"),
        to_emails=to_email,
        subject="Verify your RehearsAI email address",
        html_content=f"""
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
            <h2 style="color: #059669;">RehearsAI</h2>
            <p>Thanks for signing up. Click the button below to verify your email address and activate your account.</p>
            <a href="{verify_url}"
               style="display: inline-block; background: #059669; color: white;
                      padding: 12px 24px; border-radius: 8px; text-decoration: none;
                      font-weight: bold; margin: 16px 0;">
                Verify email address
            </a>
            <p style="color: #888; font-size: 13px;">
                This link expires in 24 hours. If you didn't create a RehearsAI account, ignore this email.
            </p>
        </div>
        """
    )
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        sg.send(message)
    except Exception as e:
        print(f"SendGrid error: {e}")


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    email = request.data.get("email", "").strip().lower()
    password = request.data.get("password", "")
    name = request.data.get("name", "").strip()

    name_parts = name.split(" ", 1)
    first_name = name_parts[0]
    last_name = name_parts[1] if len(name_parts) > 1 else ""

    if not email or not password or not name:
        return Response({"error": "Name, email and password are required."}, status=400)

    if User.objects.filter(email=email).exists():
        return Response({"error": "An account with this email already exists."}, status=400)

    user = User.objects.create_user(
        username=email,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        is_email_verified=False,
    )

    token = EmailVerificationToken.objects.create(user=user)
    frontend_url = os.getenv(
        "FRONTEND_URL", "http://localhost:3000").split(",")[0].strip()
    verify_url = f"{frontend_url}/verify-email?token={token.token}"
    send_verification_email(user.email, verify_url)

    return Response({
        "message": "Account created. Please check your email to verify your account."
    }, status=201)


@api_view(["POST"])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get("email", "").strip().lower()
    password = request.data.get("password", "")

    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({"error": "Invalid email or password."}, status=401)

    if not user.is_email_verified:
        return Response({
            "error": "email_not_verified",
            "message": "Please verify your email before logging in."
        }, status=403)

    tokens = get_tokens_for_user(user)
    return Response({
        "user": {"id": user.id, "email": user.email, "name": user.first_name, "is_pro": user.is_pro},
        **tokens
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    user = request.user
    return Response({
        "id": user.id,
        "email": user.email,
        "name": user.first_name,
        "is_pro": user.is_pro,
        "target_role": user.target_role,
        "experience_level": user.experience_level,
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def logout(request):
    try:
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
    except Exception:
        pass
    return Response({"message": "Logged out."})


@api_view(["POST"])
@permission_classes([AllowAny])
def google_auth(request):
    token = request.data.get("id_token")
    if not token:
        return Response({"error": "ID token required."}, status=400)

    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID")
        )
    except ValueError:
        return Response({"error": "Invalid Google token."}, status=401)

    email = idinfo.get("email", "").lower()
    name = idinfo.get("name", "")
    google_id = idinfo.get("sub")

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "first_name": name,
            "google_id": google_id,
            "is_email_verified": True,
        }
    )

    if not created and not user.google_id:
        user.google_id = google_id
        user.save()

    tokens = get_tokens_for_user(user)
    return Response({
        "user": {"id": user.id, "email": user.email, "name": user.first_name, "is_pro": user.is_pro},
        **tokens
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    email = request.data.get("email", "").strip().lower()
    if not email:
        return Response({"error": "Email is required."}, status=400)

    try:
        user = User.objects.get(email=email)
        token = PasswordResetToken.objects.create(user=user)
        frontend_url = os.getenv(
            "FRONTEND_URL", "http://localhost:3000").split(",")[0].strip()
        reset_url = f"{frontend_url}/reset-password?token={token.token}"
        send_reset_email(user.email, reset_url)
    except User.DoesNotExist:
        pass

    return Response({"message": "If that email exists, a reset link has been sent."})


@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request):
    token_str = request.data.get("token", "")
    password = request.data.get("password", "")

    if not token_str or not password:
        return Response({"error": "Token and password are required."}, status=400)

    if len(password) < 8:
        return Response({"error": "Password must be at least 8 characters."}, status=400)

    try:
        token = PasswordResetToken.objects.get(token=token_str)
    except PasswordResetToken.DoesNotExist:
        return Response({"error": "Invalid or expired reset link."}, status=400)

    if not token.is_valid():
        return Response({"error": "This reset link has expired. Please request a new one."}, status=400)

    user = token.user
    user.set_password(password)
    user.save()
    token.used = True
    token.save()

    return Response({"message": "Password reset successfully."})


@api_view(["POST"])
@permission_classes([AllowAny])
def create_session(request):
    user = request.user if request.user.is_authenticated else None
    if not user:
        return Response({"error": "Authentication required."}, status=401)

    now = timezone.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    sessions_this_month = Session.objects.filter(
        user=user, created_at__gte=month_start).count()

    if not user.is_pro and sessions_this_month >= 3:
        return Response({"error": "free_tier_limit"}, status=403)

    role = request.data.get("role", "general")
    interview_type = request.data.get("interview_type", "behavioural")
    question_count = int(request.data.get("question_count", 5))
    input_mode = request.data.get("input_mode", "text")

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    role_label = dict(Session.ROLE_CHOICES).get(role, role)

    prompt = f"""Generate {question_count} {interview_type} interview questions for a {role_label} role.

Return ONLY a JSON array of strings, no other text. Example:
["Question 1?", "Question 2?", "Question 3?"]"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        content = message.content[0].text.strip()
        question_list = json.loads(content)
    except Exception:
        question_list = [
            f"Tell me about your experience as a {role_label}." for _ in range(question_count)]

    session = Session.objects.create(
        user=user,
        role=role,
        interview_type=interview_type,
        question_count=question_count,
        input_mode=input_mode,
    )

    for i, q_text in enumerate(question_list[:question_count], 1):
        Question.objects.create(
            session=session,
            question_number=i,
            question_text=q_text,
        )

    return Response({"session_id": session.id})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_session(request, session_id):
    try:
        session = Session.objects.get(id=session_id, user=request.user)
    except Session.DoesNotExist:
        return Response({"error": "Session not found."}, status=404)

    questions = Question.objects.filter(
        session=session).order_by("question_number")

    return Response({
        "id": session.id,
        "role": session.role,
        "interview_type": session.interview_type,
        "question_count": session.question_count,
        "input_mode": session.input_mode,
        "questions": [
            {
                "id": q.id,
                "question_number": q.question_number,
                "question_text": q.question_text,
                "answer_text": q.answer_text,
                "score": round((q.clarity_score + q.relevance_score + q.depth_score) / 3, 1) if q.clarity_score is not None else None,
                "feedback": q.feedback_tip,
                "tip": None,
            }
            for q in questions
        ]
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def evaluate_answer(request, session_id, question_id):
    try:
        session = Session.objects.get(id=session_id, user=request.user)
        question = Question.objects.get(id=question_id, session=session)
    except (Session.DoesNotExist, Question.DoesNotExist):
        return Response({"error": "Not found."}, status=404)

    answer = request.data.get("answer", "").strip()
    if not answer:
        return Response({"error": "Answer is required."}, status=400)

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    role_label = dict(Session.ROLE_CHOICES).get(session.role, session.role)

    prompt = f"""You are an expert interview coach evaluating a candidate's answer.

Role: {role_label}
Interview type: {session.interview_type}
Question: {question.question_text}
Answer: {answer}

Evaluate this answer and return ONLY a JSON object with this exact structure:
{{
    "clarity_score": <integer 1-10>,
    "relevance_score": <integer 1-10>,
    "depth_score": <integer 1-10>,
    "feedback_tip": "<2-3 sentence evaluation followed by one specific improvement tip>"
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}]
        )
        content = message.content[0].text.strip()
        result = json.loads(content)
        clarity = int(result.get("clarity_score", 5))
        relevance = int(result.get("relevance_score", 5))
        depth = int(result.get("depth_score", 5))
        feedback_tip = result.get(
            "feedback_tip", "Good attempt. Try to use the STAR method.")
    except Exception:
        clarity = relevance = depth = 5
        feedback_tip = "Your answer was received. Try to use the STAR method: Situation, Task, Action, Result."

    question.answer_text = answer
    question.clarity_score = clarity
    question.relevance_score = relevance
    question.depth_score = depth
    question.feedback_tip = feedback_tip
    question.save()

    score = round((clarity + relevance + depth) / 3, 1)

    return Response({
        "score": score,
        "feedback": feedback_tip,
        "tip": feedback_tip,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def complete_session(request, session_id):
    try:
        session = Session.objects.get(id=session_id, user=request.user)
    except Session.DoesNotExist:
        return Response({"error": "Session not found."}, status=404)

    questions = Question.objects.filter(
        session=session,
        clarity_score__isnull=False
    ).order_by("question_number")

    if not questions.exists():
        return Response({"error": "No answered questions found."}, status=400)

    scores = [round((q.clarity_score + q.relevance_score +
                    q.depth_score) / 3, 1) for q in questions]
    overall_score = round(sum(scores) / len(scores), 1)

    session_data = [
        {
            "question": q.question_text,
            "answer": q.answer_text,
            "score": round((q.clarity_score + q.relevance_score + q.depth_score) / 3, 1),
            "feedback": q.feedback_tip,
            "tip": q.feedback_tip,
        }
        for q in questions
    ]

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    role_label = dict(Session.ROLE_CHOICES).get(session.role, session.role)

    prompt = f"""You are an expert interview coach. Here is a complete interview session for a {role_label} role:

{json.dumps(session_data, indent=2)}

Overall score: {overall_score}/10

Provide a summary returning ONLY a JSON object with this exact structure:
{{
    "strengths": ["<strength 1>", "<strength 2>", "<strength 3>"],
    "weaknesses": ["<weakness 1>", "<weakness 2>"],
    "practice_questions": ["<practice question 1>", "<practice question 2>", "<practice question 3>"]
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        content = message.content[0].text.strip()
        summary = json.loads(content)
    except Exception:
        summary = {
            "strengths": [],
            "weaknesses": [],
            "practice_questions": []
        }

    session.overall_score = overall_score
    session.completed_at = timezone.now()
    session.save()

    return Response({
        "overall_score": overall_score,
        "strengths": summary.get("strengths", []),
        "weaknesses": summary.get("weaknesses", []),
        "practice_questions": summary.get("practice_questions", []),
        "questions": session_data,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    user = request.user
    now = timezone.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    sessions_this_month = Session.objects.filter(
        user=user,
        created_at__gte=month_start
    ).count()

    completed_sessions = Session.objects.filter(
        user=user,
        overall_score__isnull=False
    ).order_by("-completed_at")

    average_score = None
    if completed_sessions.exists():
        scores = [s.overall_score for s in completed_sessions]
        average_score = round(sum(scores) / len(scores), 1)

    last_score = None
    last_role = None
    if completed_sessions.exists():
        last = completed_sessions.first()
        last_score = last.overall_score
        last_role = dict(Session.ROLE_CHOICES).get(last.role, last.role)

    streak = 0
    check_date = now.date()
    while True:
        day_sessions = Session.objects.filter(
            user=user,
            overall_score__isnull=False,
            completed_at__date=check_date
        ).exists()
        if day_sessions:
            streak += 1
            check_date -= timedelta(days=1)
        else:
            break

    return Response({
        "sessions_this_month": sessions_this_month,
        "sessions_remaining": max(0, 3 - sessions_this_month),
        "average_score": average_score,
        "last_score": last_score,
        "last_role": last_role,
        "streak": streak,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_profile(request):
    user = request.user
    target_role = request.data.get("target_role", "").strip()

    valid_roles = [r[0] for r in Session.ROLE_CHOICES]
    if target_role and target_role not in valid_roles:
        return Response({"error": "Invalid role."}, status=400)

    user.target_role = target_role
    user.save()

    return Response({
        "id": user.id,
        "email": user.email,
        "name": user.first_name,
        "target_role": user.target_role,
        "is_pro": user.is_pro,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def session_history(request):
    sessions = Session.objects.filter(
        user=request.user
    ).order_by("-created_at")[:20]

    return Response([
        {
            "id": s.id,
            "role": dict(Session.ROLE_CHOICES).get(s.role, s.role),
            "interview_type": s.interview_type,
            "question_count": s.question_count,
            "overall_score": s.overall_score,
            "completed": s.completed_at is not None,
            "created_at": s.created_at.strftime("%d %b %Y"),
        }
        for s in sessions
    ])


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_email(request):
    token_str = request.data.get("token", "")
    if not token_str:
        return Response({"error": "Token is required."}, status=400)

    try:
        token = EmailVerificationToken.objects.get(token=token_str)
    except EmailVerificationToken.DoesNotExist:
        return Response({"error": "Invalid or expired verification link."}, status=400)

    if not token.is_valid():
        return Response({"error": "This verification link has expired. Please request a new one."}, status=400)

    token.user.is_email_verified = True
    token.user.save()
    token.used = True
    token.save()

    tokens = get_tokens_for_user(token.user)
    return Response({
        "message": "Email verified successfully.",
        "user": {
            "id": token.user.id,
            "email": token.user.email,
            "name": token.user.first_name,
            "is_pro": token.user.is_pro
        },
        **tokens
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def resend_verification(request):
    email = request.data.get("email", "").strip().lower()
    if not email:
        return Response({"error": "Email is required."}, status=400)

    try:
        user = User.objects.get(email=email)
        if user.is_email_verified:
            return Response({"message": "This email is already verified."})

        token = EmailVerificationToken.objects.create(user=user)
        frontend_url = os.getenv(
            "FRONTEND_URL", "http://localhost:3000").split(",")[0].strip()
        verify_url = f"{frontend_url}/verify-email?token={token.token}"
        send_verification_email(user.email, verify_url)
    except User.DoesNotExist:
        pass

    return Response({"message": "If that account exists and is unverified, a new link has been sent."})


@api_view(["GET"])
@permission_classes([AllowAny])
def admin_stats(request):
    secret = request.GET.get("secret", "")
    if secret != os.getenv("ADMIN_SECRET", ""):
        return Response({"error": "Forbidden"}, status=403)

    users = User.objects.filter(is_superuser=False).order_by("-created_at")
    total_sessions = Session.objects.count()
    verified_count = User.objects.filter(
        is_email_verified=True, is_superuser=False).count()
    waitlist_count = WaitlistEntry.objects.count()

    completed_sessions = Session.objects.filter(overall_score__isnull=False)
    avg_score = None
    if completed_sessions.exists():
        scores = [s.overall_score for s in completed_sessions]
        avg_score = round(sum(scores) / len(scores), 1)

    user_data = []
    for user in users:
        user_sessions = Session.objects.filter(user=user)
        completed = user_sessions.filter(overall_score__isnull=False)
        user_avg = None
        if completed.exists():
            s = [c.overall_score for c in completed]
            user_avg = round(sum(s) / len(s), 1)

        user_data.append({
            "id": user.id,
            "name": user.get_full_name() or user.first_name or "—",
            "email": user.email,
            "joined": user.created_at.strftime("%d %b %Y"),
            "sessions": user_sessions.count(),
            "avg_score": user_avg,
            "is_email_verified": user.is_email_verified,
            "is_pro": user.is_pro,
            "google": bool(user.google_id),
        })

    waitlist = WaitlistEntry.objects.order_by("-created_at")
    waitlist_data = [
        {"email": w.email, "joined": w.created_at.strftime("%d %b %Y")}
        for w in waitlist
    ]

    return Response({
        "total_users": users.count(),
        "total_sessions": total_sessions,
        "verified_emails": verified_count,
        "avg_score": avg_score,
        "waitlist_count": waitlist_count,
        "waitlist": waitlist_data,
        "users": user_data,
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def join_waitlist(request):
    email = request.data.get("email", "").strip().lower()
    if not email:
        return Response({"error": "Email is required."}, status=400)

    if WaitlistEntry.objects.filter(email=email).exists():
        return Response({"message": "You're already on the waitlist!"})

    WaitlistEntry.objects.create(email=email)
    return Response({"message": "You're on the list! We'll be in touch soon."}, status=201)
