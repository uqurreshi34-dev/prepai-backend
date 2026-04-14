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
                     Question, EmailVerificationToken)


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
        subject="Reset your PrepAI password",
        html_content=f"""
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
            <h2 style="color: #059669;">PrepAI</h2>
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
        subject="Verify your PrepAI email address",
        html_content=f"""
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
            <h2 style="color: #059669;">PrepAI</h2>
            <p>Thanks for signing up. Click the button below to verify your email address and activate your account.</p>
            <a href="{verify_url}"
               style="display: inline-block; background: #059669; color: white;
                      padding: 12px 24px; border-radius: 8px; text-decoration: none;
                      font-weight: bold; margin: 16px 0;">
                Verify email address
            </a>
            <p style="color: #888; font-size: 13px;">
                This link expires in 24 hours. If you didn't create a PrepAI account, ignore this email.
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

    if not email or not password or not name:
        return Response({"error": "Name, email and password are required."}, status=400)

    if User.objects.filter(email=email).exists():
        return Response({"error": "An account with this email already exists."}, status=400)

    user = User.objects.create_user(
        username=email,
        email=email,
        password=password,
        first_name=name,
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

    token.user.set_password(password)
    token.user.save()
    token.used = True
    token.save()

    return Response({"message": "Password reset successfully."})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_session(request):
    user = request.user
    role = request.data.get("role")
    interview_type = request.data.get("interview_type")
    input_mode = request.data.get("input_mode", "text")
    question_count = int(request.data.get("question_count", 5))

    if not all([role, interview_type]):
        return Response({"error": "Role and interview type are required."}, status=400)

    now = timezone.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    if not user.is_pro:
        sessions_this_month = Session.objects.filter(
            user=user,
            created_at__gte=month_start
        ).count()
        if sessions_this_month >= 3:
            return Response({
                "error": "free_tier_limit",
                "message": "You have used all 3 free sessions this month. Upgrade to Pro for unlimited sessions."
            }, status=403)

    role_display = dict(Session.ROLE_CHOICES).get(role, role)

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": f"""Generate {question_count} realistic {interview_type} interview questions 
                for a {role_display} candidate. 
                Return ONLY a JSON array of strings. No preamble, no markdown, no explanation.
                Example: ["Question 1?", "Question 2?"]"""
            }]
        )

        raw = message.content[0].text.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        questions_list = json.loads(raw)

    except Exception as e:
        return Response({"error": f"Failed to generate questions: {str(e)}"}, status=500)

    session = Session.objects.create(
        user=user,
        role=role,
        interview_type=interview_type,
        experience_level="junior",
        input_mode=input_mode,
        question_count=question_count,
    )

    questions = []
    for i, q_text in enumerate(questions_list):
        q = Question.objects.create(
            session=session,
            question_number=i + 1,
            question_text=q_text,
        )
        questions.append({
            "id": q.id,
            "question_number": q.question_number,
            "question_text": q.question_text
        })

    return Response({
        "session_id": session.id,
        "questions": questions,
        "input_mode": session.input_mode,
    }, status=201)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_session(request, session_id):
    try:
        session = Session.objects.get(id=session_id, user=request.user)
    except Session.DoesNotExist:
        return Response({"error": "Session not found."}, status=404)

    questions = session.questions.all()
    return Response({
        "session_id": session.id,
        "role": session.role,
        "interview_type": session.interview_type,
        "experience_level": session.experience_level,
        "input_mode": session.input_mode,
        "question_count": session.question_count,
        "overall_score": session.overall_score,
        "questions": [
            {
                "id": q.id,
                "question_number": q.question_number,
                "question_text": q.question_text,
                "answer_text": q.answer_text,
                "clarity_score": q.clarity_score,
                "relevance_score": q.relevance_score,
                "depth_score": q.depth_score,
                "feedback_tip": q.feedback_tip,
            }
            for q in questions
        ],
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def evaluate_answer(request, session_id, question_id):
    try:
        session = Session.objects.get(id=session_id, user=request.user)
        question = Question.objects.get(id=question_id, session=session)
    except (Session.DoesNotExist, Question.DoesNotExist):
        return Response({"error": "Not found."}, status=404)

    answer_text = request.data.get("answer_text", "").strip()
    if not answer_text:
        return Response({"error": "Answer is required."}, status=400)

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=512,
            messages=[{
                "role": "user",
                "content": f"""You are a strict but fair interview coach. Evaluate this interview answer.
Return ONLY valid JSON, no other text, no markdown:
{{
  "clarity": 7,
  "relevance": 8,
  "depth": 6,
  "tip": "one specific actionable improvement in max 2 sentences"
}}

Question: {question.question_text}
Answer: {answer_text}"""
            }]
        )

        raw = message.content[0].text.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        feedback = json.loads(raw)

    except Exception as e:
        return Response({"error": f"Failed to evaluate answer: {str(e)}"}, status=500)

    question.answer_text = answer_text
    question.clarity_score = feedback.get("clarity")
    question.relevance_score = feedback.get("relevance")
    question.depth_score = feedback.get("depth")
    question.feedback_tip = feedback.get("tip", "")
    question.save()

    return Response({
        "clarity": question.clarity_score,
        "relevance": question.relevance_score,
        "depth": question.depth_score,
        "tip": question.feedback_tip,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def complete_session(request, session_id):
    try:
        session = Session.objects.get(id=session_id, user=request.user)
    except Session.DoesNotExist:
        return Response({"error": "Session not found."}, status=404)

    questions = session.questions.filter(clarity_score__isnull=False)
    if not questions.exists():
        return Response({"error": "No answered questions found."}, status=400)

    all_scores = []
    session_data = []
    for q in questions:
        avg = (q.clarity_score + q.relevance_score + q.depth_score) / 3
        all_scores.append(avg)
        session_data.append({
            "question": q.question_text,
            "answer": q.answer_text,
            "clarity": q.clarity_score,
            "relevance": q.relevance_score,
            "depth": q.depth_score,
        })

    overall_score = round(sum(all_scores) / len(all_scores), 1)

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": f"""You are an interview coach reviewing a completed practice session.
Return ONLY valid JSON, no other text, no markdown:
{{
  "strengths": ["specific strength 1", "specific strength 2", "specific strength 3"],
  "weaknesses": ["specific weakness 1", "specific weakness 2", "specific weakness 3"],
  "practice_questions": ["follow up question 1", "follow up question 2", "follow up question 3"]
}}

Session data: {json.dumps(session_data)}"""
            }]
        )

        raw = message.content[0].text.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        summary = json.loads(raw)

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
