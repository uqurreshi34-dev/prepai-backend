import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from .models import User, PasswordResetToken, Session, Question
import anthropic
import json


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
    )
    tokens = get_tokens_for_user(user)
    return Response({
        "user": {"id": user.id, "email": user.email, "name": user.first_name, "is_pro": user.is_pro},
        **tokens
    }, status=201)


@api_view(["POST"])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get("email", "").strip().lower()
    password = request.data.get("password", "")

    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({"error": "Invalid email or password."}, status=401)

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
