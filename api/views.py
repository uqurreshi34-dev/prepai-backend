import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import User


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


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
