# user/auth.py
from django.contrib.auth import get_user_model
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication

User = get_user_model()


class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        validated_user = JWTAuthentication().authenticate(request)  # type: ignore
        if validated_user is not None:
            user, _ = validated_user
            return user
        return None
