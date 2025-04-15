from common.schema import ErrorResponse
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password, make_password
from ninja import Router
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from user.auth import JWTAuth
from user.schema import (
    AccessTokenSchema,
    LoginSchema,
    LogoutSchema,
    PasswordChangeSchema,
    RefreshTokenSchema,
    RegisterSchema,
    TokenResponse,
    UserMeSchema,
)

User = get_user_model()
router = Router(tags=["User"])


@router.get("/me", response={200: UserMeSchema, 400: ErrorResponse}, auth=JWTAuth())
def get_current_user(request):
    try:
        user = request.auth  # 인증된 사용자 객체
        return UserMeSchema(id=user.id, username=user.username)
    except Exception as e:
        return 400, {"error": str(e)}


@router.post("/register")
def register(request, data: RegisterSchema):
    if User.objects.filter(username=data.username).exists():
        return {"error": "Username already exists"}

    user = User.objects.create(
        username=data.username, password=make_password(data.password)
    )
    return {"message": "User registered successfully", "user_id": user.pk}


@router.post("/login", response={200: TokenResponse, 401: ErrorResponse})
def login(request, data: LoginSchema):
    user = authenticate(username=data.username, password=data.password)
    if not user:
        return 401, {"error": "Invalid credentials"}

    refresh = RefreshToken.for_user(user)
    return TokenResponse(access=str(refresh.access_token), refresh=str(refresh))


@router.post(
    "/change-password", response={204: None, 400: ErrorResponse}, auth=JWTAuth()
)
def change_password(request, data: PasswordChangeSchema):
    user = request.auth

    if not check_password(data.current_password, user.password):
        return 400, {"error": "Current password is incorrect"}

    user.set_password(data.new_password)
    user.save()
    return 204, None


@router.post("/refresh", response={200: AccessTokenSchema, 400: ErrorResponse})
def refresh_token(request, data: RefreshTokenSchema):
    try:
        refresh = RefreshToken(data.refresh)  # type: ignore
        access_token = str(refresh.access_token)
        return {"access": access_token}
    except TokenError:
        return 400, {"error": "Invalid refresh token"}


@router.post("/logout", response={204: None, 400: ErrorResponse})
def logout(request, data: LogoutSchema):
    try:
        token = RefreshToken(data.refresh)  # type: ignore
        token.blacklist()  # 블랙리스트에 등록
        return 204, None
    except TokenError as e:
        return 400, {"error": f"Invalid token: {str(e)}"}
