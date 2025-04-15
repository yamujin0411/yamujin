from ninja import Schema


class RegisterSchema(Schema):
    username: str
    password: str


class LoginSchema(Schema):
    username: str
    password: str


class TokenResponse(Schema):
    access: str
    refresh: str


class UserMeSchema(Schema):
    id: int
    username: str


class PasswordChangeSchema(Schema):
    current_password: str
    new_password: str


class RefreshTokenSchema(Schema):
    refresh: str


class AccessTokenSchema(Schema):
    access: str


# user/schema.py
class LogoutSchema(Schema):
    refresh: str
