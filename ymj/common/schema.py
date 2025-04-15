from ninja import Schema


class ErrorResponse(Schema):
    error: str
