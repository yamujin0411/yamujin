from ninja import NinjaAPI

api = NinjaAPI()

api.add_router("user", "user.api.router")
