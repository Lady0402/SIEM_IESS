import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import siem_app.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_iess.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            siem_app.routing.websocket_urlpatterns
        )
    ),
})
