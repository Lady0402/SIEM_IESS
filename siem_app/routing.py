from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
    re_path(r'ws/alerts/$', consumers.AlertsConsumer.as_asgi()),
    re_path(r'ws/logs/$', consumers.LogsConsumer.as_asgi()),
]
