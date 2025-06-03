import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import SecurityEvent, Alert, SystemLog, DashboardMetrics

class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_group_name = 'dashboard'
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data['type']
        
        if message_type == 'get_metrics':
            metrics = await self.get_dashboard_metrics()
            await self.send(text_data=json.dumps({
                'type': 'metrics_update',
                'data': metrics
            }))

    async def metrics_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'metrics_update',
            'data': event['data']
        }))

    @database_sync_to_async
    def get_dashboard_metrics(self):
        today = timezone.now().date()
        try:
            metrics = DashboardMetrics.objects.get(date=today)
            return {
                'total_events': metrics.total_events,
                'critical_alerts': metrics.critical_alerts,
                'medium_alerts': metrics.medium_alerts,
                'security_score': metrics.security_score,
                'response_time': metrics.response_time_avg,
            }
        except DashboardMetrics.DoesNotExist:
            return {
                'total_events': 0,
                'critical_alerts': 0,
                'medium_alerts': 0,
                'security_score': 85,
                'response_time': 4.2,
            }

class AlertsConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_group_name = 'alerts'
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def new_alert(self, event):
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'alert': event['alert']
        }))

class LogsConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_group_name = 'logs'
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def new_log(self, event):
        await self.send(text_data=json.dumps({
            'type': 'new_log',
            'log': event['log']
        }))
