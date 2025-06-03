from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import random
from .models import Server, SystemLog, DashboardMetrics, SecurityEvent, Alert

@shared_task
def update_server_metrics():
    """Update server metrics - this would integrate with actual monitoring tools"""
    servers = Server.objects.all()
    
    for server in servers:
        # In a real system, this would collect actual metrics
        # For demo purposes, we'll simulate the data
        server.cpu_usage = random.uniform(10, 90)
        server.memory_usage = random.uniform(30, 95)
        server.disk_usage = random.uniform(20, 80)
        server.temperature = random.uniform(35, 75)
        
        # Update state based on metrics
        if server.cpu_usage > 90 or server.memory_usage > 95 or server.temperature > 70:
            server.state = 'critical'
        elif server.cpu_usage > 80 or server.memory_usage > 85 or server.temperature > 60:
            server.state = 'warning'
        else:
            server.state = 'active'
        
        server.save()
        
        # Log critical states
        if server.state == 'critical':
            SystemLog.objects.create(
                level='CRITICAL',
                source='system',
                message=f"Servidor {server.name} en estado crítico",
                additional_data={
                    'server_id': server.id,
                    'cpu_usage': server.cpu_usage,
                    'memory_usage': server.memory_usage,
                    'temperature': server.temperature
                }
            )

@shared_task
def update_dashboard_metrics():
    """Update daily dashboard metrics"""
    today = timezone.now().date()
    
    metrics, created = DashboardMetrics.objects.get_or_create(
        date=today,
        defaults={
            'total_events': 0,
            'critical_alerts': 0,
            'medium_alerts': 0,
            'total_alerts': 0,
            'resolved_incidents': 0,
            'total_incidents': 0,
            'response_time_avg': 0.0,
            'security_score': 85
        }
    )
    
    # Update metrics
    metrics.total_events = SecurityEvent.objects.filter(timestamp__date=today).count()
    metrics.critical_alerts = Alert.objects.filter(alert_type='critical', state='active').count()
    metrics.medium_alerts = Alert.objects.filter(alert_type='medium', state='active').count()
    metrics.total_alerts = Alert.objects.filter(created_at__date=today).count()
    
    metrics.save()

@shared_task
def cleanup_old_logs():
    """Clean up old system logs"""
    cutoff_date = timezone.now() - timedelta(days=365)
    deleted_count = SystemLog.objects.filter(timestamp__lt=cutoff_date).delete()[0]
    
    if deleted_count > 0:
        SystemLog.objects.create(
            level='INFO',
            source='system',
            message=f"Limpieza automática: {deleted_count} logs eliminados",
        )

@shared_task
def generate_security_report():
    """Generate automated security reports"""
    # This would generate and email security reports
    pass
