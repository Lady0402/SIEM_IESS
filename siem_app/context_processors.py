from django.utils import timezone
from .models import Alert, SecurityEvent, Incident

def global_context(request):
    """Add global context variables to all templates"""
    if request.user.is_authenticated:
        # Get current alerts count
        critical_alerts = Alert.objects.filter(
            alert_type='critical',
            state='active'
        ).count()
        
        # Get recent events count
        recent_events = SecurityEvent.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
        ).count()
        
        # Get open incidents count
        open_incidents = Incident.objects.filter(
            state__in=['new', 'investigating']
        ).count()
        
        return {
            'critical_alerts_count': critical_alerts,
            'recent_events_count': recent_events,
            'open_incidents_count': open_incidents,
            'current_time': timezone.now(),
        }
    
    return {}
