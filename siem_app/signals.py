from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import SecurityEvent, Alert, UserProfile, SystemLog

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile when a new User is created"""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save UserProfile when User is saved"""
    if hasattr(instance, 'userprofile'):
        instance.userprofile.save()

@receiver(post_save, sender=SecurityEvent)
def create_alert_for_critical_event(sender, instance, created, **kwargs):
    """Automatically create alert for critical security events"""
    if created and instance.severity == 'critical':
        Alert.objects.create(
            title=f"Evento crítico: {instance.event_type}",
            description=f"Se detectó un evento crítico desde {instance.source_ip}",
            alert_type='critical',
            event=instance
        )
        
        # Log the alert creation
        SystemLog.objects.create(
            level='WARNING',
            source='security',
            message=f"Alerta crítica creada automáticamente para evento {instance.id}",
            additional_data={'event_id': instance.id}
        )

@receiver(post_save, sender=Alert)
def log_alert_creation(sender, instance, created, **kwargs):
    """Log when alerts are created or updated"""
    if created:
        SystemLog.objects.create(
            level='INFO',
            source='security',
            message=f"Nueva alerta creada: {instance.title}",
            additional_data={'alert_id': instance.id, 'alert_type': instance.alert_type}
        )
