from django.apps import AppConfig

class SiemAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'siem_app'
    verbose_name = 'SIEM IESS Application'
    
    def ready(self):
        import siem_app.signals
