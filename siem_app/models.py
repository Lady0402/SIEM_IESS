from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import json

class SecurityEvent(models.Model):
    SEVERITY_CHOICES = [
        ('info', 'Información'),
        ('low', 'Baja'),
        ('medium', 'Media'),
        ('high', 'Alta'),
        ('critical', 'Crítica'),
    ]
    
    CATEGORY_CHOICES = [
        ('authentication_failure', 'Fallo de Autenticación'),
        ('data_exfiltration', 'Exfiltración de Datos'),
        ('intrusion_attempt', 'Intento de Intrusión'),
        ('malware_detection', 'Detección de Malware'),
        ('network_anomaly', 'Anomalía de Red'),
        ('suspicious_activity', 'Actividad Sospechosa'),
        ('privilege_escalation', 'Escalación de Privilegios'),
        ('ddos_attack', 'Ataque DDoS'),
        ('sql_injection', 'Inyección SQL'),
        ('xss_attack', 'Ataque XSS'),
    ]
    
    STATE_CHOICES = [
        ('new', 'Nuevo'),
        ('investigating', 'Investigando'),
        ('resolved', 'Resuelto'),
        ('false_positive', 'Falso Positivo'),
        ('closed', 'Cerrado'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    event_type = models.CharField(max_length=100)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, default='TCP')
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default='new', db_index=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField()
    raw_data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'severity']),
            models.Index(fields=['source_ip', 'timestamp']),
            models.Index(fields=['category', 'state']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.source_ip} ({self.timestamp})"
    
    def get_severity_color(self):
        colors = {
            'info': 'info',
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'danger'
        }
        return colors.get(self.severity, 'secondary')

class Alert(models.Model):
    ALERT_TYPE_CHOICES = [
        ('critical', 'Crítica'),
        ('medium', 'Media'),
        ('low', 'Baja'),
        ('info', 'Información'),
    ]
    
    STATE_CHOICES = [
        ('active', 'Activa'),
        ('acknowledged', 'Reconocida'),
        ('resolved', 'Resuelta'),
        ('false_positive', 'Falso Positivo'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES)
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default='active')
    event = models.ForeignKey(SecurityEvent, on_delete=models.CASCADE, related_name='alerts')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Alerta: {self.title}"

class Incident(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Baja'),
        ('medium', 'Media'),
        ('high', 'Alta'),
        ('critical', 'Crítica'),
    ]
    
    STATE_CHOICES = [
        ('new', 'Nuevo'),
        ('investigating', 'Investigando'),
        ('resolved', 'Resuelto'),
        ('closed', 'Cerrado'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES)
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default='new')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    events = models.ManyToManyField(SecurityEvent, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.title

class SystemLog(models.Model):
    LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    SOURCE_CHOICES = [
        ('network', 'Red'),
        ('application', 'Aplicación'),
        ('system', 'Sistema'),
        ('security', 'Seguridad'),
        ('database', 'Base de Datos'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, db_index=True)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, db_index=True)
    message = models.TextField()
    user = models.CharField(max_length=100, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    additional_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'level']),
            models.Index(fields=['source', 'level']),
        ]
    
    def __str__(self):
        return f"{self.level} - {self.source} - {self.timestamp}"

class Server(models.Model):
    SERVER_TYPE_CHOICES = [
        ('web', 'Servidor Web'),
        ('database', 'Base de Datos'),
        ('application', 'Aplicación'),
        ('file', 'Archivos'),
        ('mail', 'Correo'),
        ('dns', 'DNS'),
        ('firewall', 'Firewall'),
    ]
    
    STATE_CHOICES = [
        ('active', 'Activo'),
        ('warning', 'Advertencia'),
        ('critical', 'Crítico'),
        ('offline', 'Fuera de línea'),
    ]
    
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(unique=True)
    server_type = models.CharField(max_length=20, choices=SERVER_TYPE_CHOICES)
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default='active')
    cpu_usage = models.FloatField(validators=[MinValueValidator(0), MaxValueValidator(100)], default=0)
    memory_usage = models.FloatField(validators=[MinValueValidator(0), MaxValueValidator(100)], default=0)
    disk_usage = models.FloatField(validators=[MinValueValidator(0), MaxValueValidator(100)], default=0)
    temperature = models.FloatField(default=0)
    uptime_days = models.IntegerField(default=0)
    threats_count = models.IntegerField(default=0)
    last_update = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.ip_address})"
    
    def get_state_color(self):
        colors = {
            'active': 'success',
            'warning': 'warning',
            'critical': 'danger',
            'offline': 'secondary'
        }
        return colors.get(self.state, 'secondary')

class SecurityRule(models.Model):
    RULE_TYPE_CHOICES = [
        ('signature', 'Firma'),
        ('anomaly', 'Anomalía'),
        ('threshold', 'Umbral'),
        ('correlation', 'Correlación'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Baja'),
        ('medium', 'Media'),
        ('high', 'Alta'),
        ('critical', 'Crítica'),
    ]
    
    name = models.CharField(max_length=200)
    description = models.TextField()
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    pattern = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name

class Report(models.Model):
    REPORT_TYPE_CHOICES = [
        ('security', 'Reporte de Seguridad'),
        ('incidents', 'Reporte de Incidentes'),
        ('performance', 'Reporte de Rendimiento'),
        ('compliance', 'Reporte de Cumplimiento'),
        ('threat_analysis', 'Análisis de Amenazas'),
    ]
    
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)
    description = models.TextField(blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    date_from = models.DateTimeField()
    date_to = models.DateTimeField()
    file_path = models.FileField(upload_to='reports/', null=True, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.title

class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrador'),
        ('analyst', 'Analista'),
        ('operator', 'Operador'),
        ('viewer', 'Visualizador'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    department = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    is_locked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.get_role_display()}"

class DashboardMetrics(models.Model):
    date = models.DateField(default=timezone.now, unique=True)
    total_events = models.IntegerField(default=0)
    critical_alerts = models.IntegerField(default=0)
    medium_alerts = models.IntegerField(default=0)
    total_alerts = models.IntegerField(default=0)
    resolved_incidents = models.IntegerField(default=0)
    total_incidents = models.IntegerField(default=0)
    response_time_avg = models.FloatField(default=0.0)
    security_score = models.IntegerField(default=85)
    
    class Meta:
        ordering = ['-date']
    
    def __str__(self):
        return f"Métricas {self.date}"
