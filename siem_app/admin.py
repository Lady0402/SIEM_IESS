from django.contrib import admin
from .models import (
    SecurityEvent, Alert, Incident, SystemLog, Server, 
    SecurityRule, Report, UserProfile, DashboardMetrics
)

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'event_type', 'source_ip', 'severity', 'state', 'assigned_to']
    list_filter = ['event_type', 'severity', 'state', 'category']
    search_fields = ['source_ip', 'description', 'event_type']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('event_type', 'source_ip', 'destination_ip', 'category', 'severity')
        }),
        ('Red', {
            'fields': ('source_port', 'destination_port', 'protocol')
        }),
        ('Estado y Asignación', {
            'fields': ('state', 'assigned_to')
        }),
        ('Detalles', {
            'fields': ('description', 'raw_data')
        }),
        ('Timestamps', {
            'fields': ('timestamp',),
            'classes': ('collapse',)
        })
    )

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'alert_type', 'state', 'event', 'assigned_to', 'created_at']
    list_filter = ['alert_type', 'state']
    search_fields = ['title', 'description']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ['title', 'priority', 'state', 'assigned_to', 'created_at']
    list_filter = ['priority', 'state']
    search_fields = ['title', 'description']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    filter_horizontal = ['events']

@admin.register(SystemLog)
class SystemLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'level', 'source', 'message', 'user', 'ip_address']
    list_filter = ['level', 'source']
    search_fields = ['message', 'source']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    readonly_fields = ['timestamp']

@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ['name', 'ip_address', 'server_type', 'state', 'cpu_usage', 'memory_usage', 'last_update']
    list_filter = ['server_type', 'state']
    search_fields = ['name', 'ip_address']
    ordering = ['name']
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('name', 'ip_address', 'server_type', 'state')
        }),
        ('Métricas de Rendimiento', {
            'fields': ('cpu_usage', 'memory_usage', 'disk_usage', 'temperature', 'uptime_days', 'threats_count')
        })
    )

@admin.register(SecurityRule)
class SecurityRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'rule_type', 'severity', 'is_active', 'created_at']
    list_filter = ['rule_type', 'severity', 'is_active']
    search_fields = ['name', 'description']
    date_hierarchy = 'created_at'
    ordering = ['name']

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'report_type', 'generated_by', 'date_from', 'date_to', 'created_at']
    list_filter = ['report_type']
    search_fields = ['title']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    readonly_fields = ['created_at']

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'department', 'is_locked', 'failed_login_attempts']
    list_filter = ['role', 'is_locked']
    search_fields = ['user__username', 'user__email', 'department']

@admin.register(DashboardMetrics)
class DashboardMetricsAdmin(admin.ModelAdmin):
    list_display = ['date', 'total_events', 'critical_alerts', 'total_incidents', 'security_score']
    ordering = ['-date']
    readonly_fields = ['date']

# Personalizar el sitio de administración
admin.site.site_header = "SIEM IESS - Administración"
admin.site.site_title = "SIEM IESS Admin"
admin.site.index_title = "Panel de Administración del Sistema"
