import random
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth.models import User
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
import os

from .models import (
    SecurityEvent, Alert, Incident, SystemLog, Server, 
    SecurityRule, Report, UserProfile, DashboardMetrics
)

def create_sample_data():
    """Create sample data for the SIEM system"""
    
    print("🚀 Iniciando creación de datos de ejemplo...")
    
    # Create admin user if not exists
    admin_user, created = User.objects.get_or_create(
        username='admin',
        defaults={
            'email': 'admin@iess.gob.ec',
            'first_name': 'Administrador',
            'last_name': 'SIEM',
            'is_superuser': True,
            'is_staff': True
        }
    )
    
    if created:
        admin_user.set_password('admin123')
        admin_user.save()
        print("✅ Usuario admin creado")
    else:
        print("ℹ️ Usuario admin ya existe")
    
    # Create or get admin profile
    admin_profile, created = UserProfile.objects.get_or_create(
        user=admin_user,
        defaults={
            'role': 'admin',
            'department': 'Seguridad Informática'
        }
    )
    
    if created:
        print("✅ Perfil de admin creado")
    else:
        print("ℹ️ Perfil de admin ya existe")
    
    # Create sample users
    users_data = [
        ('analista1', 'analista1@iess.gob.ec', 'Analista', 'Seguridad', 'analyst'),
        ('operador1', 'operador1@iess.gob.ec', 'Operador', 'TI', 'operator'),
        ('viewer1', 'viewer1@iess.gob.ec', 'Visualizador', 'Auditoría', 'viewer'),
    ]
    
    for username, email, first_name, dept, role in users_data:
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'first_name': first_name,
                'last_name': 'Usuario'
            }
        )
        
        if created:
            user.set_password('password123')
            user.save()
            print(f"✅ Usuario {username} creado")
        else:
            print(f"ℹ️ Usuario {username} ya existe")
        
        # Create or get user profile
        profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={
                'role': role,
                'department': dept
            }
        )
        
        if created:
            print(f"✅ Perfil de {username} creado")
        else:
            print(f"ℹ️ Perfil de {username} ya existe")
    
    # Clear existing sample data to avoid duplicates
    print("🧹 Limpiando datos existentes...")
    SecurityEvent.objects.filter(description__contains='Evento de seguridad detectado').delete()
    SystemLog.objects.filter(message__in=[
        'Sistema iniciado correctamente',
        'Falla crítica del servidor',
        'Usuario autenticado exitosamente'
    ]).delete()
    
    # Sample IPs and event types
    sample_ips = [
        '192.168.1.100', '10.0.1.50', '172.16.0.25', '203.243.12.165',
        '129.210.209.4', '127.1.236.57', '149.140.127.216', '251.174.203.210',
        '221.63.205.76', '46.157.13.75', '29.155.184.145', '102.39.215.38'
    ]
    
    event_types = [
        'Port Scan', 'Malware Upload', 'Network Intrusion', 'Suspicious Login',
        'SQL Injection', 'DDoS Attack', 'Privilege Escalation', 'Data Access',
        'XSS Attack', 'Brute Force', 'File Upload', 'Command Injection'
    ]
    
    categories = [
        'authentication_failure', 'data_exfiltration', 'intrusion_attempt',
        'malware_detection', 'network_anomaly', 'suspicious_activity',
        'privilege_escalation', 'ddos_attack', 'sql_injection', 'xss_attack'
    ]
    
    severities = ['info', 'low', 'medium', 'high', 'critical']
    states = ['new', 'investigating', 'resolved', 'false_positive']
    
    print("📊 Creando eventos de seguridad...")
    # Create security events
    events_created = 0
    for i in range(100):
        event = SecurityEvent.objects.create(
            timestamp=timezone.now() - timedelta(hours=random.randint(0, 72)),
            event_type=random.choice(event_types),
            source_ip=random.choice(sample_ips),
            destination_ip=random.choice(sample_ips),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443, 22, 21, 25, 53, 3389]),
            protocol=random.choice(['TCP', 'UDP', 'ICMP']),
            category=random.choice(categories),
            severity=random.choice(severities),
            state=random.choice(states),
            description=f'Evento de seguridad detectado: {random.choice(event_types)}',
            raw_data={
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                'status_code': random.choice([200, 401, 403, 404, 500])
            }
        )
        events_created += 1
        
        # Create alerts for high/critical events
        if event.severity in ['high', 'critical'] and random.random() > 0.3:
            Alert.objects.create(
                title=f'Alerta: {event.event_type}',
                description=f'Se detectó actividad {event.severity} desde {event.source_ip}',
                alert_type=event.severity if event.severity in ['critical', 'medium', 'low'] else 'medium',
                event=event,
                state=random.choice(['active', 'acknowledged', 'resolved'])
            )
    
    print(f"✅ {events_created} eventos de seguridad creados")
    
    # Create incidents
    print("🚨 Creando incidentes...")
    incident_titles = [
        'Intento de intrusión detectado',
        'Múltiples intentos de login fallidos',
        'Actividad sospechosa en servidor web',
        'Posible exfiltración de datos',
        'Ataque DDoS en progreso',
        'Malware detectado en estación de trabajo'
    ]
    
    incidents_created = 0
    for title in incident_titles:
        incident, created = Incident.objects.get_or_create(
            title=title,
            defaults={
                'description': f'Descripción detallada del incidente: {title}',
                'priority': random.choice(['low', 'medium', 'high', 'critical']),
                'state': random.choice(['new', 'investigating', 'resolved']),
                'created_at': timezone.now() - timedelta(hours=random.randint(0, 48))
            }
        )
        
        if created:
            incidents_created += 1
            # Associate some events with incidents
            related_events = SecurityEvent.objects.filter(
                severity__in=['high', 'critical']
            ).order_by('?')[:random.randint(1, 3)]
            incident.events.set(related_events)
    
    print(f"✅ {incidents_created} incidentes creados")
    
    # Create system logs
    print("📝 Creando logs del sistema...")
    log_sources = ['network', 'application', 'system', 'security', 'database']
    log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    
    log_messages = [
        'Sistema iniciado correctamente',
        'Falla crítica del servidor',
        'Usuario autenticado exitosamente',
        'Intento de acceso no autorizado',
        'Base de datos conectada',
        'Error de conexión de red',
        'Backup completado',
        'Configuración actualizada',
        'Servicio reiniciado',
        'Alerta de seguridad generada'
    ]
    
    logs_created = 0
    for i in range(200):
        SystemLog.objects.create(
            timestamp=timezone.now() - timedelta(minutes=random.randint(0, 1440)),
            level=random.choice(log_levels),
            source=random.choice(log_sources),
            message=random.choice(log_messages),
            user=random.choice(['admin', 'user68', 'system', 'analista1']),
            ip_address=random.choice(sample_ips),
            additional_data={
                'process_id': random.randint(1000, 9999),
                'thread_id': random.randint(100, 999)
            }
        )
        logs_created += 1
    
    print(f"✅ {logs_created} logs del sistema creados")
    
    # Create servers
    print("🖥️ Creando servidores...")
    servers_data = [
        ('Servidor Web Principal', '10.0.1.10', 'web'),
        ('Servidor Base de Datos', '10.0.1.20', 'database'),
        ('Servidor de Aplicaciones', '10.0.1.30', 'application'),
        ('Servidor de Archivos', '10.0.1.40', 'file'),
        ('Servidor de Correo', '10.0.1.50', 'mail'),
        ('Servidor DNS', '10.0.1.60', 'dns'),
        ('Firewall Principal', '10.0.1.70', 'firewall'),
    ]
    
    servers_created = 0
    for name, ip, server_type in servers_data:
        server, created = Server.objects.get_or_create(
            ip_address=ip,
            defaults={
                'name': name,
                'server_type': server_type,
                'state': random.choice(['active', 'warning', 'critical']),
                'cpu_usage': random.uniform(10, 90),
                'memory_usage': random.uniform(30, 95),
                'disk_usage': random.uniform(20, 80),
                'temperature': random.uniform(35, 75),
                'uptime_days': random.randint(1, 365),
                'threats_count': random.randint(0, 10)
            }
        )
        
        if created:
            servers_created += 1
    
    print(f"✅ {servers_created} servidores creados")
    
    # Create security rules
    print("🔒 Creando reglas de seguridad...")
    rules_data = [
        ('Detección de Port Scan', 'signature', 'high', 'Detecta intentos de escaneo de puertos'),
        ('Múltiples intentos de login', 'threshold', 'medium', 'Detecta múltiples intentos de autenticación fallidos'),
        ('Tráfico anómalo', 'anomaly', 'medium', 'Detecta patrones de tráfico inusuales'),
        ('Inyección SQL', 'signature', 'critical', 'Detecta intentos de inyección SQL'),
        ('Escalación de privilegios', 'correlation', 'high', 'Detecta intentos de escalación de privilegios'),
    ]
    
    rules_created = 0
    for name, rule_type, severity, description in rules_data:
        rule, created = SecurityRule.objects.get_or_create(
            name=name,
            defaults={
                'description': description,
                'rule_type': rule_type,
                'severity': severity,
                'pattern': f'pattern_{name.lower().replace(" ", "_")}',
                'is_active': True
            }
        )
        
        if created:
            rules_created += 1
    
    print(f"✅ {rules_created} reglas de seguridad creadas")
    
    # Create dashboard metrics
    print("📈 Creando métricas del dashboard...")
    metrics_created = 0
    for i in range(7):
        date = timezone.now().date() - timedelta(days=i)
        metrics, created = DashboardMetrics.objects.get_or_create(
            date=date,
            defaults={
                'total_events': random.randint(50, 200),
                'critical_alerts': random.randint(0, 10),
                'medium_alerts': random.randint(5, 25),
                'total_alerts': random.randint(10, 50),
                'resolved_incidents': random.randint(5, 20),
                'total_incidents': random.randint(10, 30),
                'response_time_avg': random.uniform(2.0, 8.0),
                'security_score': random.randint(75, 95)
            }
        )
        
        if created:
            metrics_created += 1
    
    print(f"✅ {metrics_created} métricas del dashboard creadas")
    
    print("\n🎉 ¡DATOS DE EJEMPLO CREADOS EXITOSAMENTE!")
    print("\n📋 RESUMEN:")
    print(f"   👥 Usuarios: {User.objects.count()}")
    print(f"   🔒 Eventos de Seguridad: {SecurityEvent.objects.count()}")
    print(f"   🚨 Alertas: {Alert.objects.count()}")
    print(f"   📋 Incidentes: {Incident.objects.count()}")
    print(f"   📝 Logs: {SystemLog.objects.count()}")
    print(f"   🖥️ Servidores: {Server.objects.count()}")
    print(f"   🔧 Reglas: {SecurityRule.objects.count()}")
    print("\n🔑 CREDENCIALES:")
    print("   Admin: admin / admin123")
    print("   Analista: analista1 / password123")
    print("   Operador: operador1 / password123")
    print("   Visualizador: viewer1 / password123")
    print("\n✅ ¡Sistema listo para usar!")

def generate_report(report):
    """Generate a PDF report"""
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        import os
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join('media', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename
        filename = f"report_{report.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(reports_dir, filename)
        
        # Create PDF
        c = canvas.Canvas(filepath, pagesize=letter)
        width, height = letter
        
        # Title
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, f"SIEM IESS - {report.title}")
        
        # Header info
        c.setFont("Helvetica", 12)
        y_position = height - 100
        c.drawString(50, y_position, f"Tipo de Reporte: {report.get_report_type_display()}")
        y_position -= 20
        c.drawString(50, y_position, f"Período: {report.date_from.strftime('%d/%m/%Y')} - {report.date_to.strftime('%d/%m/%Y')}")
        y_position -= 20
        c.drawString(50, y_position, f"Generado por: {report.generated_by.get_full_name() or report.generated_by.username}")
        y_position -= 20
        c.drawString(50, y_position, f"Fecha de generación: {report.created_at.strftime('%d/%m/%Y %H:%M')}")
        y_position -= 40
        
        # Content based on report type
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_position, "Resumen Ejecutivo")
        y_position -= 30
        
        c.setFont("Helvetica", 11)
        
        if report.report_type == 'security':
            # Security events summary
            events = SecurityEvent.objects.filter(
                timestamp__range=[report.date_from, report.date_to]
            )
            
            c.drawString(50, y_position, f"Total de eventos de seguridad: {events.count()}")
            y_position -= 20
            
            # Events by severity
            for severity, label in SecurityEvent.SEVERITY_CHOICES:
                count = events.filter(severity=severity).count()
                c.drawString(70, y_position, f"• {label}: {count} eventos")
                y_position -= 15
                
            y_position -= 20
            c.drawString(50, y_position, "Top 5 IPs con más eventos:")
            y_position -= 15
            
            # Top IPs
            from django.db.models import Count
            top_ips = events.values('source_ip').annotate(
                count=Count('id')
            ).order_by('-count')[:5]
            
            for ip_data in top_ips:
                c.drawString(70, y_position, f"• {ip_data['source_ip']}: {ip_data['count']} eventos")
                y_position -= 15
        
        elif report.report_type == 'incidents':
            # Incidents summary
            incidents = Incident.objects.filter(
                created_at__range=[report.date_from, report.date_to]
            )
            
            c.drawString(50, y_position, f"Total de incidentes: {incidents.count()}")
            y_position -= 20
            
            # Incidents by priority
            for priority, label in Incident.PRIORITY_CHOICES:
                count = incidents.filter(priority=priority).count()
                c.drawString(70, y_position, f"• {label}: {count} incidentes")
                y_position -= 15
                
            y_position -= 20
            resolved_count = incidents.filter(state='resolved').count()
            c.drawString(50, y_position, f"Incidentes resueltos: {resolved_count}")
            y_position -= 15
            
            if incidents.count() > 0:
                resolution_rate = (resolved_count / incidents.count()) * 100
                c.drawString(50, y_position, f"Tasa de resolución: {resolution_rate:.1f}%")
        
        elif report.report_type == 'performance':
            # Performance metrics
            servers = Server.objects.all()
            if servers.exists():
                from django.db.models import Avg
                avg_cpu = servers.aggregate(avg_cpu=Avg('cpu_usage'))['avg_cpu'] or 0
                avg_memory = servers.aggregate(avg_memory=Avg('memory_usage'))['avg_memory'] or 0
                avg_disk = servers.aggregate(avg_disk=Avg('disk_usage'))['avg_disk'] or 0
                
                c.drawString(50, y_position, "Métricas de rendimiento promedio:")
                y_position -= 20
                c.drawString(70, y_position, f"• CPU: {avg_cpu:.1f}%")
                y_position -= 15
                c.drawString(70, y_position, f"• Memoria: {avg_memory:.1f}%")
                y_position -= 15
                c.drawString(70, y_position, f"• Disco: {avg_disk:.1f}%")
                y_position -= 20
                
                active_servers = servers.filter(state='active').count()
                c.drawString(50, y_position, f"Servidores activos: {active_servers} de {servers.count()}")
        
        # Footer
        c.setFont("Helvetica", 8)
        c.drawString(50, 50, "SIEM IESS - Instituto Ecuatoriano de Seguridad Social")
        c.drawString(50, 35, "Sistema de Información y Gestión de Eventos de Seguridad")
        
        c.save()
        
        return f"reports/{filename}"
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return None

def calculate_security_score():
    """Calculate overall security score based on various metrics"""
    # This is a simplified calculation
    # In a real system, this would be more sophisticated
    
    total_events = SecurityEvent.objects.filter(
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).count()
    
    critical_events = SecurityEvent.objects.filter(
        timestamp__gte=timezone.now() - timedelta(days=7),
        severity='critical'
    ).count()
    
    active_alerts = Alert.objects.filter(state='active').count()
    
    # Base score
    score = 100
    
    # Deduct points for critical events
    score -= critical_events * 5
    
    # Deduct points for active alerts
    score -= active_alerts * 2
    
    # Ensure score is between 0 and 100
    return max(0, min(100, score))

def get_threat_level():
    """Determine current threat level"""
    critical_alerts = Alert.objects.filter(
        alert_type='critical',
        state='active'
    ).count()
    
    if critical_alerts >= 5:
        return 'critical'
    elif critical_alerts >= 2:
        return 'high'
    elif critical_alerts >= 1:
        return 'medium'
    else:
        return 'low'
