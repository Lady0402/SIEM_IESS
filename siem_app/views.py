from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Count, Avg
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta, datetime
import json
import random

from .models import (
    SecurityEvent, Alert, Incident, SystemLog, Server, 
    SecurityRule, Report, UserProfile, DashboardMetrics
)
from .utils import generate_report, create_sample_data

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            login(request, user)
            # Log successful login
            SystemLog.objects.create(
                level='INFO',
                source='security',
                message=f'Usuario {user.username} inició sesión exitosamente',
                user=user.username,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return redirect('dashboard')
        else:
            messages.error(request, 'Credenciales inválidas')
            # Log failed login
            SystemLog.objects.create(
                level='WARNING',
                source='security',
                message=f'Intento de login fallido para email: {email}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
    
    return render(request, 'siem_app/login.html')

def logout_view(request):
    if request.user.is_authenticated:
        SystemLog.objects.create(
            level='INFO',
            source='security',
            message=f'Usuario {request.user.username} cerró sesión',
            user=request.user.username,
            ip_address=request.META.get('REMOTE_ADDR')
        )
    logout(request)
    return redirect('login')

@login_required
def dashboard_view(request):
    # Get or create today's metrics with real-time data
    today = timezone.now().date()
    
    # Calculate real metrics
    total_events_today = SecurityEvent.objects.filter(timestamp__date=today).count()
    critical_alerts = Alert.objects.filter(alert_type='critical', state='active').count()
    medium_alerts = Alert.objects.filter(alert_type='medium', state='active').count()
    total_alerts_today = Alert.objects.filter(created_at__date=today).count()
    total_incidents_today = Incident.objects.filter(created_at__date=today).count()
    resolved_incidents_today = Incident.objects.filter(state='resolved', updated_at__date=today).count()
    
    # Calculate security score
    security_score = 100
    if critical_alerts > 0:
        security_score -= critical_alerts * 10
    if medium_alerts > 0:
        security_score -= medium_alerts * 5
    security_score = max(0, min(100, security_score))
    
    # Calculate response time (simplified)
    response_time = 4.2 - (security_score / 100) * 2  # Better score = faster response
    
    metrics, created = DashboardMetrics.objects.get_or_create(
        date=today,
        defaults={
            'total_events': total_events_today,
            'critical_alerts': critical_alerts,
            'medium_alerts': medium_alerts,
            'total_alerts': total_alerts_today,
            'total_incidents': total_incidents_today,
            'resolved_incidents': resolved_incidents_today,
            'security_score': security_score,
            'response_time_avg': response_time,
        }
    )
    
    # Update existing metrics with real-time data
    if not created:
        metrics.total_events = total_events_today
        metrics.critical_alerts = critical_alerts
        metrics.medium_alerts = medium_alerts
        metrics.total_alerts = total_alerts_today
        metrics.total_incidents = total_incidents_today
        metrics.resolved_incidents = resolved_incidents_today
        metrics.security_score = security_score
        metrics.response_time_avg = response_time
        metrics.save()
    
    # Recent events
    recent_events = SecurityEvent.objects.select_related('assigned_to').order_by('-timestamp')[:10]
    
    # Critical alerts
    critical_alerts_list = Alert.objects.filter(alert_type='critical', state='active').order_by('-created_at')[:5]
    
    # Open incidents
    open_incidents = Incident.objects.filter(state__in=['new', 'investigating']).order_by('-created_at')[:5]
    
    # Events by severity for chart
    events_by_severity = SecurityEvent.objects.values('severity').annotate(count=Count('id'))
    
    # Events by category for chart
    events_by_category = SecurityEvent.objects.values('category').annotate(count=Count('id'))
    
    context = {
        'metrics': metrics,
        'recent_events': recent_events,
        'critical_alerts': critical_alerts_list,
        'open_incidents': open_incidents,
        'events_by_severity': list(events_by_severity),
        'events_by_category': list(events_by_category),
        'current_date': timezone.now(),
        'critical_alerts_count': critical_alerts,
    }
    
    return render(request, 'siem_app/dashboard.html', context)

@login_required
def alerts_center_view(request):
    # Filter parameters
    search_query = request.GET.get('search', '')
    alert_type_filter = request.GET.get('type', '')
    
    alerts = Alert.objects.select_related('event', 'assigned_to').all()
    
    if search_query:
        alerts = alerts.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    if alert_type_filter:
        alerts = alerts.filter(alert_type=alert_type_filter)
    
    # Real-time metrics
    critical_alerts_count = Alert.objects.filter(alert_type='critical', state='active').count()
    medium_alerts_count = Alert.objects.filter(alert_type='medium', state='active').count()
    total_alerts_count = Alert.objects.filter(created_at__gte=timezone.now() - timedelta(hours=24)).count()
    
    # Recent alerts
    recent_alerts = alerts.order_by('-created_at')[:20]
    
    context = {
        'alerts': recent_alerts,
        'critical_alerts_count': critical_alerts_count,
        'medium_alerts_count': medium_alerts_count,
        'total_alerts_count': total_alerts_count,
        'search_query': search_query,
        'alert_type_filter': alert_type_filter,
        'alert_types': Alert.ALERT_TYPE_CHOICES,
    }
    
    return render(request, 'siem_app/alerts_center.html', context)

@login_required
def reports_center_view(request):
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        period = request.POST.get('period')
        description = request.POST.get('description', '')
        
        # Calculate date range based on period
        end_date = timezone.now()
        if period == 'last_7_days':
            start_date = end_date - timedelta(days=7)
        elif period == 'last_30_days':
            start_date = end_date - timedelta(days=30)
        elif period == 'last_90_days':
            start_date = end_date - timedelta(days=90)
        else:
            start_date = end_date - timedelta(days=7)
        
        # Create report
        report = Report.objects.create(
            title=f"Reporte de {dict(Report.REPORT_TYPE_CHOICES)[report_type]} - {period}",
            report_type=report_type,
            description=description,
            generated_by=request.user,
            date_from=start_date,
            date_to=end_date,
            parameters={'period': period}
        )
        
        # Generate report file immediately
        try:
            from .utils import generate_report
            file_path = generate_report(report)
            if file_path:
                # Save relative path
                report.file_path.name = file_path
                report.save()
                messages.success(request, f'Reporte generado exitosamente: {report.title}')
            else:
                messages.error(request, 'Error al generar el archivo del reporte')
        except Exception as e:
            messages.error(request, f'Error al generar reporte: {str(e)}')
            
        return redirect('reports_center')
    
    # Get real-time metrics for the dashboard
    total_incidents = Incident.objects.count()
    resolved_incidents = Incident.objects.filter(state='resolved').count()
    
    # Calculate real response time
    recent_incidents = Incident.objects.filter(
        created_at__gte=timezone.now() - timedelta(days=30),
        state='resolved'
    )
    
    if recent_incidents.exists():
        total_time = sum([
            (incident.updated_at - incident.created_at).total_seconds() / 60
            for incident in recent_incidents
            if incident.updated_at
        ])
        avg_response_time = total_time / recent_incidents.count()
    else:
        avg_response_time = 4.2
    
    # Calculate real security score
    critical_alerts = Alert.objects.filter(alert_type='critical', state='active').count()
    medium_alerts = Alert.objects.filter(alert_type='medium', state='active').count()
    security_score = 100 - (critical_alerts * 10) - (medium_alerts * 5)
    security_score = max(0, min(100, security_score))
    
    # Recent reports
    recent_reports = Report.objects.filter(generated_by=request.user).order_by('-created_at')[:10]
    
    context = {
        'total_incidents': total_incidents,
        'resolved_incidents': resolved_incidents,
        'avg_response_time': round(avg_response_time, 1),
        'security_score': security_score,
        'recent_reports': recent_reports,
        'report_types': Report.REPORT_TYPE_CHOICES,
    }
    
    return render(request, 'siem_app/reports_center.html', context)

@login_required
def logs_center_view(request):
    # Filter parameters
    search_query = request.GET.get('search', '')
    level_filter = request.GET.get('level', '')
    source_filter = request.GET.get('source', '')
    
    logs = SystemLog.objects.all()
    
    if search_query:
        logs = logs.filter(message__icontains=search_query)
    
    if level_filter:
        logs = logs.filter(level=level_filter)
    
    if source_filter:
        logs = logs.filter(source=source_filter)
    
    # Real-time metrics
    total_logs = SystemLog.objects.filter(timestamp__gte=timezone.now() - timedelta(hours=24)).count()
    critical_events = SystemLog.objects.filter(level='CRITICAL', timestamp__gte=timezone.now() - timedelta(hours=24)).count()
    errors = SystemLog.objects.filter(level='ERROR', timestamp__gte=timezone.now() - timedelta(hours=24)).count()
    filtered_logs = logs.count()
    
    # Paginate logs
    paginator = Paginator(logs.order_by('-timestamp'), 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'total_logs': total_logs,
        'critical_events': critical_events,
        'errors': errors,
        'filtered_logs': filtered_logs,
        'search_query': search_query,
        'level_filter': level_filter,
        'source_filter': source_filter,
        'log_levels': SystemLog.LEVEL_CHOICES,
        'log_sources': SystemLog.SOURCE_CHOICES,
    }
    
    return render(request, 'siem_app/logs_center.html', context)

@login_required
def infrastructure_view(request):
    servers = Server.objects.all().order_by('name')
    
    # Update server metrics with random realistic data for demo
    for server in servers:
        # Simulate real-time updates
        server.cpu_usage = max(10, min(95, server.cpu_usage + random.uniform(-5, 5)))
        server.memory_usage = max(20, min(98, server.memory_usage + random.uniform(-3, 3)))
        server.disk_usage = max(15, min(90, server.disk_usage + random.uniform(-2, 2)))
        server.temperature = max(30, min(80, server.temperature + random.uniform(-2, 2)))
        server.save()
    
    # Calculate average metrics
    avg_cpu = servers.aggregate(avg_cpu=Avg('cpu_usage'))['avg_cpu'] or 0
    avg_memory = servers.aggregate(avg_memory=Avg('memory_usage'))['avg_memory'] or 0
    avg_disk = servers.aggregate(avg_disk=Avg('disk_usage'))['avg_disk'] or 0
    avg_temp = servers.aggregate(avg_temp=Avg('temperature'))['avg_temp'] or 0
    
    # Server counts
    total_servers = servers.count()
    active_servers = servers.filter(state='active').count()
    
    context = {
        'servers': servers,
        'avg_cpu': round(avg_cpu, 1),
        'avg_memory': round(avg_memory, 1),
        'avg_disk': round(avg_disk, 1),
        'avg_temp': round(avg_temp, 1),
        'total_servers': total_servers,
        'active_servers': active_servers,
    }
    
    return render(request, 'siem_app/infrastructure.html', context)

@login_required
def events_view(request):
    # Filter parameters
    search_query = request.GET.get('search', '')
    severity_filter = request.GET.get('severity', '')
    category_filter = request.GET.get('category', '')
    state_filter = request.GET.get('state', '')
    
    events = SecurityEvent.objects.select_related('assigned_to').all()
    
    if search_query:
        events = events.filter(
            Q(event_type__icontains=search_query) |
            Q(source_ip__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    if severity_filter:
        events = events.filter(severity=severity_filter)
    
    if category_filter:
        events = events.filter(category=category_filter)
    
    if state_filter:
        events = events.filter(state=state_filter)
    
    # Paginate events
    paginator = Paginator(events.order_by('-timestamp'), 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'severity_filter': severity_filter,
        'category_filter': category_filter,
        'state_filter': state_filter,
        'severity_choices': SecurityEvent.SEVERITY_CHOICES,
        'category_choices': SecurityEvent.CATEGORY_CHOICES,
        'state_choices': SecurityEvent.STATE_CHOICES,
    }
    
    return render(request, 'siem_app/events.html', context)

@login_required
def users_view(request):
    from django.contrib.auth.models import User
    users = User.objects.select_related('userprofile').all()
    
    context = {
        'users': users,
    }
    
    return render(request, 'siem_app/users.html', context)

@login_required
def network_view(request):
    # This would integrate with actual network monitoring tools
    context = {
        'network_devices': [],  # Would be populated with real data
    }
    
    return render(request, 'siem_app/network.html', context)

@login_required
def security_view(request):
    # Security dashboard with rules and policies
    rules = SecurityRule.objects.filter(is_active=True)
    
    context = {
        'rules': rules,
    }
    
    return render(request, 'siem_app/security.html', context)

@login_required
def configuration_view(request):
    context = {}
    return render(request, 'siem_app/configuration.html', context)

@login_required
def iess_services_view(request):
    """Vista de servicios IESS con datos simulados realistas"""
    
    # DATOS SIMULADOS PERO REALISTAS
    import random
    from datetime import datetime, timedelta
    
    # Simular métricas de servicios en tiempo real
    base_time = datetime.now()
    
    # Datos que cambian cada vez que recargas
    context = {
        'total_services': 6,
        'services_online': random.randint(4, 6),
        'services_warning': random.randint(0, 2),
        'services_offline': random.randint(0, 1),
        
        # Métricas dinámicas que cambian
        'afiliados_hoy': random.randint(1200, 1300),
        'pagos_procesados': f"${random.uniform(2.2, 2.6):.1f}M",
        'transacciones': random.randint(15000, 16000),
        'citas_agendadas': random.randint(3400, 3500),
        'centros_activos': f"{random.randint(125, 130)}/130",
        'pensionistas': "456,789",  # Dato fijo realista
        'pagos_mensuales': "$89.2M",  # Dato fijo realista
        'casos_reportados': random.randint(230, 240),
        'casos_proceso': random.randint(60, 70),
        'usuarios_activos': random.randint(12000, 13000),
        
        # Disponibilidades que varían ligeramente
        'disponibilidad_afiliacion': round(random.uniform(99.5, 99.9), 1),
        'disponibilidad_prestaciones': round(random.uniform(96.5, 97.5), 1),
        'disponibilidad_salud': round(random.uniform(98.5, 99.0), 1),
        'disponibilidad_pensiones': round(random.uniform(99.2, 99.8), 1),
        'disponibilidad_riesgos': round(random.uniform(98.8, 99.5), 1),
        'disponibilidad_portal': round(random.uniform(96.0, 97.5), 1),
        
        # Alertas dinámicas
        'alertas_prestaciones': random.randint(2, 4),
        'alertas_portal': 1,  # Fijo para el SSL
        
        # Timestamp para mostrar última actualización
        'ultima_actualizacion': base_time.strftime('%H:%M:%S'),
    }
    
    return render(request, 'siem_app/iess_services.html', context)

# API Views for real-time updates
@login_required
def api_dashboard_metrics(request):
    today = timezone.now().date()
    
    # Calculate real-time metrics
    total_events = SecurityEvent.objects.filter(timestamp__date=today).count()
    critical_alerts = Alert.objects.filter(alert_type='critical', state='active').count()
    medium_alerts = Alert.objects.filter(alert_type='medium', state='active').count()
    total_alerts = Alert.objects.filter(created_at__date=today).count()
    
    # Calculate security score
    security_score = 100 - (critical_alerts * 10) - (medium_alerts * 5)
    security_score = max(0, min(100, security_score))
    
    # Calculate response time
    response_time = 4.2 - (security_score / 100) * 2
    
    data = {
        'total_events': total_events,
        'critical_alerts': critical_alerts,
        'medium_alerts': medium_alerts,
        'total_alerts': total_alerts,
        'security_score': security_score,
        'response_time': response_time,
        'timestamp': timezone.now().isoformat(),
    }
    
    return JsonResponse(data)

@login_required
def api_server_metrics(request):
    servers = Server.objects.all()
    data = []
    
    for server in servers:
        # Simulate real-time updates
        server.cpu_usage = max(10, min(95, server.cpu_usage + random.uniform(-2, 2)))
        server.memory_usage = max(20, min(98, server.memory_usage + random.uniform(-1, 1)))
        server.save()
        
        data.append({
            'id': server.id,
            'name': server.name,
            'cpu_usage': round(server.cpu_usage, 1),
            'memory_usage': round(server.memory_usage, 1),
            'disk_usage': round(server.disk_usage, 1),
            'temperature': round(server.temperature, 1),
            'state': server.state,
        })
    
    return JsonResponse({'servers': data})

@login_required
def api_iess_services_metrics(request):
    """API que devuelve métricas actualizadas de servicios IESS"""
    import random
    
    # Datos que cambian cada vez que se llama la API
    data = {
        'afiliados_hoy': random.randint(1200, 1300),
        'transacciones': random.randint(15000, 16000),
        'citas_agendadas': random.randint(3400, 3500),
        'usuarios_activos': random.randint(12000, 13000),
        'casos_reportados': random.randint(230, 240),
        
        # Disponibilidades que fluctúan
        'disponibilidad_afiliacion': round(random.uniform(99.5, 99.9), 1),
        'disponibilidad_prestaciones': round(random.uniform(96.5, 97.5), 1),
        'disponibilidad_salud': round(random.uniform(98.5, 99.0), 1),
        
        # Estados de servicios
        'estado_afiliacion': random.choice(['online', 'online', 'online', 'warning']),
        'estado_prestaciones': random.choice(['warning', 'warning', 'online']),
        'estado_salud': 'online',
        'estado_pensiones': 'online',
        'estado_riesgos': 'online',
        'estado_portal': random.choice(['warning', 'warning', 'online']),
        
        # Nuevas alertas
        'nuevas_alertas': random.randint(0, 2),
        'timestamp': timezone.now().isoformat(),
    }
    
    return JsonResponse(data)

@csrf_exempt
@login_required
def api_create_event(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            event = SecurityEvent.objects.create(
                event_type=data.get('event_type'),
                source_ip=data.get('source_ip'),
                destination_ip=data.get('destination_ip'),
                category=data.get('category'),
                severity=data.get('severity'),
                description=data.get('description', ''),
                raw_data=data.get('raw_data', {})
            )
            
            # Create alert if critical
            if event.severity == 'critical':
                Alert.objects.create(
                    title=f"Evento crítico: {event.event_type}",
                    description=f"Se detectó un evento crítico desde {event.source_ip}",
                    alert_type='critical',
                    event=event
                )
            
            return JsonResponse({'status': 'success', 'event_id': event.id})
        
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'})

# Utility views
@login_required
def create_sample_data_view(request):
    if request.user.is_superuser:
        try:
            create_sample_data()
            messages.success(request, 'Datos de ejemplo creados exitosamente')
        except Exception as e:
            messages.error(request, f'Error al crear datos de ejemplo: {str(e)}')
    else:
        messages.error(request, 'No tienes permisos para realizar esta acción')
    
    return redirect('dashboard')

@login_required
def export_report(request, report_id):
    report = get_object_or_404(Report, id=report_id, generated_by=request.user)
    
    if report.file_path:
        with open(report.file_path.path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{report.title}.pdf"'
            return response
    else:
        messages.error(request, 'El archivo del reporte no está disponible')
        return redirect('reports_center')

@login_required
def create_user_view(request):
    if request.method == 'POST':
        try:
            from django.contrib.auth.models import User
            
            username = request.POST.get('username')
            email = request.POST.get('email')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            password = request.POST.get('password')
            role = request.POST.get('role')
            department = request.POST.get('department')
            
            # Validate required fields
            if not all([username, email, password, role]):
                return JsonResponse({'status': 'error', 'message': 'Todos los campos requeridos deben ser completados'})
            
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                return JsonResponse({'status': 'error', 'message': 'El nombre de usuario ya existe'})
            
            if User.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'El email ya está registrado'})
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            
            # Create or update user profile
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.role = role
            profile.department = department
            profile.save()
            
            # Log user creation
            SystemLog.objects.create(
                level='INFO',
                source='security',
                message=f'Nuevo usuario creado: {username} por {request.user.username}',
                user=request.user.username,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return JsonResponse({'status': 'success', 'message': f'Usuario {username} creado exitosamente'})
            
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Error al crear usuario: {str(e)}'})
    
    return JsonResponse({'status': 'error', 'message': 'Método no permitido'})

@login_required
def update_event_view(request, event_id):
    if request.method == 'POST':
        try:
            event = get_object_or_404(SecurityEvent, id=event_id)
            
            # Update event fields
            if 'severity' in request.POST:
                event.severity = request.POST.get('severity')
            if 'category' in request.POST:
                event.category = request.POST.get('category')
            if 'state' in request.POST:
                event.state = request.POST.get('state')
            if 'assigned_to' in request.POST:
                assigned_to_id = request.POST.get('assigned_to')
                if assigned_to_id:
                    from django.contrib.auth.models import User
                    event.assigned_to = User.objects.get(id=assigned_to_id)
                else:
                    event.assigned_to = None
            
            event.save()
            
            # Log the update
            SystemLog.objects.create(
                level='INFO',
                source='security',
                message=f'Evento {event_id} actualizado por {request.user.username}',
                user=request.user.username,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            return JsonResponse({'status': 'success', 'message': 'Evento actualizado exitosamente'})
            
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Error al actualizar evento: {str(e)}'})
    
    return JsonResponse({'status': 'error', 'message': 'Método no permitido'})

@login_required
def manual_data_entry_view(request):
    if request.method == 'POST':
        try:
            # Create manual security event
            event = SecurityEvent.objects.create(
                event_type=request.POST.get('event_type'),
                source_ip=request.POST.get('source_ip'),
                destination_ip=request.POST.get('destination_ip', ''),
                source_port=request.POST.get('source_port') or None,
                destination_port=request.POST.get('destination_port') or None,
                protocol=request.POST.get('protocol', 'TCP'),
                category=request.POST.get('category'),
                severity=request.POST.get('severity'),
                description=request.POST.get('description'),
                state='new'
            )
            
            # Create alert if critical
            if event.severity == 'critical':
                Alert.objects.create(
                    title=f"Evento crítico manual: {event.event_type}",
                    description=f"Evento crítico ingresado manualmente desde {event.source_ip}",
                    alert_type='critical',
                    event=event
                )
            
            # Log manual entry
            SystemLog.objects.create(
                level='INFO',
                source='security',
                message=f'Evento manual creado: {event.event_type} por {request.user.username}',
                user=request.user.username,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Evento de seguridad creado exitosamente')
            return redirect('events')
            
        except Exception as e:
            messages.error(request, f'Error al crear evento: {str(e)}')
    
    context = {
        'severity_choices': SecurityEvent.SEVERITY_CHOICES,
        'category_choices': SecurityEvent.CATEGORY_CHOICES,
    }
    
    return render(request, 'siem_app/manual_data_entry.html', context)

@login_required
def get_real_dashboard_data(request):
    """Get real-time dashboard data"""
    today = timezone.now().date()
    
    # Real metrics calculation
    total_events_today = SecurityEvent.objects.filter(timestamp__date=today).count()
    critical_alerts = Alert.objects.filter(alert_type='critical', state='active').count()
    medium_alerts = Alert.objects.filter(alert_type='medium', state='active').count()
    total_alerts_today = Alert.objects.filter(created_at__date=today).count()
    
    # Incidents
    total_incidents = Incident.objects.filter(created_at__date=today).count()
    resolved_incidents = Incident.objects.filter(state='resolved', updated_at__date=today).count()
    
    # Calculate security score based on real data
    security_score = 100
    if critical_alerts > 0:
        security_score -= critical_alerts * 10
    if medium_alerts > 0:
        security_score -= medium_alerts * 5
    security_score = max(0, min(100, security_score))
    
    # Response time calculation (simplified)
    response_time = 4.2 - (security_score / 100) * 2
    
    data = {
        'total_events': total_events_today,
        'critical_alerts': critical_alerts,
        'medium_alerts': medium_alerts,
        'total_alerts': total_alerts_today,
        'total_incidents': total_incidents,
        'resolved_incidents': resolved_incidents,
        'security_score': security_score,
        'response_time': response_time,
        'timestamp': timezone.now().isoformat()
    }
    
    return JsonResponse(data)
