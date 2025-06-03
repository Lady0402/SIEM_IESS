from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main views
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('events/', views.events_view, name='events'),
    path('alerts/', views.alerts_center_view, name='alerts_center'),
    path('reports/', views.reports_center_view, name='reports_center'),
    path('logs/', views.logs_center_view, name='logs_center'),
    path('infrastructure/', views.infrastructure_view, name='infrastructure'),
    path('network/', views.network_view, name='network'),
    path('security/', views.security_view, name='security'),
    path('users/', views.users_view, name='users'),
    path('configuration/', views.configuration_view, name='configuration'),
    path('iess-services/', views.iess_services_view, name='iess_services'),
    
    # Manual data entry
    path('manual-entry/', views.manual_data_entry_view, name='manual_data_entry'),
    
    # API endpoints
    path('api/dashboard-metrics/', views.api_dashboard_metrics, name='api_dashboard_metrics'),
    path('api/server-metrics/', views.api_server_metrics, name='api_server_metrics'),
    path('api/create-event/', views.api_create_event, name='api_create_event'),
    path('api/real-dashboard-data/', views.get_real_dashboard_data, name='api_real_dashboard_data'),
    path('api/iess-services-metrics/', views.api_iess_services_metrics, name='api_iess_services_metrics'),
    
    # Utility endpoints
    path('create-sample-data/', views.create_sample_data_view, name='create_sample_data'),
    path('export-report/<int:report_id>/', views.export_report, name='export_report'),
    path('create-user/', views.create_user_view, name='create_user'),
    path('update-event/<int:event_id>/', views.update_event_view, name='update_event'),
]
