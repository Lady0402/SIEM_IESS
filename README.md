<<<<<<< HEAD
# SIEM IESS - Sistema de Información y Gestión de Eventos de Seguridad

## Descripción

Sistema de Información y Gestión de Eventos de Seguridad (SIEM) desarrollado para el Instituto Ecuatoriano de Seguridad Social (IESS). Este sistema proporciona monitoreo en tiempo real, análisis de eventos de seguridad, gestión de alertas e incidentes, y generación de reportes.

## Características Principales

- **Dashboard en Tiempo Real**: Métricas y visualizaciones actualizadas automáticamente
- **Centro de Alertas**: Monitoreo y gestión de alertas de seguridad
- **Centro de Reportes**: Generación de informes personalizados
- **Centro de Logs**: Monitoreo de logs del sistema en tiempo real
- **Infraestructura**: Monitoreo de servidores y recursos
- **Gestión de Eventos**: Análisis y clasificación de eventos de seguridad
- **Gestión de Usuarios**: Control de acceso y permisos
- **Configuración**: Personalización del sistema

## Tecnologías Utilizadas

- **Backend**: Django 4.2.7
- **Base de Datos**: SQLite (desarrollo) / PostgreSQL (producción)
- **Frontend**: Bootstrap 5, Chart.js
- **Tiempo Real**: Django Channels, WebSockets
- **Tareas Asíncronas**: Celery, Redis
- **Reportes**: ReportLab, OpenPyXL

## Instalación

### Prerrequisitos

- Python 3.8+
- pip
- virtualenv (recomendado)

### Pasos de Instalación

1. **Clonar o descomprimir el proyecto**:
   \`\`\`bash
   cd siem_iess_project
   \`\`\`

2. **Crear entorno virtual**:
   \`\`\`bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   \`\`\`

3. **Instalar dependencias**:
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`
   Si ves errores de módulos faltantes como `crispy_bootstrap5`, `widget_tweaks` o `corsheaders`, instálalos manualmente:
   \`\`\`bash
   pip install crispy-bootstrap5 django-widget-tweaks django-cors-headers
   \`\`\`

4. **Ejecutar configuración automática**:
   \`\`\`bash
   python setup.py
   \`\`\`

5. **Aplicar migraciones**:
   \`\`\`bash
   python manage.py migrate
   \`\`\`

6. **Crear superusuario** (opcional):
   \`\`\`bash
   python manage.py createsuperuser
   \`\`\`

7. **Cargar datos de ejemplo**:
   \`\`\`bash
   python manage.py shell -c "from siem_app.utils import create_sample_data; create_sample_data()"
   \`\`\`

8. **Iniciar servidor**:
   \`\`\`bash
   python manage.py runserver
   \`\`\`

## Acceso al Sistema

- **URL**: http://127.0.0.1:8000
=======
# SIEM_IESS
>>>>>>> 3cda840196b49a3b4799c8d82c8b0059ec2eb4f9
