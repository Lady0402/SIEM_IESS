#!/usr/bin/env python
"""
Script de configuración para el proyecto SIEM IESS
Ejecutar: python setup.py
"""
import os
import sys
import subprocess
import sqlite3
from pathlib import Path

def run_command(command, description):
    """Ejecuta un comando y maneja errores"""
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completado")
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Error en {description}: {e}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return None

def create_directories():
    """Crear directorios necesarios"""
    directories = [
        'logs',
        'media',
        'media/reports',
        'static',
        'staticfiles'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Directorio {directory} creado/verificado")

def main():
    print("🚀 === CONFIGURACIÓN DEL PROYECTO SIEM IESS ===")
    print("📋 Sistema de Información y Gestión de Eventos de Seguridad")
    print("🏢 Instituto Ecuatoriano de Seguridad Social\n")
    
    # Verificar si estamos en un entorno virtual
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Recomendación: Ejecutar en un entorno virtual")
        response = input("¿Continuar de todos modos? (y/N): ")
        if response.lower() != 'y':
            return
    
    # Crear directorios
    create_directories()
    
    # Instalar dependencias
    run_command("pip install -r requirements.txt", "Instalando dependencias de Python")
    
    # Crear y aplicar migraciones
    run_command("python manage.py makemigrations", "Creando migraciones de base de datos")
    run_command("python manage.py migrate", "Aplicando migraciones")
    
    # Crear superusuario
    print("\n👤 Creando usuario administrador...")
    print("Usuario: admin")
    print("Email: admin@iess.gob.ec")
    print("Contraseña: admin123")
    
    # Crear datos de ejemplo
    run_command("python manage.py shell -c \"from siem_app.utils import create_sample_data; create_sample_data()\"", 
                "Creando datos de ejemplo")
    
    # Recopilar archivos estáticos
    run_command("python manage.py collectstatic --noinput", "Recopilando archivos estáticos")
    
    print("\n🎉 === CONFIGURACIÓN COMPLETADA ===")
    print("🌐 Para iniciar el servidor ejecuta: python manage.py runserver")
    print("🔗 URL: http://127.0.0.1:8000/")
    print("👤 Usuario: admin@iess.gob.ec")
    print("🔑 Contraseña: admin123")
    print("\n📚 Documentación adicional en README.md")

if __name__ == "__main__":
    main()
