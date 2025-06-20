import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APPS_DIR = os.path.join(BASE_DIR, 'apps')

apps = [
    "users",           # UserDetails, Role, Profile
    "sessions",        # UserSession, FailedLoginAttempt, PasswordChange
    "attendance",      # Attendance tracking
    "leave",           # LeaveRequest, LeavePolicy, LeaveType, CompOff
    "shifts",          # ShiftMaster, ShiftAssignment
    "finance",         # Expenses, Vouchers, BankAccount
    "appraisal",       # Appraisal workflows
    "support",         # Ticket system
    "auditing",        # Logs, RoleAssignmentAudit, SystemUsage
    "chat",            # Chat, ChatMessage, ChatRoom
    "games",           # GameIcon, TicTacToeGame, PlayerStats
    "notifications",   # Email, Push, In-app Notifications
    "core"             # Shared utils, middleware, context # Authentication & password handling
]


# Base file content templates
basic_init = ""
basic_views = "from django.shortcuts import render\n"
basic_models = "from django.db import models\n"
basic_urls = """from django.urls import path\n\nurlpatterns = []\n"""
basic_serializers = "from rest_framework import serializers\n"
basic_services = "# Business logic goes here\n"
basic_admin = "from django.contrib import admin\n"
basic_apps = """from django.apps import AppConfig\n\n\nclass {app_title}Config(AppConfig):\n    default_auto_field = 'django.db.models.BigAutoField'\n    name = 'apps.{app_name}'\n"""
basic_tests = "# Write your unit tests here\n"

def create_file(path, content=""):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(content)

# Make apps/ folder
os.makedirs(APPS_DIR, exist_ok=True)
create_file(os.path.join(APPS_DIR, '__init__.py'), basic_init)

for app in apps:
    app_dir = os.path.join(APPS_DIR, app)
    migrations_dir = os.path.join(app_dir, 'migrations')
    tests_dir = os.path.join(app_dir, 'tests')

    if os.path.exists(app_dir):
        print(f"[✔] App '{app}' already exists.")
    else:
        print(f"[+] Creating app '{app}'...")

        os.makedirs(app_dir)
        os.makedirs(migrations_dir)
        os.makedirs(tests_dir)

        # Add __init__.py to package dirs
        create_file(os.path.join(app_dir, '__init__.py'), basic_init)
        create_file(os.path.join(migrations_dir, '__init__.py'), basic_init)
        create_file(os.path.join(tests_dir, '__init__.py'), basic_init)

        # Standard Django files
        create_file(os.path.join(app_dir, 'models.py'), basic_models)
        create_file(os.path.join(app_dir, 'views.py'), basic_views)
        create_file(os.path.join(app_dir, 'urls.py'), basic_urls)
        create_file(os.path.join(app_dir, 'serializers.py'), basic_serializers)
        create_file(os.path.join(app_dir, 'services.py'), basic_services)
        create_file(os.path.join(app_dir, 'admin.py'), basic_admin)
        create_file(os.path.join(app_dir, 'apps.py'), basic_apps.format(app_title=app.capitalize(), app_name=app))
        create_file(os.path.join(app_dir, 'tests.py'), basic_tests)

print("\n✅ Apps and files created successfully!")
