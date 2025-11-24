import os
import sys
import django
from django.conf import settings
import inspect
import logging

# Setup Django
sys.path.append(os.getcwd())
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ardurTrueAlign.settings")
django.setup()

def verify_changes():
    print("Verifying changes...")
    results = {"passed": [], "failed": []}

    # 1. Verify Logging Configuration (No pythonjsonlogger)
    try:
        logging_config = settings.LOGGING
        formatters = logging_config.get('formatters', {})
        json_formatter = formatters.get('json', {})
        if 'pythonjsonlogger' in str(json_formatter):
            results["failed"].append("Logging: pythonjsonlogger still present in settings")
        else:
            results["passed"].append("Logging: pythonjsonlogger removed")
    except Exception as e:
        results["failed"].append(f"Logging check failed: {e}")

    # 2. Verify Session Security Settings
    try:
        if settings.SESSION_COOKIE_HTTPONLY and settings.SESSION_COOKIE_SAMESITE == 'Lax':
            results["passed"].append("Session Settings: Secure cookies configured")
        else:
            results["failed"].append(f"Session Settings: HTTPONLY={settings.SESSION_COOKIE_HTTPONLY}, SAMESITE={settings.SESSION_COOKIE_SAMESITE}")
    except Exception as e:
        results["failed"].append(f"Session Settings check failed: {e}")

    # 3. Verify End Session Logic
    try:
        from trueAlign.core.views import optimized_end_session
        source = inspect.getsource(optimized_end_session)
        if "session.logout_time = now" in source or "session.logout_time =" in source:
            results["passed"].append("End Session: logout_time is explicitly set")
        else:
            results["failed"].append("End Session: logout_time NOT explicitly set in optimized_end_session")
    except Exception as e:
        results["failed"].append(f"End Session check failed: {e}")

    # 4. Verify Rapid Session Alert Logic
    try:
        from trueAlign.core.enhanced_logger import EnhancedSessionLogger
        source = inspect.getsource(EnhancedSessionLogger._check_session_anomalies)
        if "len(recent_sessions) > 30" in source and "unique_ips" in source:
             results["passed"].append("Alert Logic: Rapid session threshold increased and IP check added")
        else:
             results["failed"].append("Alert Logic: Rapid session logic not updated correctly")
    except Exception as e:
        results["failed"].append(f"Alert Logic check failed: {e}")

    # 5. Verify Active Alerts Endpoint
    try:
        from trueAlign.attendance import api_views
        if hasattr(api_views, 'active_alerts'):
            results["passed"].append("API: active_alerts endpoint exists in api_views")
        else:
            results["failed"].append("API: active_alerts endpoint MISSING in api_views")
            
        from trueAlign.attendance import api_urls
        if 'active-alerts/' in str(api_urls.urlpatterns):
             results["passed"].append("API: active_alerts URL registered")
        else:
             results["failed"].append("API: active_alerts URL NOT registered")
             
    except Exception as e:
        results["failed"].append(f"API check failed: {e}")

    # Report
    print("\nVerification Results:")
    for p in results["passed"]:
        print(f"✅ {p}")
    for f in results["failed"]:
        print(f"❌ {f}")

    if results["failed"]:
        sys.exit(1)
    else:
        print("\nAll checks passed successfully!")
        sys.exit(0)

if __name__ == "__main__":
    verify_changes()
