"""
Logging Configuration for TrueAlign Shift Management System

This module provides comprehensive logging configuration for the shift management system
with action-based logging, structured logging, and performance monitoring.

Usage:
1. Import this configuration in your Django settings.py
2. Add the LOGGING configuration to your settings
3. Customize handlers and formatters as needed

Features:
- Action-based logging with unique request IDs
- Structured logging with JSON format option
- Performance monitoring with duration tracking
- Security logging for authentication and authorization
- Database operation logging
- API endpoint logging
- Error tracking with stack traces
- User activity logging
"""

import os
import logging
from datetime import datetime

# Base logging configuration for Django
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'json': {
            'format': '{levelname}|{asctime}|{module}|{process}|{thread}|{message}',
            'style': '{',
        },
        'action_based': {
            'format': '[{asctime}] {levelname} - {name} - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'detailed': {
            'format': '[{asctime}] {levelname} - {name} - {funcName}:{lineno} - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },

    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },

    'handlers': {
        'console': {
            'level': 'INFO',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'action_based'
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('logs', 'shift_app.log'),
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'detailed',
        },
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('logs', 'shift_errors.log'),
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'detailed',
        },
        'action_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('logs', 'shift_actions.log'),
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('logs', 'shift_security.log'),
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'detailed',
        },
        'api_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('logs', 'shift_api.log'),
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'json',
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'verbose'
        },
    },

    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'django.request': {
            'handlers': ['error_file', 'mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
        'trueAlign.shift': {
            'handlers': ['console', 'file', 'action_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'trueAlign.shift.actions': {
            'handlers': ['action_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'trueAlign.shift.security': {
            'handlers': ['security_file', 'error_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'trueAlign.shift.api': {
            'handlers': ['api_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'trueAlign.shift.performance': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


class ActionLogger:
    """
    Specialized logger for action-based logging with context management.

    Usage:
        action_logger = ActionLogger('trueAlign.shift.actions')
        action_logger.log_action('USER_LOGIN', user_id=123, ip='192.168.1.1')
    """

    def __init__(self, logger_name='trueAlign.shift.actions'):
        self.logger = logging.getLogger(logger_name)

    def log_action(self, action, user_id=None, user=None, ip=None, request_id=None, **kwargs):
        """Log a user action with structured data."""
        extra_data = {
            'action': action,
            'user_id': user_id,
            'user': user,
            'ip': ip,
            'request_id': request_id,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }

        message = f"ACTION: {action}"
        if user:
            message += f" by {user}"
        if user_id:
            message += f" (ID: {user_id})"

        self.logger.info(message, extra=extra_data)

    def log_security_event(self, event, level='WARNING', **kwargs):
        """Log security-related events."""
        security_logger = logging.getLogger('trueAlign.shift.security')
        extra_data = {
            'event_type': 'security',
            'event': event,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }

        if level == 'WARNING':
            security_logger.warning(f"SECURITY: {event}", extra=extra_data)
        elif level == 'ERROR':
            security_logger.error(f"SECURITY: {event}", extra=extra_data)
        else:
            security_logger.info(f"SECURITY: {event}", extra=extra_data)

    def log_performance(self, operation, duration_ms, **kwargs):
        """Log performance metrics."""
        perf_logger = logging.getLogger('trueAlign.shift.performance')
        extra_data = {
            'operation': operation,
            'duration_ms': duration_ms,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }

        message = f"PERFORMANCE: {operation} took {duration_ms}ms"
        if duration_ms > 1000:  # Log as warning if over 1 second
            perf_logger.warning(message, extra=extra_data)
        else:
            perf_logger.info(message, extra=extra_data)


class APILogger:
    """
    Specialized logger for API endpoints.

    Usage:
        api_logger = APILogger()
        api_logger.log_api_request('GET', '/api/shifts/', user_id=123)
    """

    def __init__(self):
        self.logger = logging.getLogger('trueAlign.shift.api')

    def log_api_request(self, method, endpoint, user_id=None, status_code=None,
                       duration_ms=None, request_id=None, **kwargs):
        """Log API request with details."""
        extra_data = {
            'api_method': method,
            'api_endpoint': endpoint,
            'user_id': user_id,
            'status_code': status_code,
            'duration_ms': duration_ms,
            'request_id': request_id,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }

        message = f"API {method} {endpoint}"
        if status_code:
            message += f" - {status_code}"
        if duration_ms:
            message += f" ({duration_ms}ms)"

        if status_code and status_code >= 400:
            self.logger.error(message, extra=extra_data)
        else:
            self.logger.info(message, extra=extra_data)


# Example usage and setup instructions
SETUP_INSTRUCTIONS = """
To use this logging configuration in your Django project:

1. Add to settings.py:
   ```python
   from trueAlign.shift.logging_config import LOGGING_CONFIG
   LOGGING = LOGGING_CONFIG
   ```

2. Create logs directory:
   ```bash
   mkdir -p logs
   ```

3. Use in your views:
   ```python
   import logging
   from trueAlign.shift.logging_config import ActionLogger, APILogger

   logger = logging.getLogger('trueAlign.shift')
   action_logger = ActionLogger()
   api_logger = APILogger()

   # In your view function:
   logger.info("User accessed dashboard")
   action_logger.log_action('DASHBOARD_VIEW', user_id=request.user.id, user=request.user.username)
   ```

4. Log rotation:
   The configuration includes automatic log rotation (15MB per file, 10 backups).

5. Monitoring:
   Consider integrating with monitoring tools like:
   - Sentry for error tracking
   - ELK Stack for log aggregation
   - Grafana for log visualization

Log Files Created:
- logs/shift_app.log - General application logs
- logs/shift_errors.log - Error logs only
- logs/shift_actions.log - User action logs (JSON format)
- logs/shift_security.log - Security events
- logs/shift_api.log - API request logs
"""

# Log level mapping for different environments
LOG_LEVELS = {
    'development': {
        'trueAlign.shift': 'DEBUG',
        'django': 'INFO',
    },
    'staging': {
        'trueAlign.shift': 'INFO',
        'django': 'INFO',
    },
    'production': {
        'trueAlign.shift': 'WARNING',
        'django': 'ERROR',
    }
}

# Security logging patterns to watch for
SECURITY_PATTERNS = [
    'permission_denied',
    'authentication_failed',
    'unauthorized_access',
    'suspicious_activity',
    'rate_limit_exceeded',
    'invalid_token',
    'sql_injection_attempt',
    'xss_attempt',
]

# Performance thresholds (in milliseconds)
PERFORMANCE_THRESHOLDS = {
    'database_query': 100,
    'view_rendering': 500,
    'api_response': 200,
    'file_upload': 2000,
    'csv_processing': 5000,
}

if __name__ == "__main__":
    print(SETUP_INSTRUCTIONS)
