"""
Logging configuration for leave management
Add this to your Django settings.py LOGGING configuration
"""

LEAVE_MANAGEMENT_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'audit': {
            'format': '[{asctime}] {levelname} {name}: {message}',
            'style': '{',
        },
        'detailed': {
            'format': '[{asctime}] {levelname} {name} {process:d} {thread:d}: {message}',
            'style': '{',
        },
    },
    'handlers': {
        'leave_audit_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/leave_audit.log',
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 5,
            'formatter': 'audit',
        },
        'leave_performance_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/leave_performance.log',
            'maxBytes': 1024*1024*5,   # 5MB
            'backupCount': 3,
            'formatter': 'detailed',
        },
        'leave_security_file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/leave_security.log',
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 10,
            'formatter': 'audit',
        },
    },
    'loggers': {
        'leave_management.audit': {
            'handlers': ['leave_audit_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'leave_management.performance': {
            'handlers': ['leave_performance_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'leave_management.security': {
            'handlers': ['leave_security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'trueAlign.leave_management': {
            'handlers': ['leave_audit_file', 'leave_performance_file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Performance monitoring decorator
import time
import functools
import logging

performance_logger = logging.getLogger('leave_management.performance')

def monitor_performance(operation_name):
    """Decorator to monitor performance of operations"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                performance_logger.info(
                    f"PERFORMANCE | Operation: {operation_name} | "
                    f"Duration: {execution_time:.3f}s | Status: SUCCESS"
                )
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                performance_logger.warning(
                    f"PERFORMANCE | Operation: {operation_name} | "
                    f"Duration: {execution_time:.3f}s | Status: ERROR | Error: {str(e)}"
                )
                raise
        return wrapper
    return decorator
