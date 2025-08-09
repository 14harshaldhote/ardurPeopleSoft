"""
Shift Management App Settings Configuration

This file contains all configuration settings specific to the shift management app.
These settings extend the main Django settings and provide app-specific configurations.
"""

import os
from datetime import timedelta
from django.conf import settings

# ============================
# TIMEZONE SETTINGS
# ============================

# Default timezone for shift management
SHIFT_TIMEZONE = getattr(settings, 'TIME_ZONE', 'Asia/Kolkata')

# Enable timezone awareness
USE_TZ = True

# Timezone choices for shift configuration
TIMEZONE_CHOICES = [
    ('Asia/Kolkata', 'India Standard Time (IST)'),
    ('America/New_York', 'Eastern Standard Time (EST)'),
    ('America/Chicago', 'Central Standard Time (CST)'),
    ('America/Denver', 'Mountain Standard Time (MST)'),
    ('America/Los_Angeles', 'Pacific Standard Time (PST)'),
    ('Europe/London', 'Greenwich Mean Time (GMT)'),
    ('Europe/Paris', 'Central European Time (CET)'),
    ('Asia/Tokyo', 'Japan Standard Time (JST)'),
    ('Australia/Sydney', 'Australian Eastern Standard Time (AEST)'),
    ('UTC', 'Coordinated Universal Time (UTC)'),
]

# ============================
# LOGGING CONFIGURATION
# ============================

SHIFT_LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'shift_detailed': {
            'format': '[{levelname}] {asctime} - {name} - {funcName}:{lineno} - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'shift_simple': {
            'format': '[{levelname}] {asctime} - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'shift_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(getattr(settings, 'BASE_DIR', '/tmp'), 'logs', 'shift.log'),
            'maxBytes': 10 * 1024 * 1024,  # 10MB
            'backupCount': 5,
            'formatter': 'shift_detailed',
        },
        'shift_error_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(getattr(settings, 'BASE_DIR', '/tmp'), 'logs', 'shift_errors.log'),
            'maxBytes': 10 * 1024 * 1024,  # 10MB
            'backupCount': 5,
            'formatter': 'shift_detailed',
        },
        'shift_console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'shift_simple',
        },
    },
    'loggers': {
        'trueAlign.shift': {
            'handlers': ['shift_file', 'shift_error_file'],
            'level': 'INFO',
            'propagate': True,
        },
        'trueAlign.shift.services': {
            'handlers': ['shift_file', 'shift_console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'trueAlign.shift.views': {
            'handlers': ['shift_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# ============================
# GROUP PERMISSIONS & ROLES
# ============================

SHIFT_GROUPS = {
    'Manager': {
        'permissions': [
            'add_shiftmaster', 'change_shiftmaster', 'delete_shiftmaster', 'view_shiftmaster',
            'add_shiftassignment', 'change_shiftassignment', 'delete_shiftassignment', 'view_shiftassignment',
            'add_holiday', 'change_holiday', 'delete_holiday', 'view_holiday',
        ],
        'description': 'Can manage all shift operations including creation, assignment, and reporting'
    },
    'HR': {
        'permissions': [
            'add_shiftmaster', 'change_shiftmaster', 'view_shiftmaster',
            'add_shiftassignment', 'change_shiftassignment', 'delete_shiftassignment', 'view_shiftassignment',
            'add_holiday', 'change_holiday', 'delete_holiday', 'view_holiday',
        ],
        'description': 'Can manage shift assignments and view all shift-related data'
    },
    'Employee': {
        'permissions': [
            'view_shiftmaster', 'view_shiftassignment', 'view_holiday',
        ],
        'description': 'Can view their own shift assignments and shift information'
    },
}

# Default group for new users
DEFAULT_USER_GROUP = 'Employee'

# ============================
# SHIFT CONFIGURATION DEFAULTS
# ============================

# Default shift patterns
DEFAULT_SHIFTS = {
    'Day Shift': {
        'start_time': '09:00',
        'end_time': '17:30',
        'duration': 8.5,
        'break_duration': 30,  # minutes
        'grace_period': 15,    # minutes
        'work_days': 'All Days',  # Monday to Saturday
    },
    'Night Shift': {
        'start_time': '18:30',
        'end_time': '03:30',
        'duration': 9.0,
        'break_duration': 30,  # minutes
        'grace_period': 15,    # minutes
        'work_days': 'Weekdays',  # Monday to Friday
    },
}

# Shift validation rules
SHIFT_VALIDATION = {
    'min_duration': 0.5,      # Minimum shift duration in hours
    'max_duration': 24.0,     # Maximum shift duration in hours
    'max_break_duration': 8,   # Maximum break duration in hours
    'max_grace_period': 2,     # Maximum grace period in hours
    'min_assignment_days': 1,  # Minimum assignment duration in days
    'max_assignment_days': 365, # Maximum assignment duration in days
}

# Work day patterns
WORK_DAY_PATTERNS = {
    'Weekdays': [0, 1, 2, 3, 4],          # Monday to Friday
    'All Days': [0, 1, 2, 3, 4, 5],       # Monday to Saturday
    'Weekends': [5, 6],                    # Saturday and Sunday
    'Custom': [],                          # User-defined
}

# ============================
# API CONFIGURATION
# ============================

# API rate limiting (requests per hour)
API_RATE_LIMITS = {
    'default': 1000,
    'authenticated': 5000,
    'manager': 10000,
    'hr': 8000,
}

# API pagination settings
API_PAGINATION = {
    'default_page_size': 20,
    'max_page_size': 100,
}

# API response timeout (seconds)
API_TIMEOUT = 30

# ============================
# FILE UPLOAD SETTINGS
# ============================

# CSV upload configuration
CSV_UPLOAD = {
    'max_file_size': 5 * 1024 * 1024,  # 5MB
    'allowed_extensions': ['.csv'],
    'max_rows': 1000,
    'required_headers': ['username', 'shift_name', 'effective_from'],
    'optional_headers': ['effective_to'],
    'encoding': 'utf-8',
}

# File storage for uploads
UPLOAD_STORAGE = {
    'location': os.path.join(getattr(settings, 'MEDIA_ROOT', '/tmp'), 'shift_uploads'),
    'base_url': '/media/shift_uploads/',
}

# ============================
# EMAIL CONFIGURATION
# ============================

# Email templates for shift notifications
EMAIL_TEMPLATES = {
    'shift_assignment': {
        'subject': 'New Shift Assignment - {shift_name}',
        'template': 'shift/emails/assignment_notification.html',
    },
    'shift_change': {
        'subject': 'Shift Assignment Change - {shift_name}',
        'template': 'shift/emails/change_notification.html',
    },
    'shift_ending': {
        'subject': 'Shift Assignment Ending Soon - {shift_name}',
        'template': 'shift/emails/ending_notification.html',
    },
    'bulk_assignment': {
        'subject': 'Bulk Shift Assignment Completed',
        'template': 'shift/emails/bulk_assignment.html',
    },
}

# Email notification settings
EMAIL_NOTIFICATIONS = {
    'enabled': True,
    'send_assignment_notifications': True,
    'send_change_notifications': True,
    'send_ending_reminders': True,
    'reminder_days_before': 7,  # Days before assignment ends
    'batch_size': 50,  # Maximum emails to send in one batch
}

# Email sender configuration
EMAIL_FROM = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@truealign.com')

# ============================
# CACHING CONFIGURATION
# ============================

# Cache settings for shift data
CACHE_SETTINGS = {
    'default_timeout': 300,  # 5 minutes
    'user_shift_timeout': 600,  # 10 minutes
    'statistics_timeout': 1800,  # 30 minutes
    'holidays_timeout': 3600,  # 1 hour
}

# Cache key prefixes
CACHE_KEY_PREFIXES = {
    'user_current_shift': 'shift:user_current:',
    'shift_statistics': 'shift:stats:',
    'holidays': 'shift:holidays:',
    'schedule': 'shift:schedule:',
}

# ============================
# DATABASE OPTIMIZATION
# ============================

# Database query optimization settings
DATABASE_OPTIMIZATION = {
    'select_related_fields': {
        'ShiftAssignment': ['user', 'shift'],
        'ShiftMaster': [],
        'Holiday': [],
    },
    'prefetch_related_fields': {
        'ShiftMaster': ['shiftassignment_set'],
        'User': ['shiftassignment_set'],
    },
    'indexes': {
        'ShiftAssignment': [
            ['user', 'effective_from'],
            ['shift', 'is_current'],
            ['effective_from', 'effective_to'],
        ],
        'ShiftMaster': [
            ['is_active', 'work_days'],
        ],
        'Holiday': [
            ['date', 'recurring_yearly'],
        ],
    },
}

# ============================
# SECURITY SETTINGS
# ============================

# Security configuration for shift management
SECURITY_SETTINGS = {
    'require_https': getattr(settings, 'SECURE_SSL_REDIRECT', False),
    'csrf_protection': True,
    'xframe_options': 'DENY',
    'content_type_options': 'nosniff',
    'browser_xss_filter': True,
}

# Session security
SESSION_SECURITY = {
    'session_timeout': 3600,  # 1 hour
    'warn_before': 300,       # 5 minutes warning
    'expire_at_browser_close': True,
}

# ============================
# REPORT GENERATION
# ============================

# Report generation settings
REPORT_SETTINGS = {
    'formats': ['html', 'csv', 'pdf'],
    'max_date_range': 365,  # Maximum days in report range
    'default_format': 'html',
    'export_timeout': 300,  # 5 minutes
    'max_records': 10000,   # Maximum records in report
}

# Report templates
REPORT_TEMPLATES = {
    'daily_schedule': 'shift/reports/daily_schedule.html',
    'weekly_summary': 'shift/reports/weekly_summary.html',
    'monthly_report': 'shift/reports/monthly_report.html',
    'assignment_history': 'shift/reports/assignment_history.html',
    'statistics': 'shift/reports/statistics.html',
}

# ============================
# CALENDAR INTEGRATION
# ============================

# Calendar display settings
CALENDAR_SETTINGS = {
    'default_view': 'month',
    'show_weekends': True,
    'highlight_holidays': True,
    'show_shift_details': True,
    'color_schemes': {
        'Day Shift': '#4CAF50',    # Green
        'Night Shift': '#2196F3',  # Blue
        'Custom Shift': '#FF9800', # Orange
        'Holiday': '#F44336',      # Red
    },
}

# ============================
# NOTIFICATION SETTINGS
# ============================

# In-app notification configuration
NOTIFICATION_SETTINGS = {
    'enabled': True,
    'show_shift_reminders': True,
    'show_assignment_changes': True,
    'show_upcoming_holidays': True,
    'reminder_frequency': 'daily',  # daily, weekly, monthly
    'max_notifications': 50,        # Maximum notifications to store per user
}

# ============================
# PERFORMANCE MONITORING
# ============================

# Performance monitoring settings
PERFORMANCE_MONITORING = {
    'enabled': True,
    'slow_query_threshold': 1.0,  # Log queries taking more than 1 second
    'memory_usage_warning': 100,  # MB
    'log_api_response_times': True,
}

# ============================
# FEATURE FLAGS
# ============================

# Feature flags for enabling/disabling functionality
FEATURE_FLAGS = {
    'enable_bulk_assignment': True,
    'enable_csv_import': True,
    'enable_email_notifications': True,
    'enable_api_endpoints': True,
    'enable_advanced_reporting': True,
    'enable_calendar_view': True,
    'enable_shift_templates': True,
    'enable_automatic_assignments': False,  # Future feature
    'enable_shift_swapping': False,         # Future feature
}

# ============================
# INTEGRATION SETTINGS
# ============================

# Settings for integrating with other systems
INTEGRATION_SETTINGS = {
    'hr_system': {
        'enabled': False,
        'api_endpoint': '',
        'api_key': '',
        'sync_frequency': 'daily',
    },
    'payroll_system': {
        'enabled': False,
        'api_endpoint': '',
        'api_key': '',
        'export_format': 'csv',
    },
    'attendance_system': {
        'enabled': False,
        'api_endpoint': '',
        'api_key': '',
        'real_time_sync': False,
    },
}

# ============================
# DEVELOPMENT SETTINGS
# ============================

# Development and debugging settings
DEVELOPMENT_SETTINGS = {
    'debug_toolbar': getattr(settings, 'DEBUG', False),
    'sql_debug': False,
    'template_debug': False,
    'fake_data_generation': False,  # For testing with fake data
}

# Test data configuration
TEST_DATA_CONFIG = {
    'create_test_users': 10,
    'create_test_shifts': 5,
    'create_test_assignments': 20,
    'create_test_holidays': 10,
}

# ============================
# HELPER FUNCTIONS
# ============================

def get_shift_setting(key, default=None):
    """
    Get a shift-specific setting value.

    Args:
        key: Setting key (e.g., 'API_RATE_LIMITS.default')
        default: Default value if setting not found

    Returns:
        Setting value or default
    """
    keys = key.split('.')
    value = globals()

    try:
        for k in keys:
            value = value[k]
        return value
    except (KeyError, TypeError):
        return default


def update_shift_setting(key, value):
    """
    Update a shift-specific setting value.

    Args:
        key: Setting key
        value: New value
    """
    keys = key.split('.')
    setting_dict = globals()

    # Navigate to the parent dictionary
    for k in keys[:-1]:
        if k not in setting_dict:
            setting_dict[k] = {}
        setting_dict = setting_dict[k]

    # Set the value
    setting_dict[keys[-1]] = value


def validate_shift_settings():
    """
    Validate shift settings for consistency and correctness.

    Returns:
        List of validation errors
    """
    errors = []

    # Validate timezone
    try:
        import pytz
        pytz.timezone(SHIFT_TIMEZONE)
    except:
        errors.append(f"Invalid timezone: {SHIFT_TIMEZONE}")

    # Validate shift duration limits
    if SHIFT_VALIDATION['min_duration'] >= SHIFT_VALIDATION['max_duration']:
        errors.append("Minimum shift duration must be less than maximum")

    # Validate file upload size
    if CSV_UPLOAD['max_file_size'] <= 0:
        errors.append("CSV upload max file size must be positive")

    # Validate cache timeouts
    for timeout_key, timeout_value in CACHE_SETTINGS.items():
        if timeout_value <= 0:
            errors.append(f"Cache timeout {timeout_key} must be positive")

    return errors


# Validate settings on import
_validation_errors = validate_shift_settings()
if _validation_errors:
    import warnings
    for error in _validation_errors:
        warnings.warn(f"Shift settings validation error: {error}")
