# attendance/config.py
"""
Attendance System Configuration
Contains all configuration settings, constants, and defaults for the attendance system.
"""

from datetime import timedelta
import pytz

# Timezone Configuration
DEFAULT_TIMEZONE = pytz.timezone('Asia/Kolkata')
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

# Attendance Status Configuration
ATTENDANCE_STATUS_CHOICES = [
    ('Present', 'Present'),
    ('Present & Late', 'Present & Late'),
    ('Absent', 'Absent'),
    ('Late', 'Late'),
    ('On Leave', 'On Leave'),
    ('Work From Home', 'Work From Home'),
    ('Weekend', 'Weekend'),
    ('Holiday', 'Holiday'),
    ('Comp Off', 'Comp Off'),
    ('Not Marked', 'Not Marked'),
    ('Yet to Clock In', 'Yet to Clock In'),
    ('Half Day', 'Half Day')
]

# Status color mapping for UI
ATTENDANCE_STATUS_COLORS = {
    'Present': 'success',
    'Present & Late': 'warning',
    'Absent': 'danger',
    'Late': 'warning',
    'On Leave': 'info',
    'Work From Home': 'primary',
    'Weekend': 'secondary',
    'Holiday': 'info',
    'Comp Off': 'info',
    'Not Marked': 'light',
    'Yet to Clock In': 'warning',
    'Half Day': 'warning'
}

# Present status categories
PRESENT_STATUSES = ['Present', 'Present & Late', 'Work From Home']
ABSENT_STATUSES = ['Absent']
LATE_STATUSES = ['Present & Late', 'Late']
LEAVE_STATUSES = ['On Leave']
SPECIAL_STATUSES = ['Weekend', 'Holiday', 'Comp Off']

# Location Configuration
LOCATION_CHOICES = [
    ('Office', 'Office'),
    ('Home', 'Home'),
    ('Remote', 'Remote'),
    ('Client Site', 'Client Site'),
    ('Other', 'Other')
]

# Regularization Configuration
REGULARIZATION_STATUS_CHOICES = [
    ('Pending', 'Pending'),
    ('Approved', 'Approved'),
    ('Rejected', 'Rejected')
]

# Default Settings - AUTOMATIC ATTENDANCE SYSTEM
ATTENDANCE_DEFAULTS = {
    'grace_period_minutes': 10,
    'minimum_working_hours': 4.0,
    'standard_working_hours': 8.0,
    'overtime_threshold_hours': 8.0,
    'regularization_deadline_days': 7,
    'max_regularization_attempts': 5,
    'auto_marking_enabled': True,  # MANDATORY - No manual attendance allowed
    'session_timeout_minutes': 30,
    'late_threshold_minutes': 1,
    'early_departure_threshold_minutes': 30,
    'manual_attendance_disabled': True,  # Disable manual check-in/check-out
    'session_based_only': True,  # Only session-based attendance tracking
}

# Time Configuration
TIME_SETTINGS = {
    'work_week_days': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
    'weekend_days': ['Saturday', 'Sunday'],
    'shift_types': {
        'morning': {'start': '09:00', 'end': '18:00'},
        'evening': {'start': '14:00', 'end': '23:00'},
        'night': {'start': '22:00', 'end': '07:00'},
        'flexible': {'start': '09:00', 'end': '18:00'},
    }
}

# Auto-Marking Configuration - MANDATORY AUTOMATIC ATTENDANCE
AUTO_MARKING_CONFIG = {
    'enabled': True,  # ALWAYS ENABLED - Attendance is fully automatic
    'run_time': '09:30',  # Time to run auto-marking daily
    'process_past_days': 1,  # How many past days to process
    'batch_size': 100,  # Number of users to process in one batch
    'retry_attempts': 3,
    'timeout_seconds': 300,
    'real_time_updates': True,  # Enable real-time attendance updates
    'session_based_tracking': True,  # Track attendance based on login sessions
}

# Notification Configuration
NOTIFICATION_CONFIG = {
    'enabled': True,
    'attendance_reminder_time': '09:15',
    'late_arrival_threshold_minutes': 30,
    'absent_notification_time': '11:00',
    'regularization_reminder_days': [3, 1],  # Remind 3 days and 1 day before deadline
    'email_enabled': True,
    'sms_enabled': False,
    'push_notification_enabled': True,
}

# Report Configuration
REPORT_CONFIG = {
    'default_date_range': 'current_month',
    'max_export_records': 10000,
    'supported_export_formats': ['csv', 'xlsx', 'pdf'],
    'pagination_size': 25,
    'cache_timeout_minutes': 15,
    'include_charts': True,
}

# Analytics Configuration
ANALYTICS_CONFIG = {
    'enabled': True,
    'retention_days': 365,
    'trend_analysis_days': 30,
    'benchmark_attendance_percentage': 90.0,
    'late_arrival_threshold_percentage': 20.0,
    'department_comparison_enabled': True,
}

# API Configuration
API_CONFIG = {
    'rate_limit_per_minute': 60,
    'pagination_size': 20,
    'max_pagination_size': 100,
    'cache_timeout_seconds': 300,
    'authentication_required': True,
}

# Validation Rules
VALIDATION_RULES = {
    'max_hours_per_day': 24,
    'min_session_duration_minutes': 1,
    'max_session_duration_hours': 18,
    'future_date_allowed': False,
    'past_date_limit_days': 90,
    'bulk_operation_limit': 100,
}

# Session Configuration
SESSION_CONFIG = {
    'idle_timeout_minutes': 30,
    'max_concurrent_sessions': 3,
    'track_idle_time': True,
    'auto_logout_enabled': True,
    'location_tracking_enabled': True,
    'device_tracking_enabled': True,
}

# Leave Integration
LEAVE_INTEGRATION = {
    'auto_sync_enabled': True,
    'override_manual_attendance': True,
    'supported_leave_types': [
        'Annual Leave',
        'Sick Leave',
        'Personal Leave',
        'Maternity Leave',
        'Paternity Leave',
        'Emergency Leave',
        'Compensatory Off'
    ],
}

# Holiday Configuration
HOLIDAY_CONFIG = {
    'auto_apply_to_all_users': True,
    'allow_optional_holidays': True,
    'max_optional_holidays_per_year': 3,
    'location_specific_holidays': True,
    'recurring_holidays_enabled': True,
}

# Shift Configuration
SHIFT_CONFIG = {
    'default_shift_duration': 8.0,
    'min_shift_duration': 4.0,
    'max_shift_duration': 12.0,
    'break_duration_minutes': 60,
    'allow_flexible_shifts': True,
    'shift_change_notice_days': 7,
}

# Data Cleanup Configuration
CLEANUP_CONFIG = {
    'enabled': True,
    'retention_period_days': 1095,  # 3 years
    'cleanup_schedule': 'monthly',
    'archive_before_delete': True,
    'notify_before_cleanup': True,
    'cleanup_batch_size': 1000,
}

# Security Configuration
SECURITY_CONFIG = {
    'ip_restriction_enabled': False,
    'allowed_ip_ranges': [],
    'device_registration_required': False,
    'two_factor_enabled': False,
    'audit_log_enabled': True,
    'data_encryption_enabled': True,
}

# UI Configuration
UI_CONFIG = {
    'default_theme': 'light',
    'show_analytics_dashboard': True,
    'enable_calendar_view': True,
    'show_team_overview': True,
    'enable_quick_actions': True,
    'refresh_interval_seconds': 300,
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'enable_caching': True,
    'cache_backend': 'redis',
    'database_connection_pool_size': 10,
    'query_timeout_seconds': 30,
    'background_task_enabled': True,
    'async_processing_enabled': True,
}

# Error Handling Configuration
ERROR_HANDLING = {
    'log_level': 'INFO',
    'max_retry_attempts': 3,
    'retry_delay_seconds': 5,
    'fallback_to_manual': True,
    'notify_admin_on_errors': True,
    'error_threshold_percentage': 10.0,
}

# Feature Flags - AUTOMATIC ATTENDANCE FOCUSED
FEATURE_FLAGS = {
    'geolocation_tracking': False,
    'biometric_integration': False,
    'mobile_app_support': True,
    'offline_mode': False,
    'real_time_updates': True,  # Essential for automatic attendance
    'advanced_analytics': True,
    'custom_reports': True,
    'api_access': True,
    'manual_attendance': False,  # Manual attendance completely disabled
    'automatic_session_tracking': True,  # Automatic session-based tracking enabled
}

# Integration Configuration
INTEGRATION_CONFIG = {
    'payroll_system': {
        'enabled': False,
        'sync_attendance': True,
        'sync_overtime': True,
    },
    'hr_system': {
        'enabled': True,
        'sync_employee_data': True,
        'sync_leave_data': True,
    },
    'access_control': {
        'enabled': False,
        'sync_entry_exit': False,
    }
}

# Business Rules - AUTOMATIC ATTENDANCE SYSTEM
BUSINESS_RULES = {
    'weekend_work_requires_approval': True,
    'holiday_work_requires_approval': True,
    'overtime_requires_approval': True,
    'regularization_requires_manager_approval': True,
    'bulk_operations_require_hr_approval': True,
    'attendance_freeze_after_payroll': True,
    'manual_attendance_forbidden': True,  # No manual attendance allowed
    'session_based_attendance_mandatory': True,  # Sessions determine attendance
    'automatic_status_calculation': True,  # Status calculated automatically
}

# Compliance Configuration
COMPLIANCE_CONFIG = {
    'labor_law_compliance': True,
    'data_privacy_compliance': True,
    'audit_trail_required': True,
    'data_retention_policy_days': 2555,  # 7 years
    'export_restrictions': [],
}

def get_setting(key, default=None):
    """
    Get a configuration setting by key with optional default value
    """
    # This function can be extended to read from environment variables,
    # database settings, or configuration files
    all_settings = {
        **ATTENDANCE_DEFAULTS,
        **TIME_SETTINGS,
        **AUTO_MARKING_CONFIG,
        **NOTIFICATION_CONFIG,
        **REPORT_CONFIG,
        **ANALYTICS_CONFIG,
        **API_CONFIG,
        **VALIDATION_RULES,
        **SESSION_CONFIG,
        **LEAVE_INTEGRATION,
        **HOLIDAY_CONFIG,
        **SHIFT_CONFIG,
        **CLEANUP_CONFIG,
        **SECURITY_CONFIG,
        **UI_CONFIG,
        **PERFORMANCE_CONFIG,
        **ERROR_HANDLING,
        **FEATURE_FLAGS,
        **INTEGRATION_CONFIG,
        **BUSINESS_RULES,
        **COMPLIANCE_CONFIG,
    }

    return all_settings.get(key, default)

def is_feature_enabled(feature_name):
    """
    Check if a feature is enabled
    """
    return FEATURE_FLAGS.get(feature_name, False)

def get_status_color(status):
    """
    Get the color class for an attendance status
    """
    return ATTENDANCE_STATUS_COLORS.get(status, 'secondary')

def is_present_status(status):
    """
    Check if a status is considered present
    """
    return status in PRESENT_STATUSES

def is_working_day(day_name):
    """
    Check if a day is a working day
    """
    return day_name in TIME_SETTINGS['work_week_days']

def get_default_grace_period():
    """
    Get the default grace period in minutes
    """
    return ATTENDANCE_DEFAULTS['grace_period_minutes']

def get_regularization_deadline():
    """
    Get the regularization deadline in days
    """
    return ATTENDANCE_DEFAULTS['regularization_deadline_days']
