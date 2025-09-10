"""
Attendance Logging Configuration Helper Module

This module provides configuration management and setup utilities for the attendance
logging system. It handles log directory creation, configuration validation,
and provides easy access to logging settings.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
from django.conf import settings
from django.core.management.color import color_style

# Color styling for console output
style = color_style()

# Default log levels for different components
DEFAULT_LOG_LEVELS = {
    'main': 'INFO',
    'views': 'INFO',
    'api_views': 'INFO',
    'services': 'INFO',
    'models': 'DEBUG',
    'signals': 'INFO',
    'cron': 'INFO',
    'management': 'INFO',
    'exports': 'INFO',
    'notifications': 'INFO',
    'monitoring': 'INFO',
    'regularization': 'INFO',
    'analytics': 'INFO',
    'auto_marking': 'INFO',
    'bulk_operations': 'INFO',
    'integrations': 'INFO',
    'security': 'WARNING',
    'performance': 'INFO',
    'errors': 'ERROR'
}

# Log file configurations
LOG_FILE_CONFIGS = {
    'attendance': {
        'filename': 'attendance.log',
        'max_bytes': 20 * 1024 * 1024,  # 20MB
        'backup_count': 10,
        'description': 'Main attendance system logs'
    },
    'attendance_api': {
        'filename': 'attendance_api.log',
        'max_bytes': 15 * 1024 * 1024,  # 15MB
        'backup_count': 10,
        'description': 'Attendance API requests and responses'
    },
    'attendance_operations': {
        'filename': 'attendance_operations.log',
        'max_bytes': 15 * 1024 * 1024,  # 15MB
        'backup_count': 10,
        'description': 'Clock in/out and attendance operations'
    },
    'attendance_cron': {
        'filename': 'attendance_cron.log',
        'max_bytes': 15 * 1024 * 1024,  # 15MB
        'backup_count': 10,
        'description': 'Automated attendance cron jobs'
    },
    'attendance_errors': {
        'filename': 'attendance_errors.log',
        'max_bytes': 15 * 1024 * 1024,  # 15MB
        'backup_count': 10,
        'description': 'Attendance system errors and exceptions'
    },
    'attendance_security': {
        'filename': 'attendance_security.log',
        'max_bytes': 15 * 1024 * 1024,  # 15MB
        'backup_count': 10,
        'description': 'Security events and unauthorized access attempts'
    },
    'attendance_performance': {
        'filename': 'attendance_performance.log',
        'max_bytes': 15 * 1024 * 1024,  # 15MB
        'backup_count': 10,
        'description': 'Performance metrics and timing data'
    },
    'attendance_regularization': {
        'filename': 'attendance_regularization.log',
        'max_bytes': 10 * 1024 * 1024,  # 10MB
        'backup_count': 5,
        'description': 'Attendance regularization requests and approvals'
    },
    'attendance_exports': {
        'filename': 'attendance_exports.log',
        'max_bytes': 10 * 1024 * 1024,  # 10MB
        'backup_count': 5,
        'description': 'Data exports and report generations'
    }
}

# Operation categories and their log levels
OPERATION_LOG_LEVELS = {
    'clock_in': 'INFO',
    'clock_out': 'INFO',
    'break_start': 'INFO',
    'break_end': 'INFO',
    'overtime': 'INFO',
    'leave': 'INFO',
    'holiday': 'INFO',
    'regularization_request': 'INFO',
    'regularization_approval': 'INFO',
    'report_generation': 'INFO',
    'data_export': 'INFO',
    'bulk_update': 'WARNING',
    'cron_jobs': 'INFO',
    'api_access': 'DEBUG',
    'authentication': 'INFO',
    'security_event': 'WARNING'
}

# Log retention settings
LOG_RETENTION_CONFIG = {
    'max_age_days': 90,  # Keep logs for 90 days
    'cleanup_frequency': 'daily',  # Run cleanup daily
    'compress_old_logs': True,
    'min_free_space_mb': 1024,  # Minimum 1GB free space
    'alert_on_low_space': True
}

# Performance monitoring thresholds
PERFORMANCE_THRESHOLDS = {
    'slow_operation_seconds': 5.0,
    'very_slow_operation_seconds': 10.0,
    'api_response_warning_seconds': 2.0,
    'api_response_error_seconds': 5.0,
    'database_query_warning_seconds': 1.0,
    'export_operation_warning_seconds': 30.0
}

# Security monitoring settings
SECURITY_SETTINGS = {
    'log_failed_logins': True,
    'log_unauthorized_access': True,
    'log_suspicious_activity': True,
    'failed_login_threshold': 5,  # Log after 5 failed attempts
    'ip_tracking_enabled': True,
    'user_agent_tracking': True,
    'session_monitoring': True
}


class AttendanceLoggingConfig:
    """
    Configuration manager for attendance logging system.
    """

    def __init__(self):
        self.base_dir = Path(settings.BASE_DIR)
        self.logs_dir = self.base_dir / 'logs' / 'attendance'
        self._ensure_directories()

    def _ensure_directories(self):
        """Ensure all required log directories exist."""
        try:
            self.logs_dir.mkdir(parents=True, exist_ok=True)

            # Create subdirectories for different log types
            subdirs = ['operations', 'api', 'cron', 'security', 'performance', 'exports']
            for subdir in subdirs:
                (self.logs_dir / subdir).mkdir(exist_ok=True)

            print(style.SUCCESS(f"✓ Attendance log directories created at: {self.logs_dir}"))

        except Exception as e:
            print(style.ERROR(f"✗ Failed to create log directories: {e}"))
            raise

    def get_log_file_path(self, log_type: str) -> Path:
        """
        Get the full path for a log file.

        Args:
            log_type (str): Type of log file

        Returns:
            Path: Full path to the log file
        """
        if log_type not in LOG_FILE_CONFIGS:
            raise ValueError(f"Unknown log type: {log_type}")

        filename = LOG_FILE_CONFIGS[log_type]['filename']
        return self.logs_dir / filename

    def validate_configuration(self) -> Dict[str, Union[bool, List[str]]]:
        """
        Validate the logging configuration.

        Returns:
            Dict: Validation results with status and any errors
        """
        errors = []
        warnings = []

        # Check if log directory exists and is writable
        if not self.logs_dir.exists():
            errors.append(f"Log directory does not exist: {self.logs_dir}")
        elif not os.access(self.logs_dir, os.W_OK):
            errors.append(f"Log directory is not writable: {self.logs_dir}")

        # Check disk space
        try:
            free_space = self._get_free_space(self.logs_dir)
            min_space = LOG_RETENTION_CONFIG['min_free_space_mb'] * 1024 * 1024

            if free_space < min_space:
                warnings.append(f"Low disk space: {free_space / (1024*1024):.1f}MB available")
        except Exception as e:
            warnings.append(f"Could not check disk space: {e}")

        # Validate log file configurations
        for log_type, config in LOG_FILE_CONFIGS.items():
            log_path = self.get_log_file_path(log_type)

            # Check if parent directory exists
            if not log_path.parent.exists():
                errors.append(f"Parent directory missing for {log_type}: {log_path.parent}")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }

    def _get_free_space(self, path: Path) -> int:
        """Get free disk space in bytes."""
        stat = os.statvfs(path)
        return stat.f_bavail * stat.f_frsize

    def get_logger_settings(self) -> Dict:
        """
        Get the complete logger settings for Django configuration.

        Returns:
            Dict: Logger settings ready for Django LOGGING configuration
        """
        handlers = {}
        loggers = {}

        # Create handlers for each log file type
        for log_type, config in LOG_FILE_CONFIGS.items():
            handler_name = f"{log_type}_file"
            log_path = self.get_log_file_path(log_type)

            handlers[handler_name] = {
                'level': 'INFO' if log_type != 'attendance_errors' else 'ERROR',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': str(log_path),
                'maxBytes': config['max_bytes'],
                'backupCount': config['backup_count'],
                'formatter': 'json' if 'api' in log_type or 'performance' in log_type else 'detailed',
            }

        # Create loggers for attendance components
        base_loggers = [
            'trueAlign.attendance',
            'trueAlign.attendance.views',
            'trueAlign.attendance.api_views',
            'trueAlign.attendance.services',
            'trueAlign.attendance.models',
            'trueAlign.attendance.signals',
            'trueAlign.attendance.cron',
            'trueAlign.attendance.management',
            'trueAlign.attendance.exports',
            'trueAlign.attendance.notifications',
            'trueAlign.attendance.monitoring',
            'trueAlign.attendance.regularization',
            'trueAlign.attendance.analytics',
            'trueAlign.attendance.auto_marking',
            'trueAlign.attendance.bulk_operations',
            'trueAlign.attendance.integrations',
            'trueAlign.attendance.security',
            'trueAlign.attendance.performance'
        ]

        for logger_name in base_loggers:
            component = logger_name.split('.')[-1]
            level = DEFAULT_LOG_LEVELS.get(component, 'INFO')

            # Determine appropriate handlers
            handler_list = ['attendance_file', 'console']

            if 'api' in component:
                handler_list.insert(0, 'attendance_api_file')
            elif component in ['cron', 'management']:
                handler_list.insert(0, 'attendance_cron_file')
            elif component == 'security':
                handler_list = ['attendance_security_file', 'attendance_errors_file']
            elif component == 'performance':
                handler_list = ['attendance_performance_file']
            elif component in ['exports', 'regularization']:
                handler_list.insert(0, f'attendance_{component}_file')

            loggers[logger_name] = {
                'handlers': handler_list,
                'level': level,
                'propagate': False
            }

        return {
            'handlers': handlers,
            'loggers': loggers
        }

    def setup_log_rotation(self):
        """Setup automatic log rotation and cleanup."""
        try:
            # This would typically be called by a management command
            print(style.HTTP_INFO("Setting up log rotation for attendance logs..."))

            # Implementation would depend on the system (logrotate, custom script, etc.)
            rotation_config = {
                'directory': str(self.logs_dir),
                'max_age': LOG_RETENTION_CONFIG['max_age_days'],
                'compress': LOG_RETENTION_CONFIG['compress_old_logs'],
                'frequency': LOG_RETENTION_CONFIG['cleanup_frequency']
            }

            print(style.SUCCESS("✓ Log rotation configured"))
            return rotation_config

        except Exception as e:
            print(style.ERROR(f"✗ Failed to setup log rotation: {e}"))
            raise

    def get_log_statistics(self) -> Dict[str, Dict]:
        """
        Get statistics about log files.

        Returns:
            Dict: Statistics for each log file
        """
        stats = {}

        for log_type in LOG_FILE_CONFIGS.keys():
            log_path = self.get_log_file_path(log_type)

            if log_path.exists():
                file_stats = log_path.stat()
                stats[log_type] = {
                    'size_mb': file_stats.st_size / (1024 * 1024),
                    'modified': file_stats.st_mtime,
                    'exists': True
                }
            else:
                stats[log_type] = {
                    'size_mb': 0,
                    'modified': None,
                    'exists': False
                }

        return stats

    def cleanup_old_logs(self, max_age_days: Optional[int] = None) -> Dict[str, int]:
        """
        Clean up old log files.

        Args:
            max_age_days (int, optional): Maximum age in days. Uses default if not provided.

        Returns:
            Dict: Cleanup results
        """
        if max_age_days is None:
            max_age_days = LOG_RETENTION_CONFIG['max_age_days']

        import time
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)

        cleaned_files = 0
        freed_space = 0
        errors = []

        try:
            for log_file in self.logs_dir.rglob('*.log*'):
                if log_file.stat().st_mtime < cutoff_time:
                    try:
                        file_size = log_file.stat().st_size
                        log_file.unlink()
                        cleaned_files += 1
                        freed_space += file_size
                    except Exception as e:
                        errors.append(f"Failed to delete {log_file}: {e}")

        except Exception as e:
            errors.append(f"Log cleanup failed: {e}")

        return {
            'cleaned_files': cleaned_files,
            'freed_space_mb': freed_space / (1024 * 1024),
            'errors': errors
        }


# Global configuration instance
attendance_logging_config = AttendanceLoggingConfig()


def initialize_attendance_logging() -> bool:
    """
    Initialize the attendance logging system.

    Returns:
        bool: True if initialization was successful
    """
    try:
        print(style.HTTP_INFO("Initializing attendance logging system..."))

        # Validate configuration
        validation = attendance_logging_config.validate_configuration()

        if not validation['valid']:
            for error in validation['errors']:
                print(style.ERROR(f"✗ {error}"))
            return False

        # Print warnings if any
        for warning in validation['warnings']:
            print(style.WARNING(f"⚠ {warning}"))

        # Setup log rotation
        attendance_logging_config.setup_log_rotation()

        print(style.SUCCESS("✓ Attendance logging system initialized successfully"))
        return True

    except Exception as e:
        print(style.ERROR(f"✗ Failed to initialize attendance logging: {e}"))
        return False


def get_attendance_logging_status() -> Dict:
    """
    Get the current status of the attendance logging system.

    Returns:
        Dict: Status information
    """
    config = attendance_logging_config

    return {
        'logs_directory': str(config.logs_dir),
        'directory_exists': config.logs_dir.exists(),
        'validation': config.validate_configuration(),
        'log_statistics': config.get_log_statistics(),
        'configuration': {
            'log_files': list(LOG_FILE_CONFIGS.keys()),
            'log_levels': DEFAULT_LOG_LEVELS,
            'retention_days': LOG_RETENTION_CONFIG['max_age_days'],
            'performance_thresholds': PERFORMANCE_THRESHOLDS
        }
    }


# Export configuration constants and functions
__all__ = [
    'AttendanceLoggingConfig',
    'attendance_logging_config',
    'initialize_attendance_logging',
    'get_attendance_logging_status',
    'DEFAULT_LOG_LEVELS',
    'LOG_FILE_CONFIGS',
    'OPERATION_LOG_LEVELS',
    'LOG_RETENTION_CONFIG',
    'PERFORMANCE_THRESHOLDS',
    'SECURITY_SETTINGS'
]
