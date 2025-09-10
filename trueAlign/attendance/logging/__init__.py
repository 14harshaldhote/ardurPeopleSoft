"""
Attendance Logging Configuration Module

This module provides comprehensive logging setup for all attendance-related operations.
It includes specialized loggers for different attendance components and operations.
"""

import logging
import os
from pathlib import Path
from django.conf import settings

# Logger names for different attendance components
ATTENDANCE_LOGGERS = {
    'main': 'trueAlign.attendance',
    'views': 'trueAlign.attendance.views',
    'api_views': 'trueAlign.attendance.api_views',
    'services': 'trueAlign.attendance.services',
    'models': 'trueAlign.attendance.models',
    'signals': 'trueAlign.attendance.signals',
    'cron': 'trueAlign.attendance.cron',
    'management': 'trueAlign.attendance.management',
    'exports': 'trueAlign.attendance.exports',
    'notifications': 'trueAlign.attendance.notifications',
    'monitoring': 'trueAlign.attendance.monitoring',
    'regularization': 'trueAlign.attendance.regularization',
    'analytics': 'trueAlign.attendance.analytics',
    'auto_marking': 'trueAlign.attendance.auto_marking',
    'bulk_operations': 'trueAlign.attendance.bulk_operations',
    'integrations': 'trueAlign.attendance.integrations',
    'security': 'trueAlign.attendance.security',
    'performance': 'trueAlign.attendance.performance'
}

# Operation-specific logger categories
OPERATION_LOGGERS = {
    'clock_in': 'trueAlign.attendance.operations.clock_in',
    'clock_out': 'trueAlign.attendance.operations.clock_out',
    'break_start': 'trueAlign.attendance.operations.break_start',
    'break_end': 'trueAlign.attendance.operations.break_end',
    'overtime': 'trueAlign.attendance.operations.overtime',
    'leave': 'trueAlign.attendance.operations.leave',
    'holiday': 'trueAlign.attendance.operations.holiday',
    'regularization_request': 'trueAlign.attendance.operations.regularization_request',
    'regularization_approval': 'trueAlign.attendance.operations.regularization_approval',
    'report_generation': 'trueAlign.attendance.operations.report_generation',
    'data_export': 'trueAlign.attendance.operations.data_export',
    'bulk_update': 'trueAlign.attendance.operations.bulk_update',
    'cron_jobs': 'trueAlign.attendance.operations.cron_jobs'
}


def get_attendance_logger(component='main'):
    """
    Get a logger for a specific attendance component.

    Args:
        component (str): The component name (e.g., 'views', 'services', 'api_views')

    Returns:
        logging.Logger: Configured logger instance
    """
    logger_name = ATTENDANCE_LOGGERS.get(component, ATTENDANCE_LOGGERS['main'])
    return logging.getLogger(logger_name)


def get_operation_logger(operation):
    """
    Get a logger for a specific attendance operation.

    Args:
        operation (str): The operation name (e.g., 'clock_in', 'regularization_request')

    Returns:
        logging.Logger: Configured logger instance
    """
    logger_name = OPERATION_LOGGERS.get(operation, ATTENDANCE_LOGGERS['main'])
    return logging.getLogger(logger_name)


def log_attendance_action(user, action, details=None, level='info', operation=None):
    """
    Log an attendance action with structured format.

    Args:
        user: User object who performed the action
        action (str): Description of the action
        details (dict, optional): Additional details about the action
        level (str): Log level ('info', 'warning', 'error', 'debug')
        operation (str, optional): Specific operation type for targeted logging
    """
    if operation:
        logger = get_operation_logger(operation)
    else:
        logger = get_attendance_logger('main')

    log_message = f"User: {user.username} | Action: {action}"

    if details:
        detail_str = " | ".join([f"{k}: {v}" for k, v in details.items()])
        log_message += f" | Details: {detail_str}"

    log_method = getattr(logger, level.lower(), logger.info)
    log_method(log_message)


def log_attendance_error(user, operation, error, context=None):
    """
    Log attendance-related errors with consistent format.

    Args:
        user: User object (can be None for system errors)
        operation (str): The operation that failed
        error: The error object or message
        context (dict, optional): Additional context about the error
    """
    logger = get_attendance_logger('main')

    user_info = f"User: {user.username}" if user else "System"
    error_message = f"{user_info} | Operation: {operation} | Error: {str(error)}"

    if context:
        context_str = " | ".join([f"{k}: {v}" for k, v in context.items()])
        error_message += f" | Context: {context_str}"

    logger.error(error_message, exc_info=True)


def log_performance_metric(operation, duration, user=None, additional_metrics=None):
    """
    Log performance metrics for attendance operations.

    Args:
        operation (str): The operation being measured
        duration (float): Duration in seconds
        user: User object (optional)
        additional_metrics (dict, optional): Additional performance metrics
    """
    logger = get_attendance_logger('performance')

    user_info = f"User: {user.username}" if user else "System"
    message = f"{user_info} | Operation: {operation} | Duration: {duration:.3f}s"

    if additional_metrics:
        metrics_str = " | ".join([f"{k}: {v}" for k, v in additional_metrics.items()])
        message += f" | Metrics: {metrics_str}"

    logger.info(message)


def log_security_event(user, event_type, description, severity='warning', ip_address=None):
    """
    Log security-related events in attendance system.

    Args:
        user: User object
        event_type (str): Type of security event
        description (str): Description of the event
        severity (str): Severity level ('info', 'warning', 'error', 'critical')
        ip_address (str, optional): IP address involved in the event
    """
    logger = get_attendance_logger('security')

    message = f"User: {user.username} | Event: {event_type} | Description: {description}"

    if ip_address:
        message += f" | IP: {ip_address}"

    log_method = getattr(logger, severity.lower(), logger.warning)
    log_method(message)


def log_data_access(user, data_type, action, record_count=None, filters=None):
    """
    Log data access events for compliance and auditing.

    Args:
        user: User object
        data_type (str): Type of data accessed (e.g., 'attendance_records', 'reports')
        action (str): Action performed (e.g., 'view', 'export', 'modify')
        record_count (int, optional): Number of records involved
        filters (dict, optional): Filters applied to the data
    """
    logger = get_attendance_logger('main')

    message = f"User: {user.username} | Data Access: {data_type} | Action: {action}"

    if record_count is not None:
        message += f" | Records: {record_count}"

    if filters:
        filter_str = " | ".join([f"{k}: {v}" for k, v in filters.items()])
        message += f" | Filters: {filter_str}"

    logger.info(message)


class AttendanceLoggerMixin:
    """
    Mixin class to add logging capabilities to attendance-related classes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = get_attendance_logger(self.__class__.__module__.split('.')[-1])

    def log_info(self, message, **kwargs):
        """Log info message with class context."""
        self.logger.info(f"{self.__class__.__name__}: {message}", **kwargs)

    def log_warning(self, message, **kwargs):
        """Log warning message with class context."""
        self.logger.warning(f"{self.__class__.__name__}: {message}", **kwargs)

    def log_error(self, message, **kwargs):
        """Log error message with class context."""
        self.logger.error(f"{self.__class__.__name__}: {message}", **kwargs)

    def log_debug(self, message, **kwargs):
        """Log debug message with class context."""
        self.logger.debug(f"{self.__class__.__name__}: {message}", **kwargs)


# Initialize default loggers
attendance_logger = get_attendance_logger('main')
views_logger = get_attendance_logger('views')
api_logger = get_attendance_logger('api_views')
services_logger = get_attendance_logger('services')
cron_logger = get_attendance_logger('cron')

# Export commonly used loggers and functions
__all__ = [
    'get_attendance_logger',
    'get_operation_logger',
    'log_attendance_action',
    'log_attendance_error',
    'log_performance_metric',
    'log_security_event',
    'log_data_access',
    'AttendanceLoggerMixin',
    'attendance_logger',
    'views_logger',
    'api_logger',
    'services_logger',
    'cron_logger',
    'ATTENDANCE_LOGGERS',
    'OPERATION_LOGGERS'
]
