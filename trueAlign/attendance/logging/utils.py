"""
Attendance Logging Utilities

This module provides utility functions and decorators for logging attendance-specific
operations with consistent formatting and appropriate detail levels.
"""

import time
import functools
from datetime import datetime
from typing import Optional, Dict, Any, Callable
from django.utils import timezone
from django.http import HttpRequest

from . import (
    get_attendance_logger,
    get_operation_logger,
    log_attendance_action,
    log_attendance_error,
    log_performance_metric,
    log_security_event
)


def log_attendance_operation(operation_type: str, level: str = 'info'):
    """
    Decorator to log attendance operations with timing and error handling.

    Args:
        operation_type (str): Type of operation being logged
        level (str): Log level for successful operations
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            logger = get_operation_logger(operation_type)

            # Extract user from args if available
            user = None
            if args and hasattr(args[0], 'user'):
                user = args[0].user
            elif 'user' in kwargs:
                user = kwargs['user']

            try:
                # Log operation start
                if user:
                    logger.debug(f"Starting {operation_type} for user: {user.username}")
                else:
                    logger.debug(f"Starting {operation_type}")

                # Execute the function
                result = func(*args, **kwargs)

                # Log successful completion
                duration = time.time() - start_time
                log_performance_metric(operation_type, duration, user)

                if user:
                    log_attendance_action(
                        user=user,
                        action=f"{operation_type} completed successfully",
                        details={'duration_seconds': round(duration, 3)},
                        level=level,
                        operation=operation_type
                    )

                return result

            except Exception as e:
                # Log error
                duration = time.time() - start_time
                log_attendance_error(
                    user=user,
                    operation=operation_type,
                    error=e,
                    context={'duration_seconds': round(duration, 3)}
                )
                raise

        return wrapper
    return decorator


def log_clock_action(action_type: str, user, timestamp: datetime,
                    location: Optional[str] = None, device_info: Optional[Dict] = None):
    """
    Log clock in/out actions with detailed context.

    Args:
        action_type (str): 'clock_in', 'clock_out', 'break_start', 'break_end'
        user: User object
        timestamp (datetime): When the action occurred
        location (str, optional): Location information
        device_info (dict, optional): Device/browser information
    """
    details = {
        'timestamp': timestamp.isoformat(),
        'action_type': action_type
    }

    if location:
        details['location'] = location

    if device_info:
        details.update({f'device_{k}': v for k, v in device_info.items()})

    log_attendance_action(
        user=user,
        action=f"Clock action: {action_type}",
        details=details,
        operation=action_type
    )


def log_regularization_action(user, action: str, attendance_id: int,
                            requested_status: Optional[str] = None,
                            previous_status: Optional[str] = None,
                            reason: Optional[str] = None):
    """
    Log regularization-related actions.

    Args:
        user: User object
        action (str): 'request_submitted', 'approved', 'rejected'
        attendance_id (int): ID of the attendance record
        requested_status (str, optional): Status being requested
        previous_status (str, optional): Previous status
        reason (str, optional): Reason for regularization
    """
    details = {
        'attendance_id': attendance_id,
        'regularization_action': action
    }

    if requested_status:
        details['requested_status'] = requested_status

    if previous_status:
        details['previous_status'] = previous_status

    if reason:
        details['reason'] = reason[:100]  # Truncate long reasons

    operation = 'regularization_request' if action == 'request_submitted' else 'regularization_approval'

    log_attendance_action(
        user=user,
        action=f"Regularization {action}",
        details=details,
        operation=operation
    )


def log_data_export(user, export_type: str, date_range: Dict[str, str],
                   record_count: int, file_format: str,
                   filters: Optional[Dict] = None):
    """
    Log data export operations.

    Args:
        user: User object
        export_type (str): Type of export (attendance, reports, analytics)
        date_range (dict): Start and end dates
        record_count (int): Number of records exported
        file_format (str): Export format (csv, excel, pdf)
        filters (dict, optional): Applied filters
    """
    details = {
        'export_type': export_type,
        'file_format': file_format,
        'record_count': record_count,
        'date_range': f"{date_range.get('start', 'N/A')} to {date_range.get('end', 'N/A')}"
    }

    if filters:
        details['filters'] = str(filters)[:200]  # Truncate long filter strings

    log_attendance_action(
        user=user,
        action=f"Data export: {export_type}",
        details=details,
        operation='data_export'
    )


def log_bulk_operation(user, operation: str, affected_count: int,
                      date_range: Optional[Dict[str, str]] = None,
                      criteria: Optional[Dict] = None):
    """
    Log bulk operations on attendance data.

    Args:
        user: User object
        operation (str): Type of bulk operation
        affected_count (int): Number of records affected
        date_range (dict, optional): Date range for operation
        criteria (dict, optional): Selection criteria
    """
    details = {
        'bulk_operation': operation,
        'affected_records': affected_count
    }

    if date_range:
        details['date_range'] = f"{date_range.get('start', 'N/A')} to {date_range.get('end', 'N/A')}"

    if criteria:
        details['criteria'] = str(criteria)[:200]

    log_attendance_action(
        user=user,
        action=f"Bulk operation: {operation}",
        details=details,
        operation='bulk_update'
    )


def log_cron_job_execution(job_name: str, status: str, duration: Optional[float] = None,
                          records_processed: Optional[int] = None,
                          errors: Optional[list] = None):
    """
    Log cron job execution with detailed metrics.

    Args:
        job_name (str): Name of the cron job
        status (str): 'started', 'completed', 'failed'
        duration (float, optional): Execution duration in seconds
        records_processed (int, optional): Number of records processed
        errors (list, optional): List of errors encountered
    """
    logger = get_operation_logger('cron_jobs')

    details = {
        'job_name': job_name,
        'status': status,
        'timestamp': timezone.now().isoformat()
    }

    if duration is not None:
        details['duration_seconds'] = round(duration, 3)

    if records_processed is not None:
        details['records_processed'] = records_processed

    if errors:
        details['error_count'] = len(errors)
        details['errors'] = str(errors)[:500]  # Truncate long error lists

    message = f"Cron job: {job_name} | Status: {status}"

    if status == 'failed':
        logger.error(message, extra=details)
    elif status == 'completed':
        logger.info(message, extra=details)
    else:
        logger.debug(message, extra=details)


def log_api_access(request: HttpRequest, endpoint: str, response_status: int,
                  duration: Optional[float] = None, data_count: Optional[int] = None):
    """
    Log API access with request details.

    Args:
        request: Django request object
        endpoint (str): API endpoint name
        response_status (int): HTTP response status
        duration (float, optional): Request duration
        data_count (int, optional): Number of data items returned
    """
    user = getattr(request, 'user', None)

    details = {
        'endpoint': endpoint,
        'method': request.method,
        'status_code': response_status,
        'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown')[:100],
        'ip_address': get_client_ip(request)
    }

    if duration is not None:
        details['duration_seconds'] = round(duration, 3)

    if data_count is not None:
        details['data_count'] = data_count

    if user and user.is_authenticated:
        log_attendance_action(
            user=user,
            action=f"API access: {endpoint}",
            details=details,
            operation='api_access'
        )
    else:
        logger = get_attendance_logger('api_views')
        logger.info(f"API access: {endpoint} | Status: {response_status}", extra=details)


def log_authentication_event(user, event_type: str, request: HttpRequest,
                            success: bool = True, reason: Optional[str] = None):
    """
    Log authentication-related events.

    Args:
        user: User object (can be None for failed attempts)
        event_type (str): 'login', 'logout', 'session_expired', 'unauthorized_access'
        request: Django request object
        success (bool): Whether the event was successful
        reason (str, optional): Reason for failure
    """
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')[:100]

    if user:
        username = user.username
    else:
        username = request.POST.get('username', 'Unknown')

    description = f"{event_type} {'successful' if success else 'failed'}"
    if reason:
        description += f" - {reason}"

    details = {
        'user_agent': user_agent,
        'event_type': event_type,
        'success': success
    }

    if reason:
        details['reason'] = reason

    severity = 'info' if success else 'warning'
    if not success and event_type in ['unauthorized_access', 'suspicious_activity']:
        severity = 'error'

    if user:
        log_security_event(
            user=user,
            event_type=event_type,
            description=description,
            severity=severity,
            ip_address=ip_address
        )
    else:
        # Log anonymous security events
        logger = get_attendance_logger('security')
        message = f"Username: {username} | Event: {event_type} | IP: {ip_address} | {description}"
        getattr(logger, severity)(message, extra=details)


def get_client_ip(request: HttpRequest) -> str:
    """
    Get client IP address from request.

    Args:
        request: Django request object

    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip or 'Unknown'


def log_system_health_check(component: str, status: str, metrics: Optional[Dict] = None,
                           message: Optional[str] = None):
    """
    Log system health check results.

    Args:
        component (str): Component being checked
        status (str): 'healthy', 'warning', 'critical'
        metrics (dict, optional): Health metrics
        message (str, optional): Additional message
    """
    logger = get_attendance_logger('monitoring')

    details = {
        'component': component,
        'health_status': status,
        'timestamp': timezone.now().isoformat()
    }

    if metrics:
        details.update(metrics)

    log_message = f"Health check: {component} | Status: {status}"
    if message:
        log_message += f" | {message}"

    if status == 'critical':
        logger.error(log_message, extra=details)
    elif status == 'warning':
        logger.warning(log_message, extra=details)
    else:
        logger.info(log_message, extra=details)


class AttendanceOperationLogger:
    """
    Context manager for logging attendance operations with automatic timing.
    """

    def __init__(self, operation: str, user=None, details: Optional[Dict] = None):
        self.operation = operation
        self.user = user
        self.details = details or {}
        self.start_time = None
        self.logger = get_operation_logger(operation)

    def __enter__(self):
        self.start_time = time.time()
        if self.user:
            self.logger.debug(f"Starting {self.operation} for user: {self.user.username}")
        else:
            self.logger.debug(f"Starting {self.operation}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time

        if exc_type is None:
            # Success
            log_performance_metric(self.operation, duration, self.user)
            if self.user:
                log_attendance_action(
                    user=self.user,
                    action=f"{self.operation} completed",
                    details={**self.details, 'duration_seconds': round(duration, 3)},
                    operation=self.operation
                )
        else:
            # Error occurred
            log_attendance_error(
                user=self.user,
                operation=self.operation,
                error=exc_val,
                context={**self.details, 'duration_seconds': round(duration, 3)}
            )

        return False  # Don't suppress exceptions
