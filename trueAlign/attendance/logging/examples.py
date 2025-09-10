"""
Attendance Logging Usage Examples and Documentation

This module provides comprehensive examples of how to use the attendance logging system
in various scenarios. It demonstrates best practices, common patterns, and advanced
usage scenarios for logging attendance-related operations.

Author: TrueAlign Development Team
Date: December 2024
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from django.contrib.auth import get_user_model
from django.http import HttpRequest, JsonResponse
from django.utils import timezone

# Import the attendance logging utilities
from . import (
    get_attendance_logger,
    get_operation_logger,
    log_attendance_action,
    log_attendance_error,
    log_performance_metric,
    log_security_event,
    log_data_access,
    AttendanceLoggerMixin
)

from .utils import (
    log_attendance_operation,
    log_clock_action,
    log_regularization_action,
    log_data_export,
    log_bulk_operation,
    log_cron_job_execution,
    log_api_access,
    log_authentication_event,
    AttendanceOperationLogger
)

User = get_user_model()


# ============================================================================
# BASIC LOGGING EXAMPLES
# ============================================================================

def example_basic_logging():
    """
    Example 1: Basic logging for attendance operations
    """
    # Get a logger for the main attendance system
    logger = get_attendance_logger('main')

    # Log different levels of messages
    logger.info("Attendance system started")
    logger.debug("Processing attendance records")
    logger.warning("Late clock-in detected")
    logger.error("Failed to process attendance record")

    # Get specialized loggers for different components
    views_logger = get_attendance_logger('views')
    api_logger = get_attendance_logger('api_views')
    services_logger = get_attendance_logger('services')

    views_logger.info("Dashboard view accessed")
    api_logger.info("API endpoint called")
    services_logger.info("Service operation completed")


def example_structured_logging(user):
    """
    Example 2: Structured logging with user context and details
    """
    # Log an attendance action with structured details
    log_attendance_action(
        user=user,
        action="Clock in successful",
        details={
            'timestamp': timezone.now().isoformat(),
            'location': 'Office Building A',
            'device': 'Web Browser',
            'ip_address': '192.168.1.100'
        },
        level='info',
        operation='clock_in'
    )

    # Log with different levels
    log_attendance_action(
        user=user,
        action="Late arrival detected",
        details={
            'expected_time': '09:00:00',
            'actual_time': '09:15:00',
            'delay_minutes': 15
        },
        level='warning',
        operation='clock_in'
    )


def example_error_logging(user):
    """
    Example 3: Error logging with context
    """
    try:
        # Simulate an operation that might fail
        result = risky_attendance_operation(user)
    except ValueError as e:
        log_attendance_error(
            user=user,
            operation='attendance_calculation',
            error=e,
            context={
                'user_id': user.id,
                'operation_details': 'calculating weekly hours',
                'input_data': 'attendance records for week 50'
            }
        )
    except Exception as e:
        log_attendance_error(
            user=user,
            operation='attendance_calculation',
            error=e,
            context={'unexpected_error': True}
        )


# ============================================================================
# DECORATOR EXAMPLES
# ============================================================================

@log_attendance_operation('clock_in', level='info')
def clock_in_user(user, timestamp=None, location=None):
    """
    Example 4: Using the logging decorator for automatic operation logging
    """
    if timestamp is None:
        timestamp = timezone.now()

    # Simulate clock-in logic
    time.sleep(0.1)  # Simulate processing time

    # The decorator will automatically log the operation timing and result
    return {
        'success': True,
        'timestamp': timestamp,
        'user': user.username,
        'location': location
    }


@log_attendance_operation('data_export', level='info')
def export_attendance_data(user, start_date, end_date, format='csv'):
    """
    Example 5: Logging data export operations
    """
    # Simulate export processing
    time.sleep(2.0)  # Simulate longer operation

    record_count = 1500  # Simulated record count

    # Additional manual logging for export details
    log_data_export(
        user=user,
        export_type='attendance_records',
        date_range={'start': str(start_date), 'end': str(end_date)},
        record_count=record_count,
        file_format=format,
        filters={'department': 'Engineering', 'status': 'Present'}
    )

    return {'record_count': record_count, 'format': format}


# ============================================================================
# DJANGO VIEW EXAMPLES
# ============================================================================

def example_view_logging(request):
    """
    Example 6: Logging in Django views
    """
    start_time = time.time()

    try:
        # Log the API access
        log_api_access(
            request=request,
            endpoint='attendance_dashboard',
            response_status=200,
            duration=None,  # Will be calculated later
            data_count=None
        )

        # Your view logic here
        user = request.user
        attendance_data = get_user_attendance_data(user)

        # Log successful data access
        log_data_access(
            user=user,
            data_type='attendance_dashboard',
            action='view',
            record_count=len(attendance_data),
            filters={'date_range': 'current_month'}
        )

        # Calculate duration
        duration = time.time() - start_time

        # Log performance metric
        log_performance_metric(
            operation='attendance_dashboard',
            duration=duration,
            user=user,
            additional_metrics={'record_count': len(attendance_data)}
        )

        return JsonResponse({
            'status': 'success',
            'data': attendance_data
        })

    except Exception as e:
        duration = time.time() - start_time

        log_attendance_error(
            user=request.user if request.user.is_authenticated else None,
            operation='attendance_dashboard',
            error=e,
            context={
                'request_path': request.path,
                'request_method': request.method,
                'duration': duration
            }
        )

        return JsonResponse({
            'status': 'error',
            'message': 'Failed to load dashboard'
        }, status=500)


def example_authentication_logging(request, username, success=True):
    """
    Example 7: Authentication event logging
    """
    try:
        user = User.objects.get(username=username) if success else None
    except User.DoesNotExist:
        user = None

    log_authentication_event(
        user=user,
        event_type='login',
        request=request,
        success=success,
        reason='Invalid credentials' if not success else None
    )


# ============================================================================
# CONTEXT MANAGER EXAMPLES
# ============================================================================

def example_context_manager_logging(user):
    """
    Example 8: Using context manager for operation logging
    """
    # Automatic timing and error handling
    with AttendanceOperationLogger('bulk_attendance_update', user=user,
                                  details={'operation_type': 'monthly_correction'}) as logger:

        # Your operation logic here
        updated_records = []

        for i in range(100):
            # Simulate processing records
            time.sleep(0.01)
            updated_records.append(f"record_{i}")

            # Log progress every 25 records
            if (i + 1) % 25 == 0:
                logger.logger.info(f"Processed {i + 1} records")

        # Operation completed successfully
        return updated_records


# ============================================================================
# SERVICE CLASS EXAMPLES
# ============================================================================

class AttendanceService(AttendanceLoggerMixin):
    """
    Example 9: Service class with logging mixin
    """

    def calculate_monthly_hours(self, user, month, year):
        """Calculate monthly hours with automatic logging."""
        self.log_info(f"Calculating monthly hours for {user.username} - {month}/{year}")

        try:
            # Your calculation logic here
            total_hours = 168.5  # Example result

            self.log_info(f"Monthly hours calculated: {total_hours} hours")
            return total_hours

        except Exception as e:
            self.log_error(f"Failed to calculate monthly hours: {e}")
            raise

    def process_regularization_request(self, user, request_data):
        """Process regularization with detailed logging."""
        self.log_info(f"Processing regularization request from {user.username}")

        try:
            # Log the regularization action
            log_regularization_action(
                user=user,
                action='request_submitted',
                attendance_id=request_data['attendance_id'],
                requested_status=request_data['new_status'],
                previous_status=request_data['current_status'],
                reason=request_data['reason']
            )

            # Process the request
            result = self._process_request(request_data)

            self.log_info(f"Regularization request processed successfully")
            return result

        except Exception as e:
            self.log_error(f"Regularization processing failed: {e}")
            raise


# ============================================================================
# CRON JOB EXAMPLES
# ============================================================================

def example_cron_job_logging():
    """
    Example 10: Logging for cron jobs and scheduled tasks
    """
    job_name = "daily_attendance_auto_marking"
    start_time = time.time()

    try:
        log_cron_job_execution(job_name, 'started')

        # Your cron job logic here
        processed_users = []
        errors = []

        users = User.objects.filter(is_active=True)

        for user in users:
            try:
                # Process each user's attendance
                process_user_attendance(user)
                processed_users.append(user.username)

            except Exception as e:
                errors.append(f"User {user.username}: {str(e)}")

        duration = time.time() - start_time

        log_cron_job_execution(
            job_name=job_name,
            status='completed',
            duration=duration,
            records_processed=len(processed_users),
            errors=errors if errors else None
        )

    except Exception as e:
        duration = time.time() - start_time

        log_cron_job_execution(
            job_name=job_name,
            status='failed',
            duration=duration,
            errors=[str(e)]
        )


# ============================================================================
# SECURITY LOGGING EXAMPLES
# ============================================================================

def example_security_logging(user, request):
    """
    Example 11: Security event logging
    """
    # Log suspicious activity
    log_security_event(
        user=user,
        event_type='suspicious_activity',
        description='Multiple rapid API calls detected',
        severity='warning',
        ip_address=get_client_ip(request)
    )

    # Log unauthorized access attempt
    log_security_event(
        user=user,
        event_type='unauthorized_access',
        description='Attempt to access restricted attendance data',
        severity='error',
        ip_address=get_client_ip(request)
    )


# ============================================================================
# PERFORMANCE MONITORING EXAMPLES
# ============================================================================

def example_performance_monitoring(user):
    """
    Example 12: Performance monitoring and metrics
    """
    # Monitor database query performance
    start_time = time.time()

    # Simulate database query
    attendance_records = get_user_attendance_records(user)

    query_duration = time.time() - start_time

    log_performance_metric(
        operation='database_query_attendance',
        duration=query_duration,
        user=user,
        additional_metrics={
            'record_count': len(attendance_records),
            'query_type': 'user_attendance_fetch'
        }
    )

    # Monitor API response time
    start_time = time.time()

    # Simulate API processing
    api_response = process_attendance_api_request(user)

    api_duration = time.time() - start_time

    log_performance_metric(
        operation='api_attendance_processing',
        duration=api_duration,
        user=user,
        additional_metrics={
            'response_size_kb': len(str(api_response)) / 1024,
            'cache_hit': True
        }
    )


# ============================================================================
# BULK OPERATIONS EXAMPLES
# ============================================================================

def example_bulk_operations_logging(user):
    """
    Example 13: Logging bulk operations
    """
    # Log bulk update operation
    log_bulk_operation(
        user=user,
        operation='bulk_status_update',
        affected_count=250,
        date_range={'start': '2024-12-01', 'end': '2024-12-31'},
        criteria={
            'department': 'Engineering',
            'status': 'Pending',
            'update_to': 'Present'
        }
    )

    # Log bulk export operation
    log_bulk_operation(
        user=user,
        operation='bulk_data_export',
        affected_count=1500,
        date_range={'start': '2024-01-01', 'end': '2024-12-31'},
        criteria={
            'format': 'excel',
            'include_overtime': True,
            'departments': ['Engineering', 'Sales', 'Marketing']
        }
    )


# ============================================================================
# HELPER FUNCTIONS (Simulated for examples)
# ============================================================================

def risky_attendance_operation(user):
    """Simulated risky operation that might fail."""
    import random
    if random.choice([True, False]):
        raise ValueError("Simulated calculation error")
    return "Success"


def get_user_attendance_data(user):
    """Simulated function to get user attendance data."""
    return [{'date': '2024-12-01', 'status': 'Present'} for _ in range(30)]


def get_user_attendance_records(user):
    """Simulated function to get attendance records."""
    return [f"record_{i}" for i in range(100)]


def process_attendance_api_request(user):
    """Simulated API processing."""
    return {'status': 'success', 'data': []}


def process_user_attendance(user):
    """Simulated user attendance processing."""
    time.sleep(0.1)  # Simulate processing time
    return True


def get_client_ip(request):
    """Get client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip or 'Unknown'


# ============================================================================
# TESTING AND DEBUGGING
# ============================================================================

def test_all_logging_examples():
    """
    Test function to run all logging examples.
    This is useful for testing the logging setup.
    """
    print("Testing attendance logging examples...")

    # Create a test user
    try:
        test_user = User.objects.first()
        if not test_user:
            print("No users found, creating test user...")
            test_user = User.objects.create_user(
                username='test_logging_user',
                email='test@example.com'
            )
    except Exception as e:
        print(f"Could not create test user: {e}")
        return

    # Run basic examples
    try:
        example_basic_logging()
        print("✓ Basic logging test passed")
    except Exception as e:
        print(f"✗ Basic logging test failed: {e}")

    try:
        example_structured_logging(test_user)
        print("✓ Structured logging test passed")
    except Exception as e:
        print(f"✗ Structured logging test failed: {e}")

    try:
        example_error_logging(test_user)
        print("✓ Error logging test passed")
    except Exception as e:
        print(f"✗ Error logging test failed: {e}")

    # Test decorator
    try:
        result = clock_in_user(test_user, location="Test Office")
        print("✓ Decorator logging test passed")
    except Exception as e:
        print(f"✗ Decorator logging test failed: {e}")

    # Test context manager
    try:
        example_context_manager_logging(test_user)
        print("✓ Context manager logging test passed")
    except Exception as e:
        print(f"✗ Context manager logging test failed: {e}")

    # Test service class
    try:
        service = AttendanceService()
        service.calculate_monthly_hours(test_user, 12, 2024)
        print("✓ Service class logging test passed")
    except Exception as e:
        print(f"✗ Service class logging test failed: {e}")

    print("Attendance logging examples testing completed!")


if __name__ == "__main__":
    test_all_logging_examples()
