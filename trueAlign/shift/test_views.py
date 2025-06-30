"""
Test views for verifying the enhanced logging system in Django context.

This module contains test views that demonstrate all logging features:
- Action-based logging with decorators
- User activity tracking
- Database operations logging
- Performance monitoring
- Security event logging
- Error handling with stack traces

Usage:
    Add to your urls.py:
    path('test-logging/', include('trueAlign.shift.test_views'))
"""

import logging
import time
import uuid
from datetime import datetime
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User
from django.db import transaction
from trueAlign.models import ShiftMaster, ShiftAssignment
from trueAlign.shift.views import log_action, log_user_action, log_db_operation, get_client_ip

logger = logging.getLogger('trueAlign.shift')


@log_action('TEST_LOGGING_DASHBOARD')
def test_logging_dashboard(request):
    """
    Test dashboard to demonstrate all logging features.
    """
    log_user_action(request.user, 'test_dashboard_access',
                   details={'test_session': True})

    # Simulate some performance logging
    start_time = time.time()
    time.sleep(0.1)  # Simulate processing
    duration = (time.time() - start_time) * 1000

    logger.info(f"Test dashboard rendered in {duration:.2f}ms")

    context = {
        'page_title': 'Logging Test Dashboard',
        'user': request.user,
        'timestamp': datetime.now(),
        'request_id': str(uuid.uuid4())[:8]
    }

    return render(request, 'shift/test_logging.html', context)


@login_required
@log_action('TEST_CREATE_SHIFT')
def test_create_shift(request):
    """
    Test shift creation with comprehensive logging.
    """
    if request.method == 'POST':
        shift_name = request.POST.get('name', f'Test Shift {int(time.time())}')

        log_user_action(request.user, 'test_shift_creation_attempt',
                       details={'shift_name': shift_name})

        try:
            with transaction.atomic():
                # Create a test shift
                shift = ShiftMaster.objects.create(
                    name=shift_name,
                    description=f'Test shift created at {datetime.now()}',
                    start_time='09:00:00',
                    end_time='17:00:00',
                    created_by=request.user
                )

                log_db_operation('CREATE', 'ShiftMaster', shift.id,
                               {'name': shift_name, 'created_by': request.user.username})

                logger.info(f"Test shift '{shift_name}' created successfully by {request.user.username}")
                log_user_action(request.user, 'test_shift_created',
                               target=f'shift_{shift.id}',
                               details={'shift_name': shift_name})

                messages.success(request, f"Test shift '{shift_name}' created successfully!")

        except Exception as e:
            logger.error(f"Error creating test shift by {request.user.username}: {str(e)}",
                        exc_info=True)
            log_user_action(request.user, 'test_shift_creation_failed',
                           details={'error': str(e), 'shift_name': shift_name})
            messages.error(request, f"Error creating test shift: {str(e)}")

    return redirect('shift:test_dashboard')


@login_required
@log_action('TEST_SECURITY_EVENT')
def test_security_logging(request):
    """
    Test security event logging.
    """
    security_logger = logging.getLogger('trueAlign.shift.security')

    # Simulate different security events
    events = [
        ('permission_check', 'INFO'),
        ('unauthorized_access_attempt', 'WARNING'),
        ('suspicious_activity', 'WARNING'),
        ('security_violation', 'ERROR')
    ]

    for event, level in events:
        extra_data = {
            'event_type': 'security_test',
            'event': event,
            'user_id': request.user.id,
            'user': request.user.username,
            'ip': get_client_ip(request),
            'timestamp': datetime.now().isoformat(),
            'test_mode': True
        }

        message = f"SECURITY TEST: {event}"

        if level == 'ERROR':
            security_logger.error(message, extra=extra_data)
        elif level == 'WARNING':
            security_logger.warning(message, extra=extra_data)
        else:
            security_logger.info(message, extra=extra_data)

    log_user_action(request.user, 'security_test_completed',
                   details={'events_logged': len(events)})

    messages.info(request, f"Security test completed - {len(events)} events logged")
    return redirect('shift:test_dashboard')


@login_required
@log_action('TEST_API_LOGGING')
def test_api_logging(request):
    """
    Test API-style logging with JSON response.
    """
    api_logger = logging.getLogger('trueAlign.shift.api')

    start_time = time.time()

    # Simulate API processing
    time.sleep(0.05)  # 50ms delay

    duration = (time.time() - start_time) * 1000

    # Log API request
    api_logger.info(f"API TEST /test-api/ - 200 ({duration:.2f}ms)", extra={
        'api_method': 'GET',
        'api_endpoint': '/test-api/',
        'status_code': 200,
        'duration_ms': duration,
        'user_id': request.user.id,
        'request_id': str(uuid.uuid4())[:8],
        'timestamp': datetime.now().isoformat(),
        'test_mode': True
    })

    log_user_action(request.user, 'api_test_called',
                   details={'endpoint': '/test-api/', 'duration_ms': duration})

    response_data = {
        'status': 'success',
        'message': 'API logging test completed',
        'duration_ms': duration,
        'timestamp': datetime.now().isoformat(),
        'user': request.user.username
    }

    return JsonResponse(response_data)


@login_required
@log_action('TEST_ERROR_HANDLING')
def test_error_logging(request):
    """
    Test error logging with different types of errors.
    """
    error_type = request.GET.get('type', 'division')

    log_user_action(request.user, 'error_test_initiated',
                   details={'error_type': error_type})

    try:
        if error_type == 'division':
            # Division by zero error
            result = 10 / 0
        elif error_type == 'key':
            # Key error
            test_dict = {'key1': 'value1'}
            value = test_dict['nonexistent_key']
        elif error_type == 'type':
            # Type error
            result = "string" + 123
        elif error_type == 'value':
            # Value error
            result = int("not_a_number")
        else:
            # Custom error
            raise ValueError(f"Custom test error: {error_type}")

    except Exception as e:
        logger.error(f"Test error ({error_type}) by user {request.user.username}: {str(e)}",
                    exc_info=True, extra={
                        'error_type': type(e).__name__,
                        'error_category': error_type,
                        'user_id': request.user.id,
                        'user': request.user.username,
                        'ip': get_client_ip(request),
                        'timestamp': datetime.now().isoformat(),
                        'test_mode': True
                    })

        log_user_action(request.user, 'error_test_completed',
                       details={'error_type': error_type, 'exception': type(e).__name__})

        messages.warning(request, f"Error test completed - {type(e).__name__}: {str(e)}")
        return redirect('shift:test_dashboard')

    # This shouldn't be reached, but just in case
    messages.info(request, "Error test completed - no error occurred")
    return redirect('shift:test_dashboard')


@login_required
@log_action('TEST_PERFORMANCE_MONITORING')
def test_performance_logging(request):
    """
    Test performance monitoring with different operation speeds.
    """
    perf_logger = logging.getLogger('trueAlign.shift.performance')
    operation_type = request.GET.get('type', 'fast')

    start_time = time.time()

    # Simulate different performance scenarios
    if operation_type == 'fast':
        time.sleep(0.05)  # 50ms - fast operation
        threshold = 100
    elif operation_type == 'medium':
        time.sleep(0.3)   # 300ms - medium operation
        threshold = 500
    elif operation_type == 'slow':
        time.sleep(1.2)   # 1200ms - slow operation
        threshold = 1000
    else:
        time.sleep(0.1)   # 100ms - default
        threshold = 200

    duration = (time.time() - start_time) * 1000

    # Log performance
    extra_data = {
        'operation': f'test_{operation_type}_operation',
        'duration_ms': duration,
        'threshold_ms': threshold,
        'user_id': request.user.id,
        'timestamp': datetime.now().isoformat(),
        'test_mode': True
    }

    message = f"PERFORMANCE TEST: {operation_type}_operation took {duration:.2f}ms"

    if duration > threshold:
        perf_logger.warning(message, extra=extra_data)
        log_level = 'WARNING'
    else:
        perf_logger.info(message, extra=extra_data)
        log_level = 'INFO'

    log_user_action(request.user, 'performance_test_completed',
                   details={'operation_type': operation_type, 'duration_ms': duration,
                           'log_level': log_level})

    messages.info(request, f"Performance test completed - {operation_type} operation took {duration:.2f}ms")
    return redirect('shift:test_dashboard')


@login_required
@log_action('TEST_USER_WORKFLOW')
def test_user_workflow(request):
    """
    Test a complete user workflow with comprehensive logging.
    """
    workflow_id = str(uuid.uuid4())[:8]

    log_user_action(request.user, 'workflow_test_started',
                   details={'workflow_id': workflow_id})

    try:
        # Step 1: User accesses dashboard
        logger.info(f"Workflow {workflow_id}: User {request.user.username} accessed dashboard")
        log_user_action(request.user, 'workflow_dashboard_access',
                       details={'workflow_id': workflow_id, 'step': 1})

        # Step 2: User views shift list
        logger.info(f"Workflow {workflow_id}: User {request.user.username} viewed shift list")
        log_user_action(request.user, 'workflow_shift_list_view',
                       details={'workflow_id': workflow_id, 'step': 2})

        # Step 3: User attempts to create shift
        logger.info(f"Workflow {workflow_id}: User {request.user.username} initiated shift creation")
        log_user_action(request.user, 'workflow_shift_creation_initiated',
                       details={'workflow_id': workflow_id, 'step': 3})

        # Step 4: Database operation
        shifts_count = ShiftMaster.objects.count()
        logger.info(f"Workflow {workflow_id}: Current shifts count: {shifts_count}")
        log_db_operation('READ', 'ShiftMaster', None, {'operation': 'count', 'result': shifts_count})

        # Step 5: User completes workflow
        logger.info(f"Workflow {workflow_id}: User {request.user.username} completed workflow")
        log_user_action(request.user, 'workflow_completed',
                       details={'workflow_id': workflow_id, 'steps_completed': 5,
                               'shifts_in_system': shifts_count})

        messages.success(request, f"Workflow test completed successfully (ID: {workflow_id})")

    except Exception as e:
        logger.error(f"Workflow {workflow_id} failed for user {request.user.username}: {str(e)}",
                    exc_info=True)
        log_user_action(request.user, 'workflow_failed',
                       details={'workflow_id': workflow_id, 'error': str(e)})
        messages.error(request, f"Workflow test failed: {str(e)}")

    return redirect('shift:test_dashboard')


@require_http_methods(["GET"])
def test_logging_status(request):
    """
    Check logging system status and configuration.
    """
    import os
    from pathlib import Path

    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    logs_dir = base_dir / 'logs'

    status_data = {
        'logging_active': True,
        'logs_directory': str(logs_dir),
        'logs_exist': logs_dir.exists(),
        'log_files': [],
        'loggers_configured': [],
        'timestamp': datetime.now().isoformat()
    }

    # Check log files
    if logs_dir.exists():
        for log_file in logs_dir.glob('*.log'):
            status_data['log_files'].append({
                'name': log_file.name,
                'size': log_file.stat().st_size,
                'modified': datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
            })

    # Check configured loggers
    logger_names = [
        'trueAlign.shift',
        'trueAlign.shift.actions',
        'trueAlign.shift.security',
        'trueAlign.shift.api',
        'trueAlign.shift.performance'
    ]

    for logger_name in logger_names:
        test_logger = logging.getLogger(logger_name)
        status_data['loggers_configured'].append({
            'name': logger_name,
            'level': test_logger.level,
            'handlers': len(test_logger.handlers),
            'effective_level': test_logger.getEffectiveLevel()
        })

    # Log this status check
    logger.info("Logging status check performed", extra={
        'user': request.user.username if request.user.is_authenticated else 'anonymous',
        'logs_directory_exists': status_data['logs_exist'],
        'log_files_count': len(status_data['log_files']),
        'timestamp': datetime.now().isoformat()
    })

    return JsonResponse(status_data, json_dumps_params={'indent': 2})


# URL patterns for test views
from django.urls import path

test_urlpatterns = [
    path('test-dashboard/', test_logging_dashboard, name='test_dashboard'),
    path('test-create-shift/', test_create_shift, name='test_create_shift'),
    path('test-security/', test_security_logging, name='test_security'),
    path('test-api/', test_api_logging, name='test_api'),
    path('test-error/', test_error_logging, name='test_error'),
    path('test-performance/', test_performance_logging, name='test_performance'),
    path('test-workflow/', test_user_workflow, name='test_workflow'),
    path('test-status/', test_logging_status, name='test_status'),
]
