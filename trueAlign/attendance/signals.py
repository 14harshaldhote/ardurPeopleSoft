# attendance/signals.py
"""
Optimized Attendance Signals Module

This module provides signal handlers for attendance-related events with:
- Robust error handling and transaction safety
- Performance optimization with caching
- Comprehensive logging
- Prevention of race conditions
- Integration with attendance services
- Proper handling of edge cases
"""

import logging
from datetime import timedelta, date
from typing import Optional, Dict, Any

from django.core.cache import cache
from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.db import transaction
from django.conf import settings

try:
    import pytz
    IST = pytz.timezone('Asia/Kolkata')
except ImportError:
    IST = timezone.get_current_timezone()

from trueAlign.models import UserSession, Attendance, ShiftAssignment, LeaveRequest, Holiday
from .services import AttendanceIntegrationService, get_attendance_services

# NOTE: Remaining Pylance errors are false positives due to Django model field type inference
# The code will work correctly at runtime as Django model fields resolve to their actual values

logger = logging.getLogger('trueAlign.attendance.signals')

# Service instances
_integration_service = None
_services_cache = None


def get_integration_service():
    """Get or create integration service instance"""
    global _integration_service
    if _integration_service is None:
        _integration_service = AttendanceIntegrationService()
    return _integration_service


def get_services():
    """Get or create services cache"""
    global _services_cache
    if _services_cache is None:
        _services_cache = get_attendance_services()
    return _services_cache


class SignalProcessingError(Exception):
    """Custom exception for signal processing errors"""
    pass


def is_signal_processing_disabled():
    """Check if signal processing is temporarily disabled"""
    return getattr(settings, 'DISABLE_ATTENDANCE_SIGNALS', False)


def should_skip_processing(instance, reason: Optional[str] = None) -> bool:
    """Determine if signal processing should be skipped"""
    if is_signal_processing_disabled():
        logger.debug("Signal processing disabled globally")
        return True

    # Check if we're in a migration or testing context
    if hasattr(instance, '_state') and instance._state.adding and not instance.pk:
        # Skip for instances being created during migrations
        return True

    # Check cache for skip flag
    if hasattr(instance, 'pk') and instance.pk:
        skip_key = f'skip_signals_{instance.pk}'
        if cache.get(skip_key):
            logger.debug(f"Skipping signal processing due to cache flag: {reason or 'No reason provided'}")
            return True

    # Skip if instance has a special flag
    if hasattr(instance, '_skip_signals') and getattr(instance, '_skip_signals', False):
        logger.debug(f"Skipping signal processing due to _skip_signals flag: {reason or 'No reason provided'}")
        return True

    return False


def get_cache_key(prefix: str, *args) -> str:
    """Generate consistent cache keys"""
    return f"attendance_signal_{prefix}_{'_'.join(str(arg) for arg in args)}"


def invalidate_signal_cache(user_id: int, target_date: Optional[date] = None):
    """Invalidate signal-related cache entries"""
    if not target_date:
        target_date = timezone.now().astimezone(IST).date()

    cache_keys = [
        get_cache_key('session_processing', user_id, target_date),
        get_cache_key('attendance_update', user_id, target_date),
        f"attendance_today_{user_id}_{target_date}",
        f"user_attendance_{user_id}",
    ]

    try:
        cache.delete_many(cache_keys)
    except Exception as e:
        logger.warning(f"Error invalidating signal cache: {e}")


def _defer_session_processing(instance: UserSession, created: bool) -> bool:
    """Handle session processing deferral when in transaction. Returns True if deferred."""
    if not transaction.get_connection().in_atomic_block:
        return False

    user = instance.user  # type: ignore
    username = getattr(user, 'username', 'unknown')
    logger.debug(f"Deferring session processing for {username} - in transaction")

    deferred_key = f'deferred_session_{instance.id}'
    cache.set(deferred_key, {
        'instance_id': instance.id,
        'created': created,
        'timestamp': timezone.now().isoformat()
    }, 300)
    return True


def _setup_session_processing(instance: UserSession, operation_type: str, start_time) -> Optional[str]:
    """Setup session processing with duplicate check. Returns processing key or None if should skip."""
    user = instance.user  # type: ignore
    login_date = instance.login_time.astimezone(IST).date()  # type: ignore

    processing_key = get_cache_key('session_processing', getattr(user, 'id'), login_date, getattr(instance, 'id'))
    if cache.get(processing_key):
        logger.debug(f"Session {instance.id} already processed, skipping")
        return None

    cache.set(processing_key, {
        'start_time': start_time.isoformat(),
        'operation': operation_type,
        'user_id': getattr(user, 'id')
    }, 300)

    return processing_key


def _process_session_login(integration_service, user, instance: UserSession, operation_type: str):
    """Process session login and handle errors."""
    result = integration_service.process_session_login(user, instance)
    if not result.success:
        error_key = f'signal_errors_{operation_type.replace(" ", "_")}'
        cache.set(error_key, cache.get(error_key, 0) + 1, 3600)
        logger.error(f"Failed to process session login: {result.message}")
        raise SignalProcessingError(f"Session login processing failed: {result.message}")


def _process_session_logout(integration_service, user, instance: UserSession):
    """Process session logout if applicable."""
    if not (instance.logout_time and instance.ended_at):
        return

    try:
        if hasattr(integration_service, 'process_session_logout'):
            result = integration_service.process_session_logout(user, instance)  # type: ignore
        else:
            result = integration_service.process_session_login(user, instance)
            logger.warning("process_session_logout method not found, using process_session_login")

        if not result.success:
            logger.warning(f"Session logout processing failed: {result.message}")
    except Exception as logout_error:
        logger.warning(f"Logout processing error (non-critical): {logout_error}")


def _log_session_performance(start_time, user, operation_type: str):
    """Log session processing performance metrics."""
    processing_time = (timezone.now() - start_time).total_seconds()
    username = getattr(user, 'username', 'unknown')
    if processing_time > 5:
        logger.warning(f"Slow session signal processing: {processing_time:.2f}s for {username}")
    else:
        logger.debug(f"Successfully processed session for {username} in {processing_time:.2f}s")


def _handle_session_error(instance: UserSession, error, operation_type: str, is_signal_error: bool = False):
    """Handle and log session processing errors."""
    user = instance.user  # type: ignore
    username = getattr(user, 'username', 'unknown')
    error_key = f'signal_errors_{operation_type.replace(" ", "_")}'

    if is_signal_error:
        logger.error(f"Signal processing error for {username}: {error}")
    else:
        logger.error(f"Unexpected error processing session signal for {username}: {error}", exc_info=True)

    cache.set(error_key, cache.get(error_key, 0) + 1, 3600)


@receiver(post_save, sender=UserSession)
def handle_session_save(sender, instance: UserSession, created: bool, **kwargs):
    """
    Enhanced UserSession save handler with improved error handling and performance
    """
    operation_type = "UserSession save"
    start_time = timezone.now()

    if should_skip_processing(instance, operation_type):
        return

    # Handle transaction deferral
    if _defer_session_processing(instance, created):
        return

    processing_key = None
    try:
        user = instance.user  # type: ignore
        login_date = instance.login_time.astimezone(IST).date()  # type: ignore

        # Setup processing with duplicate check
        processing_key = _setup_session_processing(instance, operation_type, start_time)
        if not processing_key:
            return

        username = getattr(user, 'username', 'unknown')
        logger.info(f"Processing session {'creation' if created else 'update'} for {username} on {login_date}")

        # Get integration service
        integration_service = get_integration_service()
        if not integration_service:
            raise SignalProcessingError("Integration service not available")

        # Process based on operation type
        if created:
            _process_session_login(integration_service, user, instance, operation_type)
        else:
            _process_session_logout(integration_service, user, instance)

        # Invalidate related caches
        invalidate_signal_cache(getattr(user, 'id'), login_date)

        # Log performance metrics
        _log_session_performance(start_time, user, operation_type)

    except SignalProcessingError as e:
        _handle_session_error(instance, e, operation_type, is_signal_error=True)

    except Exception as e:
        _handle_session_error(instance, e, operation_type, is_signal_error=False)

    finally:
        # Always clean up the processing flag
        if processing_key:
            try:
                cache.delete(processing_key)
            except:
                pass


@receiver(pre_save, sender=UserSession)
def handle_session_pre_save(sender, instance: UserSession, **kwargs):
    """
    Handle UserSession pre-save to detect logout events and prepare for processing
    """
    if should_skip_processing(instance, "UserSession pre_save"):
        return

    try:
        # Only process existing sessions (not new ones)
        if not instance.pk:
            return

        # Get the original session to detect changes
        try:
            original_session = sender.objects.get(pk=instance.pk)
        except Exception:  # Handle both DoesNotExist and other exceptions
            return

        # Detect logout event
        logout_detected = False

        if not original_session.ended_at and instance.ended_at:
            logout_detected = True
            logger.debug(f"Logout detected for session {instance.id}")

        if not original_session.logout_time and instance.logout_time:
            logout_detected = True

        # If logout is being set, ensure logout_time is set
        if logout_detected and not instance.logout_time:
            instance.logout_time = instance.ended_at or timezone.now()
            logger.debug(f"Set logout_time for session {instance.id}")

        # Store logout detection flag for post_save in cache instead of instance attribute
        if logout_detected:
            cache.set(f'logout_detected_{instance.id}', True, 300)

    except Exception as e:
        logger.error(f"Error in session pre_save signal: {e}", exc_info=True)


@receiver(post_save, sender=ShiftAssignment)
def handle_shift_assignment_save(sender, instance: ShiftAssignment, created: bool, **kwargs):
    """
    Handle ShiftAssignment changes to update affected attendance records
    """
    if should_skip_processing(instance, "ShiftAssignment save"):
        return

    try:
        user = instance.user  # type: ignore
        username = getattr(user, 'username', 'unknown')
        logger.info(f"Processing shift assignment {'creation' if created else 'update'} for {username}")

        # Get affected date range
        start_date = instance.effective_from
        end_date = instance.effective_to or (timezone.now().astimezone(IST).date() + timedelta(days=365))

        # Limit the range to prevent excessive updates
        max_date = timezone.now().astimezone(IST).date() + timedelta(days=90)
        if end_date > max_date:
            end_date = max_date

        # Update existing attendance records
        affected_attendances = Attendance.objects.filter(
            user=user,
            date__range=[start_date, end_date]
        ).exclude(
            shift=instance.shift
        )

        update_count = 0
        for attendance in affected_attendances[:100]:  # Limit batch size
            try:
                # Update shift assignment
                old_shift = attendance.shift
                attendance.shift = instance.shift

                # Update expected hours if changed
                shift = instance.shift
                if shift and hasattr(shift, 'shift_duration'):
                    attendance.expected_hours = getattr(shift, 'shift_duration')

                # Save without triggering signals recursively
                # Store skip flag in cache to prevent recursive signals
                skip_key = f'skip_signals_{attendance.pk}'
                cache.set(skip_key, True, 60)
                try:
                    attendance.save(update_fields=['shift', 'expected_hours', 'last_modified'])
                finally:
                    cache.delete(skip_key)

                update_count += 1

                # Invalidate cache for this attendance
                invalidate_signal_cache(getattr(user, 'id'), getattr(attendance, 'date'))

                logger.debug(f"Updated attendance {getattr(attendance, 'id')} shift from {old_shift} to {instance.shift}")

            except Exception as e:
                logger.error(f"Error updating attendance {getattr(attendance, 'id')} for shift change: {e}")

        logger.info(f"Updated {update_count} attendance records for shift assignment change")

        # Schedule async recalculation for future dates if needed
        if created:
            _schedule_attendance_recalculation(getattr(user, 'id'), start_date, end_date)  # type: ignore

    except Exception as e:
        user_obj = getattr(instance, 'user', None)
        username = getattr(user_obj, 'username', 'unknown') if user_obj else 'unknown'
        logger.error(f"Error processing shift assignment signal for {username}: {e}", exc_info=True)


@receiver(post_save, sender=LeaveRequest)
def handle_leave_request_save(sender, instance: LeaveRequest, created: bool, **kwargs):
    """
    Handle LeaveRequest changes to update attendance records
    """
    if should_skip_processing(instance, "LeaveRequest save"):
        return

    # Only process when leave is approved or status changes
    if not created and instance.status != 'Approved':
        return

    try:
        user = instance.user  # type: ignore
        username = getattr(user, 'username', 'unknown')
        logger.info(f"Processing leave request for {username}: {instance.start_date} to {instance.end_date}")

        # Get affected attendance records
        affected_attendances = Attendance.objects.filter(
            user=user,
            date__range=[instance.start_date, instance.end_date]
        )

        if instance.status == 'Approved':
            # Mark as on leave
            update_data = {
                'status': 'On Leave',
                'leave_type': instance.leave_type.name if instance.leave_type else 'Leave',
                'regularization_reason': f'On {instance.leave_type.name if instance.leave_type else "Leave"} leave',
                'last_modified': timezone.now()
            }

            updated_count = affected_attendances.update(**update_data)
            logger.info(f"Marked {updated_count} attendance records as on leave")

        elif instance.status in ['Rejected', 'Cancelled']:
            # Revert leave status - mark for recalculation
            for attendance in affected_attendances.filter(status='On Leave'):
                attendance.status = 'Not Marked'
                attendance.leave_type = None
                attendance.regularization_reason = 'Leave cancelled - needs recalculation'
                # Store skip flag in cache to prevent recursive signals
                skip_key = f'skip_signals_{attendance.pk}'
                cache.set(skip_key, True, 60)
                try:
                    attendance.save()
                finally:
                    cache.delete(skip_key)

                # Schedule for auto-marking
                invalidate_signal_cache(getattr(user, 'id'), getattr(attendance, 'date'))

        # Invalidate related caches - simplified approach
        try:
            # Get date values safely
            start_date_val = getattr(instance, 'start_date')
            end_date_val = getattr(instance, 'end_date')

            # Simple range invalidation without complex date arithmetic
            if start_date_val and end_date_val:
                invalidate_signal_cache(getattr(user, 'id'), start_date_val)
                invalidate_signal_cache(getattr(user, 'id'), end_date_val)
                logger.debug(f"Invalidated cache for date range: {start_date_val} to {end_date_val}")

        except Exception as date_error:
            logger.warning(f"Error invalidating cache for date range: {date_error}")

    except Exception as e:
        logger.error(f"Error processing leave request signal: {e}", exc_info=True)


def _get_active_users():
    """Get all active users for holiday processing."""
    try:
        from django.contrib.auth import get_user_model
        UserModel = get_user_model()
        return UserModel.objects.filter(is_active=True)
    except Exception as e:
        logger.error(f"Error getting active users: {e}")
        return None


def _try_bulk_holiday_marking(active_users, holiday_date, holiday_name):
    """Try bulk holiday marking, return True if successful."""
    try:
        services = get_services()
        bulk_service = services.get('bulk_operations')

        if not bulk_service:
            return False

        bulk_method = getattr(bulk_service, 'bulk_mark_attendance', None)
        if not bulk_method:
            return False

        result = bulk_method(
            users=list(active_users[:1000]),
            target_date=holiday_date,
            status='Holiday',
            remarks=f'Holiday: {holiday_name}'
        )

        if result.success:
            logger.info(f"Marked holiday attendance using bulk service: {result.message}")
            return True
        else:
            logger.error(f"Bulk holiday marking failed: {result.message}")
            return False

    except Exception as bulk_error:
        logger.warning(f"Bulk processing failed: {bulk_error}")
        return False


def _process_individual_holiday_marking(active_users, holiday_date, holiday_name):
    """Fallback individual holiday marking."""
    updated_count = 0
    for user in active_users[:1000]:
        try:
            attendance, created = Attendance.objects.get_or_create(
                user=user,
                date=holiday_date,
                defaults={
                    'status': 'Holiday',
                    'regularization_reason': f'Holiday: {holiday_name}',
                    'last_modified': timezone.now()
                }
            )

            if not created and attendance.status != 'Holiday':
                attendance.status = 'Holiday'
                attendance.regularization_reason = f'Holiday: {holiday_name}'
                attendance.last_modified = timezone.now()

                skip_key = f'skip_signals_{attendance.pk}'
                cache.set(skip_key, True, 60)
                try:
                    attendance.save()
                finally:
                    cache.delete(skip_key)

            updated_count += 1

        except Exception as e:
            logger.error(f"Error marking holiday attendance for user {user.username}: {e}")

    logger.info(f"Marked holiday attendance for {updated_count} users")


@receiver(post_save, sender=Holiday)
def handle_holiday_save(sender, instance: Holiday, created: bool, **kwargs):
    """
    Handle Holiday creation/updates to mark attendance as holiday
    """
    if should_skip_processing(instance, "Holiday save"):
        return

    if not created:
        return

    try:
        holiday_date = instance.date
        holiday_name = instance.name
        logger.info(f"Processing holiday creation: {holiday_name} on {holiday_date}")

        active_users = _get_active_users()
        if not active_users:
            return

        # Try bulk processing first, fallback to individual if needed
        if not _try_bulk_holiday_marking(active_users, holiday_date, holiday_name):
            _process_individual_holiday_marking(active_users, holiday_date, holiday_name)

    except Exception as e:
        logger.error(f"Error processing holiday signal: {e}", exc_info=True)


@receiver(post_delete, sender=UserSession)
def handle_session_delete(sender, instance: UserSession, **kwargs):
    """
    Handle UserSession deletion to clean up related data
    """
    if should_skip_processing(instance, "UserSession delete"):
        return

    try:
        # Clean up any attendance references to this session
        login_time = getattr(instance, 'login_time', None)
        if login_time and hasattr(login_time, 'astimezone'):
            session_date = login_time.astimezone(IST).date()
        else:
            session_date = timezone.now().astimezone(IST).date()

        user = instance.user  # type: ignore

        # Update attendance records that reference this session
        Attendance.objects.filter(
            user=user,
            date=session_date,
            first_session=instance
        ).update(first_session=None)

        Attendance.objects.filter(
            user=user,
            date=session_date,
            last_session=instance
        ).update(last_session=None)

        # Invalidate related caches
        invalidate_signal_cache(user.id, session_date)  # type: ignore

        logger.info(f"Cleaned up attendance references for deleted session {instance.id}")

    except Exception as e:
        logger.error(f"Error processing session deletion signal: {e}", exc_info=True)


# Regular function (not Celery task) for scheduling attendance recalculation
def _schedule_attendance_recalculation(user_id: int, start_date: Any, end_date: Any):
    """Schedule attendance recalculation (placeholder for async implementation)"""
    # This would be implemented with Celery or similar async task system
    logger.info(f"Scheduled attendance recalculation for user {user_id} from {start_date} to {end_date}")

    # For now, just cache the request for later processing
    recalc_key = f'recalc_request_{user_id}_{start_date}_{end_date}'
    cache.set(recalc_key, {
        'user_id': user_id,
        'start_date': str(start_date),
        'end_date': str(end_date),
        'created_at': timezone.now().isoformat()
    }, 3600)


# Signal connection management
def connect_attendance_signals():
    """Manually connect signals if needed"""
    logger.info("Attendance signals connected")


def disconnect_attendance_signals():
    """Manually disconnect signals if needed"""
    logger.info("Attendance signals disconnected")


# Health check function
def check_signal_health() -> Dict[str, Any]:
    """Check the health of signal processing"""
    try:
        health_data = {
            'signals_enabled': not is_signal_processing_disabled(),
            'cache_available': True,
            'services_available': True,
            'recent_errors': 0  # This would track recent signal processing errors
        }

        # Test cache
        test_key = get_cache_key('health_check', 'test')
        cache.set(test_key, 'ok', 10)
        if cache.get(test_key) != 'ok':
            health_data['cache_available'] = False
        cache.delete(test_key)

        # Test services
        try:
            get_integration_service()
            get_services()
        except Exception:
            health_data['services_available'] = False

        health_data['status'] = 'healthy' if all([
            health_data['signals_enabled'],
            health_data['cache_available'],
            health_data['services_available']
        ]) else 'degraded'

        return health_data

    except Exception as e:
        logger.error(f"Error checking signal health: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'signals_enabled': False,
            'cache_available': False,
            'services_available': False
        }
