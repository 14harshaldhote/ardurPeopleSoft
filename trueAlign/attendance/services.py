# attendance/services.py
"""
Optimized Attendance Services Module

This module provides comprehensive services for attendance management with:
- Clear separation of concerns
- Performance optimization
- Consistent error handling
- Comprehensive logging
- Caching support
- Transaction safety
"""

import logging
from datetime import timedelta, date
from decimal import Decimal
from typing import List, Dict, Optional, Any, TYPE_CHECKING
from collections import defaultdict

from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Q, Count, Avg

import pytz



from trueAlign.models import (
    Attendance, UserSession, Holiday, ShiftAssignment,
    LeaveRequest
)
from .config import PRESENT_STATUSES

User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

if TYPE_CHECKING:
    from django.contrib.auth.models import User as UserType
else:
    UserType = User

logger = logging.getLogger('trueAlign.attendance.services')


class ServiceResult:
    """Standard result class for service operations"""

    def __init__(self, success: bool = True, message: str = '', data: Any = None, errors: Optional[List[str]] = None):
        self.success = success
        self.message = message
        self.data = data
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'message': self.message,
            'data': self.data,
            'errors': self.errors
        }


class BaseAttendanceService:
    """Base service class with common functionality"""

    def __init__(self):
        self.ist = IST
        self.today = timezone.now().astimezone(self.ist).date()
        self.current_time = timezone.now().astimezone(self.ist)

    def _log_operation(self, operation: str, user: Optional[str] = None, details: Optional[str] = None):
        """Log service operations"""
        log_msg = f"[{operation}]"
        if user:
            log_msg += f" User: {user}"
        if details:
            log_msg += f" - {details}"
        logger.info(log_msg)

    def _handle_exception(self, operation: str, error: Exception, user: Optional[str] = None) -> ServiceResult:
        """Handle exceptions consistently"""
        error_msg = f"Error in {operation}: {str(error)}"
        if user:
            error_msg = f"Error in {operation} for {user}: {str(error)}"

        logger.error(error_msg, exc_info=True)
        return ServiceResult(success=False, message="An error occurred", errors=[error_msg])

    def _get_cache_key(self, *args) -> str:
        """Generate cache key from arguments"""
        return "_".join(str(arg) for arg in args)

    def _invalidate_user_cache(self, user_id: int, target_date: Optional[date] = None):
        """Invalidate user-specific caches"""
        if not target_date:
            target_date = self.today

        cache_keys = [
            f"attendance_today_{user_id}_{target_date}",
            f"user_attendance_{user_id}_{target_date}",
            f"user_monthly_summary_{user_id}_{target_date.year}_{target_date.month}"
        ]
        cache.delete_many(cache_keys)


class AttendanceAutoMarkingService(BaseAttendanceService):
    """
    Service for automatic attendance marking based on sessions, shifts, and business rules
    """

    def run_auto_marking(self, target_date: Optional[date] = None) -> ServiceResult:
        """
        OPTIMIZED automatic attendance marking with incremental processing
        
        Features:
        - Incremental processing (only changed records since last run)
        - Uses processing locks to prevent concurrent modifications
        - Batch processing with per-record error handling
        - Cache-aware with last run time tracking
        """
        if not target_date:
            target_date = self.today

        self._log_operation("AUTO_MARKING_START", details=f"Date: {target_date}")
        
        # Check for last run time (for incremental processing)
        last_run_key = f'last_auto_marking_{target_date}'
        last_run = cache.get(last_run_key)
        
        try:
            results = {
                'date': str(target_date),
                'created': 0,
                'updated': 0,
                'processed': 0,
                'calculated': 0,
                'skipped': 0,
                'errors': [],
                'processing_mode': 'incremental' if last_run else 'full'
            }

            # Step 1: Create missing attendance records for all active users
            created_count = self._create_missing_records(target_date)
            results['created'] = created_count

            # Step 2: INCREMENTAL - Get records to process
            if last_run:
                # Only process records modified since last run
                records_to_process = Attendance.objects.filter(
                    date=target_date,
                    last_modified__gte=last_run
                ).select_related('user', 'shift', 'first_session', 'last_session')
                
                logger.info(f"Incremental processing: {records_to_process.count()} modified records")
            else:
                # Full processing - First run of the day
                records_to_process = Attendance.objects.filter(
                    date=target_date
                ).select_related('user', 'shift', 'first_session', 'last_session')
                
                logger.info(f"Full processing: {records_to_process.count()} total records")

            # Step 3: Process records in batches with locking
            update_count, process_count, skip_count = self._process_records_batch(
                records_to_process, target_date
            )
            results['updated'] = update_count
            results['processed'] = process_count
            results['skipped'] = skip_count

            # Step 4: Handle real-time updates for current day
            if target_date == self.today:
                self._update_real_time_attendance()

            # Update last run time for next incremental processing
            cache.set(last_run_key, timezone.now(), 86400)  # 24 hours

            self._log_operation("AUTO_MARKING_COMPLETE",
                              details=f"Mode: {results['processing_mode']}, Created: {created_count}, "
                                     f"Updated: {update_count}, Processed: {process_count}, "
                                     f"Skipped: {skip_count}")

            return ServiceResult(
                success=True,
                message=f"Optimized auto marking completed for {target_date}",
                data=results
            )

        except Exception as e:
            return self._handle_exception("AUTO_MARKING", e)

    def _create_missing_records(self, target_date: date) -> int:
        """Create attendance records for users without existing records"""
        try:
            # Get all active users without attendance records for the date
            users_with_attendance = Attendance.objects.filter(date=target_date).values_list('user_id', flat=True)
            users_without_attendance = User.objects.filter(
                is_active=True
            ).exclude(id__in=users_with_attendance)

            if not users_without_attendance.exists():
                return 0

            created_records = []
            for user in users_without_attendance:
                try:
                    defaults = self._get_attendance_defaults(user, target_date)
                    record = Attendance(user=user, date=target_date, **defaults)
                    created_records.append(record)

                except Exception as e:
                    logger.error(f"Error preparing attendance for {user.username}: {e}")

            if created_records:
                Attendance.objects.bulk_create(created_records, batch_size=100)
                self._log_operation("CREATED_MISSING_RECORDS", details=f"Count: {len(created_records)}")

            return len(created_records)
        except Exception as e:
            logger.error(f"Error creating missing records: {e}")
            return 0

    def _get_attendance_defaults(self, user: 'UserType', target_date: date) -> Dict[str, Any]:
        """Get default attendance values based on business rules"""
        
        # FIX #14: CHECK FOR EXISTING SESSIONS FIRST!
        existing_sessions = UserSession.objects.filter(
            user=user,
            login_time__date=target_date
        )
        
        if existing_sessions.exists():
            # User has sessions, create with present status and session data
            first_session = existing_sessions.order_by('login_time').first()
            defaults: Dict[str, Any] = {
                'status': 'Present',
                'clock_in_time': first_session.login_time,
                'first_session': first_session,
                'regularization_reason': 'Auto-created from existing session'
            }
            logger.info(f"Creating attendance with session data for {user.username} on {target_date}")
            return defaults
        
        # No sessions, continue with standard defaults
        defaults: Dict[str, Any] = {
            'status': 'Not Marked',
            'regularization_reason': 'Auto-created attendance record'
        }

        # Check for leave
        if self._is_user_on_leave(user, target_date):
            leave_request = LeaveRequest.objects.filter(
                user=user,
                status='Approved',
                start_date__lte=target_date,
                end_date__gte=target_date
            ).select_related('leave_type').first()

            leave_update: Dict[str, Any] = {
                'status': 'On Leave',
                'leave_type': leave_request.leave_type.name if leave_request else 'Leave',
                'regularization_reason': f'On {leave_request.leave_type.name} leave' if leave_request else 'On Leave'
            }
            defaults.update(leave_update)
            return defaults

        # Check for holiday
        if self._is_holiday(target_date):
            try:
                holiday = Holiday.objects.get(date=target_date)
                holiday_update: Dict[str, Any] = {
                    'status': 'Holiday',
                    'is_holiday': True,
                    'holiday_name': str(holiday.name),
                    'regularization_reason': f'Holiday: {holiday.name}'
                }
                defaults.update(holiday_update)
            except Exception:  # Handle DoesNotExist safely
                holiday_update: Dict[str, Any] = {
                    'status': 'Holiday',
                    'is_holiday': True,
                    'holiday_name': 'Holiday',
                    'regularization_reason': 'Holiday'
                }
                defaults.update(holiday_update)
            return defaults

        # Check for weekend
        if self._is_weekend(user, target_date):
            weekend_update: Dict[str, Any] = {
                'status': 'Weekend',
                'is_weekend': True,
                'regularization_reason': 'Weekend'
            }
            defaults.update(weekend_update)
            return defaults

        # Set shift information
        try:
            shift = ShiftAssignment.objects.filter(
                user=user,
                start_date__lte=target_date,
                end_date__gte=target_date
            ).select_related('shift').first()

            if shift and shift.shift:
                # FIX #8: Use actual shift duration instead of hardcoded value
                expected_hrs = shift.shift.shift_duration if hasattr(shift.shift, 'shift_duration') else Decimal('8.0')
                shift_update: Dict[str, Any] = {
                    'shift': shift.shift,
                    'expected_hours': expected_hrs
                }
                defaults.update(shift_update)
                logger.debug(f"Set expected_hours to {expected_hrs} from shift")
        except Exception as e:
            logger.warning(f"Could not set shift for {user.username}: {e}")

        return defaults

    def _process_records_batch(self, records_queryset, target_date: date) -> tuple:
        """
        Process attendance records in batches with locking mechanism
        
        Returns: (updated_count, processed_count, skipped_count)
        """
        updated_count = 0
        processed_count = 0
        skipped_count = 0
        batch_size = 100  # Process 100 records at a time
        
        # Convert queryset to list for batching
        total_records = records_queryset.count()
        
        for batch_start in range(0, total_records, batch_size):
            batch = list(records_queryset[batch_start:batch_start + batch_size])
            
            for attendance in batch:
                try:
                    # Acquire processing lock
                    if not attendance.acquire_processing_lock(lock_duration_minutes=5):
                        # Already being processed, skip
                        skipped_count += 1
                        logger.debug(f"Skipping {attendance.id} - already being processed")
                        continue
                    
                    try:
                        # Process the attendance record
                        original_status = attendance.status
                        
                        # Initialize defaults if needed
                        if attendance.status in ['Not Marked', 'Yet to Clock In']:
                            attendance.initialize_defaults()
                        
                        # Calculate all fields (hours, status, etc.)
                        attendance.calculate_all_fields()
                        
                        # Save with skip_version_check to avoid conflicts
                        attendance.save(skip_version_check=True)
                        
                        if attendance.status != original_status:
                            updated_count += 1
                        processed_count += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing attendance {attendance.id}: {e}")
                    finally:
                        # Always release lock
                        attendance.release_processing_lock()
                        
                except Exception as e:
                    logger.error(f"Error in batch processing for record {attendance.id if hasattr(attendance, 'id') else 'unknown'}: {e}")
                    skipped_count += 1
        
        logger.info(f"Batch processing: Updated={updated_count}, Processed={processed_count}, Skipped={skipped_count}")
        return updated_count, processed_count, skipped_count

    def _update_with_sessions(self, target_date: date) -> int:
        """Update attendance records with session data"""
        sessions_for_date = UserSession.objects.filter(
            login_time__date=target_date
        ).select_related('user').order_by('user_id', 'login_time')

        if not sessions_for_date.exists():
            return 0

        updated_count = 0

        # Group sessions by user
        user_sessions = defaultdict(list)
        for session in sessions_for_date:
            user_sessions[session.user.id].append(session)

        # Update attendance for each user
        for user_id, sessions in user_sessions.items():
            try:
                attendance = Attendance.objects.get(user_id=user_id, date=target_date)

                if self._update_attendance_with_sessions(attendance, sessions):
                    updated_count += 1

            except Attendance.DoesNotExist:
                logger.warning(f"No attendance record found for user {user_id} on {target_date}")
            except Exception as e:
                logger.error(f"Error updating attendance with sessions for user {user_id}: {e}")

        return updated_count

    def _update_attendance_with_sessions(self, attendance: Attendance, sessions: List[UserSession]) -> bool:
        """Enhanced session-based attendance update with real-time accuracy"""
        if not sessions or attendance.status in ['On Leave', 'Holiday', 'Weekend']:
            return False

        try:
            # Sort sessions by login time for accurate processing
            sessions = sorted(sessions, key=lambda s: s.login_time)

            # Find first login and last logout
            first_session = sessions[0]
            last_session = sessions[-1]

            # Preserve weekend/holiday flags if they were set
            original_is_weekend = attendance.is_weekend
            original_is_holiday = attendance.is_holiday
            original_holiday_name = attendance.holiday_name

            # Get the latest logout time from all sessions
            latest_logout = None
            for session in sessions:
                if session.logout_time:
                    if not latest_logout or session.logout_time > latest_logout:
                        latest_logout = session.logout_time

            updated = False

            # Update clock-in time (earliest login)
            if not attendance.clock_in_time or first_session.login_time < attendance.clock_in_time:
                attendance.clock_in_time = first_session.login_time
                attendance.first_session = first_session
                updated = True

            # Update clock-out time (latest logout)
            if latest_logout:
                if not attendance.clock_out_time or latest_logout > attendance.clock_out_time:
                    attendance.clock_out_time = latest_logout
                    attendance.last_session = last_session
                    updated = True

            # Update session statistics
            attendance.total_sessions = len(sessions)

            # Calculate total session time
            total_session_time = timedelta(0)
            for session in sessions:
                if session.logout_time:
                    total_session_time += session.logout_time - session.login_time

            # FIX #3: Populate IP address from first session
            if first_session and hasattr(first_session, 'ip_address') and first_session.ip_address:
                if not attendance.ip_address:  # Only set if not already set
                    attendance.ip_address = first_session.ip_address
                    updated = True
                    logger.debug(f"Populated IP address: {attendance.ip_address}")

            # FIX #4: Populate device information from first session
            if first_session and not attendance.device_info:
                device_data = {}
                
                # Safely collect device information
                if hasattr(first_session, 'user_agent') and first_session.user_agent:
                    device_data['user_agent'] = first_session.user_agent
                if hasattr(first_session, 'browser') and first_session.browser:
                    device_data['browser'] = first_session.browser
                if hasattr(first_session, 'os') and first_session.os:
                    device_data['os'] = first_session.os
                if hasattr(first_session, 'device_type') and first_session.device_type:
                    device_data['device_type'] = first_session.device_type
                if hasattr(first_session, 'screen_resolution') and first_session.screen_resolution:
                    device_data['screen_resolution'] = first_session.screen_resolution
                
                if device_data:  # Only set if we have at least some data
                    attendance.device_info = device_data
                    updated = True
                    logger.debug(f"Populated device info: {device_data.get('browser', 'N/A')} on {device_data.get('os', 'N/A')}")

            # FIX #5: Calculate total idle time from all sessions
            total_idle = timedelta(0)
            for session in sessions:
                # Try both possible field names
                session_idle = getattr(session, 'total_idle_time', None) or getattr(session, 'idle_time', None)
                if session_idle:
                    total_idle += session_idle
            
            if total_idle > timedelta(0):
                attendance.idle_time = total_idle
                updated = True
                logger.debug(f"Populated idle time: {total_idle}")

            # FIX #1: Set location from most recent session - CORRECTED FIELD NAME
            if sessions:
                # FIXED: Use 'location_type' instead of 'location'
                last_session_ref = sessions[-1]
                if hasattr(last_session_ref, 'location_type') and last_session_ref.location_type:
                    # Use title() instead of capitalize() to handle multi-word locations
                    attendance.location = last_session_ref.location_type.title()
                    updated = True
                    logger.debug(f"Set location to: {attendance.location}")
                elif hasattr(last_session_ref, 'location_city') and last_session_ref.location_city:
                    # If location_type not set but has city, consider it Remote
                    attendance.location = 'Remote'
                    updated = True
                else:
                    attendance.location = 'Office'

            # Auto-determine status based on sessions
            if attendance.status in ['Not Marked', 'Yet to Clock In']:
                attendance.status = self._determine_status_from_sessions(attendance, sessions)
                updated = True

            # Restore weekend/holiday flags if they were set
            if original_is_weekend:
                attendance.is_weekend = True
            if original_is_holiday:
                attendance.is_holiday = True
                if original_holiday_name:
                    attendance.holiday_name = original_holiday_name

            if updated:
                attendance.save()
                self._invalidate_user_cache(attendance.user.pk, attendance.date)

            return updated

        except Exception as e:
            logger.error(f"Error updating attendance {attendance.id} with sessions: {e}")
            return False

    def _process_pending_statuses(self, target_date: date) -> int:
        """Process pending attendance statuses"""
        try:
            pending_records = Attendance.objects.filter(
                date=target_date,
                status='Yet to Clock In'
            )

            processed_count = 0
            for record in pending_records:
                if self._should_mark_absent(record):
                    record.status = 'Absent'
                    record.save()
                    processed_count += 1

            return processed_count
        except Exception as e:
            logger.error(f"Error processing pending statuses: {e}")
            return 0

    def _recalculate_all_statuses(self, target_date: date) -> int:
        """Enhanced status recalculation with improved business logic"""
        try:
            records = Attendance.objects.filter(date=target_date).select_related('user', 'shift')
            calculated_count = 0

            for record in records:
                if self._calculate_attendance_status(record):
                    calculated_count += 1

            self._log_operation("STATUS_RECALCULATION", details=f"Calculated {calculated_count} records")
            return calculated_count
        except Exception as e:
            logger.error(f"Error recalculating statuses: {e}")
            return 0

    def _update_real_time_attendance(self):
        """Update attendance for currently active sessions in real-time"""
        try:
            # Get all active sessions for today
            active_sessions = UserSession.objects.filter(
                is_active=True,
                login_time__date=self.today
            ).select_related('user')

            for session in active_sessions:
                try:
                    attendance, created = Attendance.objects.get_or_create(
                        user=session.user,
                        date=self.today,
                        defaults={
                            'status': 'Present',
                            'regularization_reason': 'Auto-created from active session'
                        }
                    )

                    # Update with current session data
                    if not attendance.clock_in_time or session.login_time < attendance.clock_in_time:
                        attendance.clock_in_time = session.login_time
                        attendance.status = 'Present'
                        attendance.save()

                except Exception as e:
                    logger.error(f"Error updating real-time attendance for {session.user.username}: {e}")

        except Exception as e:
            logger.error(f"Error in real-time attendance update: {e}")

    def _is_user_on_leave(self, user: 'UserType', target_date: date) -> bool:
        """Check if user is on approved leave"""
        return LeaveRequest.objects.filter(
            user=user,
            status='Approved',
            start_date__lte=target_date,
            end_date__gte=target_date
        ).exists()

    def _is_holiday(self, target_date: date) -> bool:
        """Check if date is a holiday"""
        return Holiday.objects.filter(date=target_date).exists()

    def _is_weekend(self, user: 'UserType', target_date: date) -> bool:
        """Check if date is weekend for user"""
        return target_date.weekday() >= 5  # Saturday (5) or Sunday (6)

    def _should_mark_absent(self, attendance: Attendance) -> bool:
        """Determine if attendance should be marked as absent"""
        # If it's past business hours and no clock-in, mark as absent
        current_time = timezone.now().astimezone(self.ist)
        if attendance.date < current_time.date():
            return not attendance.clock_in_time
        return False

    def _calculate_attendance_status(self, attendance: Attendance) -> bool:
        """Enhanced attendance status calculation with comprehensive business rules"""
        try:
            # Skip if already on fixed statuses
            if attendance.status in ['On Leave', 'Holiday', 'Weekend']:
                return False

            original_status = attendance.status

            # Determine status based on session data
            if not attendance.clock_in_time:
                # No session found - determine if should be absent
                if self._should_mark_absent(attendance):
                    attendance.status = 'Absent'
                else:
                    attendance.status = 'Yet to Clock In'
            else:
                # Has session - determine presence status
                attendance.status = self._determine_presence_status(attendance)

            # Calculate time-related fields
            self._calculate_time_metrics(attendance)

            # Save if status changed
            if attendance.status != original_status or attendance.pk is None:
                attendance.save()
                return True

            return False

        except Exception as e:
            logger.error(f"Error calculating status for attendance {attendance.id}: {e}")
            return False

    def _determine_status_from_sessions(self, attendance: Attendance, sessions: List[UserSession]) -> str:
        """Determine attendance status from session data - FIX #6: Calculate late_minutes BEFORE determining status"""
        if not sessions:
            return 'Absent' if self._should_mark_absent(attendance) else 'Yet to Clock In'

        # Has sessions, determine presence status
        first_session = min(sessions, key=lambda s: s.login_time)

        # Check if late based on shift - CALCULATE late_minutes FIRST!
        if attendance.shift:
            shift_start_time = attendance.shift.start_time
            login_time = first_session.login_time.astimezone(self.ist).time()

            # Apply grace period
            grace_period = getattr(attendance.shift, 'grace_period', timedelta(minutes=10))
            grace_minutes = int(grace_period.total_seconds() / 60)

            shift_start_minutes = shift_start_time.hour * 60 + shift_start_time.minute
            login_minutes = login_time.hour * 60 + login_time.minute

            # FIX #6: Calculate late_minutes BEFORE returning status
            if login_minutes > (shift_start_minutes + grace_minutes):
                attendance.late_minutes = login_minutes - shift_start_minutes
                logger.debug(f"User late by {attendance.late_minutes} minutes")
                return 'Present & Late'
            else:
                attendance.late_minutes = 0  # Not late

        # Not late or no shift, just present
        attendance.late_minutes = 0
        return 'Present'

    def _determine_presence_status(self, attendance: Attendance) -> str:
        """Determine presence status based on clock-in time and shift"""
        if not attendance.clock_in_time:
            return 'Absent'

        # Check against shift timing if available
        if attendance.shift:
            clock_in_time = attendance.clock_in_time.astimezone(self.ist).time()
            shift_start = attendance.shift.start_time

            # Calculate grace period
            grace_period = getattr(attendance.shift, 'grace_period', timedelta(minutes=10))
            grace_minutes = int(grace_period.total_seconds() / 60)

            shift_start_minutes = shift_start.hour * 60 + shift_start.minute
            clock_in_minutes = clock_in_time.hour * 60 + clock_in_time.minute

            if clock_in_minutes > (shift_start_minutes + grace_minutes):
                # Calculate late minutes
                attendance.late_minutes = clock_in_minutes - shift_start_minutes
                return 'Present & Late'

        return 'Present'

    def _calculate_time_metrics(self, attendance: Attendance):
        """Calculate time-related metrics for attendance"""
        try:
            # Calculate total hours if both times are available
            if attendance.clock_in_time and attendance.clock_out_time:
                duration = attendance.clock_out_time - attendance.clock_in_time
                total_hours = duration.total_seconds() / 3600
                attendance.total_hours = Decimal(str(round(total_hours, 2)))

                # FIX #2: Calculate overtime if applicable - CORRECTED FIELD NAME
                if attendance.shift:
                    # FIXED: Use 'shift_duration' instead of 'duration' (it's already in hours as Decimal)
                    if hasattr(attendance.shift, 'shift_duration') and attendance.shift.shift_duration:
                        shift_hours = float(attendance.shift.shift_duration)
                        if total_hours > shift_hours:
                            attendance.overtime_hours = Decimal(str(round(total_hours - shift_hours, 2)))
                            logger.debug(f"Calculated overtime: {attendance.overtime_hours} hours")
                        else:
                            attendance.overtime_hours = Decimal('0.00')
                    else:
                        # Fallback to default 8-hour shift if shift_duration not available
                        default_shift_hours = 8.0
                        if total_hours > default_shift_hours:
                            attendance.overtime_hours = Decimal(str(round(total_hours - default_shift_hours, 2)))
                        else:
                            attendance.overtime_hours = Decimal('0.00')

        except Exception as e:
            logger.error(f"Error calculating time metrics for attendance {attendance.id}: {e}")


class AttendanceRegularizationService(BaseAttendanceService):
    """Service for handling attendance regularization requests"""

    def submit_regularization_request(self, attendance: Attendance, requested_status: str,
                                    reason: str, requested_by: User) -> ServiceResult:
        """Submit regularization request"""
        try:
            with transaction.atomic():
                attendance.regularization_status = 'Pending'
                attendance.regularization_reason = reason
                attendance.regularization_requested_status = requested_status
                # FIX #7: Now these fields exist in the model
                attendance.regularization_requested_by = requested_by
                attendance.regularization_requested_at = timezone.now()
                attendance.save()

                # Send notification to HR
                self._notify_hr_regularization_request(attendance, requested_by)

                return ServiceResult(
                    success=True,
                    message="Regularization request submitted successfully",
                    data={'attendance_id': attendance.pk}
                )

        except Exception as e:
            return self._handle_exception("SUBMIT_REGULARIZATION", e, requested_by.username)

    def process_regularization_request(self, attendance: Attendance, action: str,
                                     processed_by: 'UserType', remarks: Optional[str] = None) -> ServiceResult:
        """Process regularization request (approve/reject)"""
        try:
            with transaction.atomic():
                if action == 'approve':
                    attendance.regularization_status = 'Approved'
                    # FIX #7: Use the field directly now that it exists
                    if attendance.regularization_requested_status:
                        attendance.status = attendance.regularization_requested_status
                elif action == 'reject':
                    attendance.regularization_status = 'Rejected'

                # FIX #7: Now these fields exist in the model
                attendance.regularization_processed_by = processed_by
                attendance.regularization_processed_at = timezone.now()
                attendance.regularization_remarks = remarks
                attendance.save()

                # Notify employee
                self._notify_employee_regularization_status(attendance, action, processed_by)

                return ServiceResult(
                    success=True,
                    message=f"Regularization request {action}d successfully",
                    data={'attendance_id': attendance.pk, 'action': action}
                )

        except Exception as e:
            return self._handle_exception("PROCESS_REGULARIZATION", e, processed_by.username)

    def get_pending_regularizations(self, user: Optional[User] = None) -> ServiceResult:
        """Get pending regularization requests"""
        try:
            queryset = Attendance.objects.filter(regularization_status='Pending')

            if user and not user.groups.filter(name__in=['HR', 'Admin']).exists():
                queryset = queryset.filter(user=user)

            pending_requests = queryset.select_related(
                'user', 'regularization_requested_by'
            ).order_by('-regularization_requested_at')

            data = []
            for attendance in pending_requests:
                # FIX #7: Fields now exist in model, use directly
                data.append({
                    'id': attendance.pk,
                    'user': attendance.user.get_full_name(),
                    'date': attendance.date,
                    'current_status': attendance.status,
                    'requested_status': attendance.regularization_requested_status,
                    'reason': attendance.regularization_reason,
                    'requested_by': attendance.regularization_requested_by.get_full_name() if attendance.regularization_requested_by else '',
                    'requested_at': attendance.regularization_requested_at
                })

            return ServiceResult(success=True, data=data)

        except Exception as e:
            return self._handle_exception("GET_PENDING_REGULARIZATIONS", e)

    def _notify_hr_regularization_request(self, attendance: Attendance, requested_by: User):
        """Notify HR about regularization request"""
        try:
            hr_users = User.objects.filter(groups__name='HR', is_active=True)
            notification_sent = False

            for hr_user in hr_users:
                subject = f"Attendance Regularization Request - {attendance.user.get_full_name()}"
                message = f"""
                A new attendance regularization request has been submitted.

                Employee: {attendance.user.get_full_name()}
                Date: {attendance.date}
                Current Status: {attendance.status}
                Reason: {attendance.regularization_reason}
                Requested by: {requested_by.get_full_name()}
                """

                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[hr_user.email],
                    fail_silently=True
                )
                notification_sent = True
            
            # FIX #11: Set notification flag after successful send
            if notification_sent:
                attendance.is_hr_notified = True
                attendance.save(update_fields=['is_hr_notified'])
                
        except Exception as e:
            logger.error(f"Error sending HR notification: {e}")

    def _notify_employee_regularization_status(self, attendance: Attendance, action: str, processed_by: 'UserType'):
        """Notify employee about regularization status"""
        try:
            subject = f"Attendance Regularization {action.title()} - {attendance.date}"
            # FIX #7: Use field directly now that it exists
            message = f"""
            Your attendance regularization request has been {action}d.

            Date: {attendance.date}
            Status: {attendance.status}
            Remarks: {attendance.regularization_remarks or 'None'}
            Processed by: {processed_by.get_full_name() if processed_by else 'HR'}
            """

            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[attendance.user.email],
                fail_silently=True
            )
            
            # FIX #11: Set notification flag after successful send
            attendance.is_employee_notified = True
            attendance.save(update_fields=['is_employee_notified'])
            
        except Exception as e:
            logger.error(f"Error sending employee notification: {e}")


class AttendanceAnalyticsService(BaseAttendanceService):
    """Service for attendance analytics and reporting"""

    def get_attendance_trends(self, start_date: date, end_date: date,
                            users: Optional[List[User]] = None) -> ServiceResult:
        """Get attendance trends for date range"""
        try:
            queryset = Attendance.objects.filter(date__range=[start_date, end_date])

            if users:
                queryset = queryset.filter(user__in=users)

            # Calculate trends
            trends = queryset.values('date').annotate(
                total=Count('id'),
                present=Count('id', filter=Q(status__in=PRESENT_STATUSES)),
                absent=Count('id', filter=Q(status='Absent')),
                late=Count('id', filter=Q(status__contains='Late'))
            ).order_by('date')

            return ServiceResult(success=True, data=list(trends))

        except Exception as e:
            return self._handle_exception("GET_ATTENDANCE_TRENDS", e)

    def get_status_analytics(self, target_date: Optional[date] = None) -> ServiceResult:
        """Get overall status-wise attendance analytics"""
        try:
            if not target_date:
                target_date = self.today

            queryset = Attendance.objects.filter(date=target_date)
            
            analytics = {
                'date': str(target_date),
                'total_records': queryset.count(),
                'present_on_time': queryset.filter(status='Present').exclude(status__contains='Late').count(),
                'present_late': queryset.filter(status='Present & Late').count(),
                'work_from_home': queryset.filter(status='Work From Home').count(),
                'on_leave': queryset.filter(status='On Leave').count(),
                'absent': queryset.filter(status='Absent').count(),
                'not_marked': queryset.filter(status='Not Marked').count(),
                'half_day': queryset.filter(is_half_day=True).count(),
            }

            return ServiceResult(success=True, data=analytics)

        except Exception as e:
            return self._handle_exception("GET_STATUS_ANALYTICS", e)

    def get_late_arrival_analysis(self, start_date: date, end_date: date) -> ServiceResult:
        """Analyze late arrival patterns"""
        try:
            late_patterns = Attendance.objects.filter(
                date__range=[start_date, end_date],
                status__contains='Late'
            ).values('user__username', 'user__first_name', 'user__last_name').annotate(
                late_count=Count('id'),
                avg_late_minutes=Avg('late_minutes')
            ).order_by('-late_count')

            return ServiceResult(success=True, data=list(late_patterns))

        except Exception as e:
            return self._handle_exception("GET_LATE_ARRIVAL_ANALYSIS", e)


class AttendanceBulkOperationService(BaseAttendanceService):
    """Service for bulk attendance operations"""

    def bulk_mark_attendance(self, users: List['UserType'], target_date: date,
                           status: str, remarks: Optional[str] = None) -> ServiceResult:
        """Bulk mark attendance for multiple users"""
        try:
            with transaction.atomic():
                updated_count = 0
                errors = []

                for user in users:
                    try:
                        attendance, created = Attendance.objects.get_or_create(
                            user=user,
                            date=target_date,
                            defaults={'status': status, 'remarks': remarks}
                        )

                        if not created:
                            attendance.status = status
                            attendance.remarks = remarks
                            attendance.save()

                        updated_count += 1

                    except Exception as e:
                        errors.append(f"Error updating {user.username}: {str(e)}")

                return ServiceResult(
                    success=len(errors) == 0,
                    message=f"Bulk operation completed. Updated: {updated_count}",
                    data={'updated_count': updated_count},
                    errors=errors
                )

        except Exception as e:
            return self._handle_exception("BULK_MARK_ATTENDANCE", e)


class AttendanceReportService(BaseAttendanceService):
    """Service for attendance reports generation"""

    def generate_user_summary(self, user: User, start_date: date, end_date: date) -> ServiceResult:
        """Generate attendance summary for user"""
        try:
            attendance_records = Attendance.objects.filter(
                user=user,
                date__range=[start_date, end_date]
            ).order_by('date')

            summary = {
                'user': user.get_full_name(),
                'period': f"{start_date} to {end_date}",
                'total_days': attendance_records.count(),
                'present_days': attendance_records.filter(status__in=PRESENT_STATUSES).count(),
                'absent_days': attendance_records.filter(status='Absent').count(),
                'late_days': attendance_records.filter(status__contains='Late').count(),
                'leave_days': attendance_records.filter(status='On Leave').count(),
                'total_hours': sum([r.total_hours or Decimal('0') for r in attendance_records]),
                'records': []
            }

            for record in attendance_records:
                summary['records'].append({
                    'date': record.date,
                    'status': record.status,
                    'clock_in': record.clock_in_time.strftime('%H:%M') if record.clock_in_time else None,
                    'clock_out': record.clock_out_time.strftime('%H:%M') if record.clock_out_time else None,
                    'total_hours': float(record.total_hours or 0),
                    'late_minutes': record.late_minutes or 0
                })

            return ServiceResult(success=True, data=summary)

        except Exception as e:
            return self._handle_exception("GENERATE_USER_SUMMARY", e, user.username)

    def generate_monthly_report(self, year: int, month: int, users: Optional[List[User]] = None) -> ServiceResult:
        """Generate monthly attendance report"""
        try:
            queryset = Attendance.objects.filter(date__year=year, date__month=month)

            if users:
                queryset = queryset.filter(user__in=users)

            report_data = {
                'period': f"{year}-{month:02d}",
                'summary': {
                    'total_records': queryset.count(),
                    'present_count': queryset.filter(status__in=PRESENT_STATUSES).count(),
                    'absent_count': queryset.filter(status='Absent').count(),
                    'late_count': queryset.filter(status__contains='Late').count(),
                    'leave_count': queryset.filter(status='On Leave').count()
                },
                'daily_stats': []
            }

            # Daily statistics
            daily_stats = queryset.values('date').annotate(
                total=Count('id'),
                present=Count('id', filter=Q(status__in=PRESENT_STATUSES)),
                absent=Count('id', filter=Q(status='Absent')),
                late=Count('id', filter=Q(status__contains='Late'))
            ).order_by('date')

            report_data['daily_stats'] = list(daily_stats)

            return ServiceResult(success=True, data=report_data)

        except Exception as e:
            return self._handle_exception("GENERATE_MONTHLY_REPORT", e)


class AttendanceIntegrationService(BaseAttendanceService):
    """Service for integrating attendance with sessions and other systems"""

    def process_session_login(self, user: User, session: UserSession) -> ServiceResult:
        """Process session login and update attendance"""
        try:
            # Handle login_time attribute safely
            login_time = getattr(session, 'login_time', timezone.now())
            login_date = login_time.astimezone(IST).date()

            # Get or create attendance record
            attendance, created = Attendance.objects.get_or_create(
                user=user,
                date=login_date,
                defaults=self._get_attendance_defaults(user, login_date)
            )

            # Update with session data
            if not attendance.first_session or session.login_time < attendance.first_session.login_time:
                attendance.first_session = session
                attendance.clock_in_time = session.login_time

            if not attendance.clock_in_time:
                attendance.clock_in_time = session.login_time

            # 🔥 CRITICAL FIX: Mark as Present when user logs in!
            # This is the core of attendance tracking - if user logged in, they're PRESENT!
            # This includes Weekend/Holiday - if they login, they're working!
            if attendance.status in ['Not Marked', None, '', 'Weekend', 'Holiday', 'Yet to Clock In']:
                old_status = attendance.status
                attendance.status = 'Present'
                # If it was weekend/holiday, note they worked on non-working day
                if old_status in ['Weekend', 'Holiday']:
                    attendance.is_weekend = False  # Override since they're working
                    attendance.is_holiday = False
                    logger.info(f"✅ MARKED {user.username} as PRESENT on {old_status} - Working on non-working day!")
                else:
                    logger.info(f"✅ MARKED {user.username} as PRESENT on login at {login_time}")
            
            # Determine location from IP
            location = self._determine_location_from_ip(session.ip_address)
            if location and hasattr(attendance, 'location'):
                attendance.location = location

            attendance.save()
            self._invalidate_user_cache(user.pk, login_date)

            return ServiceResult(success=True, message="Session login processed", data={'attendance_id': attendance.pk})

        except Exception as e:
            return self._handle_exception("PROCESS_SESSION_LOGOUT", e, user.username)

    def _determine_location_from_ip(self, ip_address: str) -> str:
        """Determine work location from IP address"""
        try:
            # Define office IP ranges (this should come from settings)
            office_ranges = getattr(settings, 'OFFICE_IP_RANGES', [
                '192.168.1.0/24',  # Example office network
                '10.0.0.0/16'      # Example VPN range
            ])

            import ipaddress
            ip = ipaddress.ip_address(ip_address)

            for ip_range in office_ranges:
                if ip in ipaddress.ip_network(ip_range):
                    return 'Office'

            return 'Remote'

        except Exception as e:
            logger.warning(f"Could not determine location from IP {ip_address}: {e}")
            return 'Unknown'

    def create_daily_attendance_records(self, target_date: Optional[date] = None) -> ServiceResult:
        """Create daily attendance records for all active users"""
        if not target_date:
            target_date = self.today

        try:
            # Get all active users
            active_users = User.objects.filter(is_active=True)
            created_count = 0

            for user in active_users:
                try:
                    attendance, created = Attendance.objects.get_or_create(
                        user=user,
                        date=target_date,
                        defaults=self._get_attendance_defaults(user, target_date)
                    )

                    if created:
                        created_count += 1

                except Exception as e:
                    logger.error(f"Error creating attendance for {user.username}: {e}")

            self._log_operation("DAILY_RECORDS_CREATED",
                              details=f"Date: {target_date}, Created: {created_count}")

            return ServiceResult(
                success=True,
                message=f"Created {created_count} daily attendance records",
                data={'created_count': created_count, 'date': str(target_date)}
            )

        except Exception as e:
            return self._handle_exception("CREATE_DAILY_RECORDS", e)


# Utility Functions
def get_attendance_services() -> Dict[str, BaseAttendanceService]:
    """Get all attendance services in a dictionary"""
    return {
        'auto_marking': AttendanceAutoMarkingService(),
        'integration': AttendanceIntegrationService(),
        'regularization': AttendanceRegularizationService(),
        'reports': AttendanceReportService(),
        'analytics': AttendanceAnalyticsService(),
        'bulk_operations': AttendanceBulkOperationService(),
    }


def run_daily_attendance_tasks() -> ServiceResult:
    """Run daily attendance maintenance tasks"""
    try:
        logger.info("Running daily attendance tasks...")

        services = get_attendance_services()
        results = {}

        # Run auto-marking
        auto_marking_result = services['auto_marking'].run_auto_marking()
        results['auto_marking'] = auto_marking_result.to_dict()

        # Create daily records for tomorrow
        tomorrow = timezone.now().astimezone(IST).date() + timedelta(days=1)
        daily_creation_result = services['integration'].create_daily_attendance_records(tomorrow)
        results['daily_creation'] = daily_creation_result.to_dict()

        logger.info("Daily attendance tasks completed")

        return ServiceResult(
            success=True,
            message="Daily attendance tasks completed successfully",
            data=results
        )

    except Exception as e:
        logger.error(f"Error running daily attendance tasks: {e}")
        return ServiceResult(
            success=False,
            message="Failed to run daily attendance tasks",
            errors=[str(e)]
        )


def initialize_attendance_system() -> ServiceResult:
    """Initialize attendance system with necessary setup"""
    try:
        logger.info("Initializing attendance system...")

        # Create daily attendance records if needed
        integration_service = AttendanceIntegrationService()
        result = integration_service.create_daily_attendance_records()

        if result.success:
            logger.info("Attendance system initialized successfully")
            return ServiceResult(success=True, message="Attendance system initialized")
        else:
            logger.error("Failed to initialize attendance system")
            return result

    except Exception as e:
        logger.error(f"Error initializing attendance system: {e}")
        return ServiceResult(success=False, message="Failed to initialize attendance system", errors=[str(e)])

    def process_session_logout(self, user: User, session: UserSession) -> ServiceResult:
        """Process session logout and update attendance"""
        try:
            # 🔥 FIX: Normalize logout_time to IST timezone
            logout_time_ist = session.logout_time.astimezone(self.ist) if session.logout_time else None
            logout_date = logout_time_ist.date() if logout_time_ist else self.today

            try:
                attendance = Attendance.objects.get(user=user, date=logout_date)

                # 🔥 FIX: Normalize both times to IST before comparison
                if logout_time_ist:
                    clock_in_ist = attendance.clock_in_time.astimezone(self.ist) if attendance.clock_in_time else None
                    clock_out_ist = attendance.clock_out_time.astimezone(self.ist) if attendance.clock_out_time else None
                    
                    # Update logout time if no last_session OR no clock_out OR this logout is later
                    if not attendance.last_session or not clock_out_ist or logout_time_ist > clock_out_ist:
                        attendance.last_session = session
                        attendance.clock_out_time = logout_time_ist  # Store in IST
                        logger.info(f"✅ UPDATED clock_out for {user.username} to {logout_time_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")

                    # Calculate total hours if we have both clock_in and clock_out
                    if clock_in_ist and attendance.clock_out_time:
                        clock_out_normalized = attendance.clock_out_time.astimezone(self.ist)
                        time_diff = clock_out_normalized - clock_in_ist
                        total_seconds = time_diff.total_seconds()
                        
                        # Only set positive hours
                        if total_seconds > 0:
                            attendance.total_hours = Decimal(str(round(total_seconds / 3600, 2)))
                            logger.info(f"✅ CALCULATED total_hours for {user.username}: {attendance.total_hours}h")
                        else:
                            logger.warning(f"⚠️ Negative time difference for {user.username}: {total_seconds}s - skipping total_hours")

                attendance.save()
                self._invalidate_user_cache(user.pk, logout_date)

                return ServiceResult(success=True, message="Session logout processed", data={'attendance_id': attendance.pk})

            except Attendance.DoesNotExist:
                logger.warning(f"No attendance record found for user {user.username} on {logout_date}")
                return ServiceResult(success=False, message="No attendance record found")

        except Exception as e:
            logger.error(f"Unexpected error during logout: {str(e)}")
            return ServiceResult(success=False, message="An error occurred during logout")
