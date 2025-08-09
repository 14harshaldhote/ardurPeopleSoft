import logging
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.db import transaction
from django.db.utils import OperationalError
from trueAlign.models import UserSession, Attendance, ShiftAssignment
from .services import AttendanceIntegrationService
import pytz
import time

logger = logging.getLogger('trueAlign.attendance')

# Initialize attendance integration service
attendance_service = AttendanceIntegrationService()

# In ardurPeopleSoft/trueAlign/attendance/signals.py - Replace the signal handler

@receiver(post_save, sender=UserSession)
def handle_session_save(sender, instance, created, **kwargs):
    """
    Automatically create/update attendance when user session is created or updated
    """
    try:
        # Skip if we're in a nested transaction to avoid savepoint issues
        if transaction.get_connection().in_atomic_block:
            logger.debug(f"Skipping session processing for {instance.user.username} - in atomic block")
            return

        IST = pytz.timezone('Asia/Kolkata')

        if created:
            # New session created - this is a login event
            logger.info(f"Processing new session for {instance.user.username}")
            try:
                attendance_service.process_session_login(instance.user, instance)
            except Exception as e:
                logger.error(f"Error in session login processing: {e}")

        else:
            # Session updated - check if logout occurred
            if instance.logout_time and instance.ended_at and not instance.is_active:
                logger.info(f"Processing session logout for {instance.user.username}")
                try:
                    attendance_service.process_session_logout(instance.user, instance)
                except Exception as e:
                    logger.error(f"Error in session logout processing: {e}")
            else:
                # Just update session data without processing logout
                login_date = instance.login_time.astimezone(IST).date()
                try:
                    Attendance.update_session_data(instance.user, instance, login_date)
                    logger.debug(f"Updated attendance session data for {instance.user.username}")
                except Exception as e:
                    logger.error(f"Error updating session data: {e}")

    except Exception as e:
        logger.error(f"Error processing session signal for {instance.user.username}: {e}", exc_info=True)


@receiver(pre_save, sender=UserSession)
def handle_session_pre_save(sender, instance, **kwargs):
    """
    Process session before saving to detect logout events
    """
    try:
        # Skip if we're in a nested transaction to avoid savepoint issues
        if transaction.get_connection().in_atomic_block:
            return

        # Check if this is an existing session being updated
        if instance.pk:
            try:
                old_session = UserSession.objects.get(pk=instance.pk)

                # Check if session is being ended
                if not old_session.ended_at and instance.ended_at:
                    # Session is being ended - record the logout time
                    if not instance.logout_time:
                        instance.logout_time = instance.ended_at

                    logger.debug(f"Session ending detected for {instance.user.username}")

            except UserSession.DoesNotExist:
                pass

    except Exception as e:
        logger.error(f"Error in session pre_save signal: {e}", exc_info=True)

@receiver(post_save, sender=ShiftAssignment)
def handle_shift_assignment_save(sender, instance, created, **kwargs):
    """
    Update existing attendance records when shift assignments change
    """
    try:
        # Skip if we're in a nested transaction to avoid savepoint issues
        if transaction.get_connection().in_atomic_block:
            logger.debug(f"Skipping shift assignment processing for {instance.user.username} - in atomic block")
            return

        if created:
            logger.info(f"New shift assignment created for {instance.user.username}")

            # Update future attendance records with new shift
            future_attendances = Attendance.objects.filter(
                user=instance.user,
                date__gte=instance.effective_from,
                shift__isnull=True
            )

            if instance.effective_to:
                future_attendances = future_attendances.filter(date__lte=instance.effective_to)

            updated_count = future_attendances.update(shift=instance.shift)
            logger.info(f"Updated {updated_count} future attendance records with new shift")

        else:
            # Existing assignment updated - recalculate affected attendance
            affected_attendances = Attendance.objects.filter(
                user=instance.user,
                date__gte=instance.effective_from
            )

            if instance.effective_to:
                affected_attendances = affected_attendances.filter(date__lte=instance.effective_to)

            # Recalculate each attendance record
            for attendance in affected_attendances:
                try:
                    if not attendance.shift or attendance.shift != instance.shift:
                        attendance.shift = instance.shift
                        attendance.save()  # This will trigger recalculation
                        logger.debug(f"Recalculated attendance for {instance.user.username} on {attendance.date}")
                except Exception as e:
                    logger.error(f"Error updating attendance for {instance.user.username}: {e}")

    except Exception as e:
        logger.error(f"Error processing shift assignment signal: {e}", exc_info=True)
