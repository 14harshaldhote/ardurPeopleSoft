"""
Django Signals for Optimized Session Management
Minimal version to avoid import errors
"""

import logging
from datetime import timedelta
from django.db.models.signals import post_save, pre_delete
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)

# =============================================================================
# SESSION LIFECYCLE SIGNALS
# =============================================================================

@receiver(user_logged_in)
def handle_user_login(sender, request, user, **kwargs):
    """
    Handle user login - create initial session, set up tracking, and auto-mark attendance
    """
    if not user or not user.is_authenticated:
        return

    try:
        # Clear any existing session caches for this user
        cache_key = f"opt_session:{user.id}"
        cache.delete(cache_key)

        # Clear throttle caches to allow immediate session creation
        throttle_key = f"opt_throttle:create_session:{user.id}"
        cache.delete(throttle_key)

        # Log the login for tracking
        logger.info(f"User {user.username} logged in - session tracking initialized")

        # Close any existing active sessions for this user
        try:
            from trueAlign.models import UserSession, Attendance
            UserSession.objects.filter(
                user=user,
                is_active=True
            ).update(
                is_active=False,
                session_end_time=timezone.now(),
                end_reason='new_login'
            )
            
            # Create new UserSession for the logged in user
            session = UserSession.objects.create(
                user=user,
                is_active=True,
                start_time=timezone.now(),
                last_activity=timezone.now(),
                ip_address=get_client_ip(request) if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:200] if request else ''
            )
            logger.info(f"Created new session {session.id} for user {user.username}")
            
            # Auto-create Attendance record for today if not exists
            today = timezone.now().date()
            attendance, created = Attendance.objects.get_or_create(
                user=user,
                date=today,
                defaults={
                    'status': 'Present',
                    'clock_in_time': timezone.now()
                }
            )
            if created:
                logger.info(f"Auto-created attendance for user {user.username} on {today}")
            else:
                # Update clock-in time if attendance exists but no clock-in
                if not attendance.clock_in_time:
                    attendance.clock_in_time = timezone.now()
                    attendance.status = 'Present'
                    attendance.save()
                    logger.info(f"Updated attendance clock-in for user {user.username}")
            
        except Exception as e:
            logger.error(f"Error managing sessions/attendance on login: {str(e)}")

    except Exception as e:
        logger.error(f"Error handling user login for {user.username}: {str(e)}")


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@receiver(user_logged_out)
def handle_user_logout(sender, request, user, **kwargs):
    """
    Handle user logout - cleanup sessions and buffers
    """
    if not user or not user.is_authenticated:
        return

    try:
        # Get current active sessions and close them
        try:
            from trueAlign.models import UserSession
            active_sessions = UserSession.objects.filter(
                user=user,
                is_active=True
            )

            # Close all active sessions
            for session in active_sessions:
                session.is_active = False
                session.session_end_time = timezone.now()
                session.end_reason = 'logout'
                session.save()

                logger.info(f"Closed session {session.id} for user {user.username}")
        except Exception as e:
            logger.error(f"Error closing sessions: {str(e)}")

        # Clear all caches for this user
        cache_keys_to_clear = [
            f"opt_session:{user.id}",
            f"opt_status:{user.id}",
            f"opt_heartbeat:{user.id}",
            f"opt_analytics:{user.id}",
        ]

        for key in cache_keys_to_clear:
            cache.delete(key)

        logger.info(f"User {user.username} logged out - session data cleaned up")

    except Exception as e:
        logger.error(f"Error handling user logout for {user.username}: {str(e)}")

# =============================================================================
# SESSION MODEL SIGNALS
# =============================================================================

def handle_session_save(sender, instance, created, **kwargs):
    """
    Handle session save operations
    """
    try:
        if created:
            # New session created
            logger.info(f"New session created for user {instance.user.username}: {instance.id}")

            # Clear related caches
            cache_key = f"opt_session:{instance.user.id}"
            cache.delete(cache_key)

        else:
            # Session updated
            logger.debug(f"Session updated for user {instance.user.username}: {instance.id}")

        # Update session cache
        cache_key = f"opt_session:{instance.user.id}:current"
        cache.set(cache_key, instance, timeout=300)  # 5 minutes

    except Exception as e:
        logger.error(f"Error in session save handler: {str(e)}")

def handle_session_delete(sender, instance, **kwargs):
    """
    Handle session deletion - cleanup related data
    """
    try:
        # Clear session caches
        cache_keys_to_clear = [
            f"opt_session:{instance.user.id}",
            f"opt_session:{instance.user.id}:current",
            f"opt_status:{instance.user.id}",
        ]

        for key in cache_keys_to_clear:
            cache.delete(key)

        logger.info(f"Session {instance.id} deleted for user {instance.user.username}")

    except Exception as e:
        logger.error(f"Error in session delete handler: {str(e)}")

@receiver(post_save, sender=User)
def handle_user_update(sender, instance, created, **kwargs):
    """
    Handle user creation and updates that might affect sessions
    """
    if created:
        # Auto-create UserDetails profile for new users
        try:
            from trueAlign.models import UserDetails

            # Determine default role based on user properties
            default_role = 'developer'  # Default role

            if instance.is_superuser:
                default_role = 'admin'
            elif instance.is_staff:
                default_role = 'hr'
            elif instance.groups.filter(name__icontains='admin').exists():
                default_role = 'admin'
            elif instance.groups.filter(name__icontains='hr').exists():
                default_role = 'hr'
            elif instance.groups.filter(name__icontains='manager').exists():
                default_role = 'manager'

            # Create UserDetails profile
            UserDetails.objects.get_or_create(
                user=instance,
                defaults={
                    'role': default_role,
                    'employee_type': 'full_time',
                    'employment_status': 'active',
                    'personal_email': instance.email,
                }
            )
            logger.info(f"UserDetails profile created for new user: {instance.username}")

        except Exception as e:
            logger.error(f"Error creating UserDetails for user {instance.username}: {str(e)}")
    else:
        try:
            # Clear user-related caches when user is updated
            cache_keys_to_clear = [
                f"opt_session:{instance.id}",
                f"opt_status:{instance.id}",
                f"opt_analytics:{instance.id}",
            ]

            for key in cache_keys_to_clear:
                cache.delete(key)

        except Exception as e:
            logger.error(f"Error handling user update: {str(e)}")

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

def cleanup_old_sessions():
    """
    Clean up old sessions - called via Django management command or periodic signal
    """
    try:
        from trueAlign.models import UserSession
        cutoff_date = timezone.now() - timedelta(days=30)

        # Delete old inactive sessions
        old_sessions = UserSession.objects.filter(
            is_active=False,
            session_end_time__lt=cutoff_date
        )

        count = old_sessions.count()
        old_sessions.delete()

        logger.info(f"Cleaned up {count} old sessions")
        return count

    except Exception as e:
        logger.error(f"Error cleaning up old sessions: {str(e)}")
        return 0

def cleanup_inactive_sessions():
    """
    Clean up sessions that have been inactive for too long
    """
    try:
        from trueAlign.models import UserSession
        cutoff_time = timezone.now() - timedelta(minutes=40)  # 30 + 10 minutes

        # Find sessions that should be closed
        inactive_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=cutoff_time
        )

        count = 0
        for session in inactive_sessions:
            session.is_active = False
            session.session_end_time = timezone.now()
            session.end_reason = 'timeout'
            session.save()
            count += 1

            # Clear related caches
            cache_key = f"opt_session:{session.user.id}"
            cache.delete(cache_key)

        if count > 0:
            logger.info(f"Closed {count} inactive sessions")

        return count

    except Exception as e:
        logger.error(f"Error cleaning up inactive sessions: {str(e)}")
        return 0

# =============================================================================
# SIGNAL-BASED CLEANUP TRIGGER
# =============================================================================

def trigger_maintenance_if_needed():
    """
    Trigger maintenance tasks if needed - called from middleware
    """
    try:
        last_cleanup = cache.get('last_session_cleanup')
        if not last_cleanup:
            last_cleanup = timezone.now() - timedelta(hours=1)

        # Run cleanup every hour
        if timezone.now() - last_cleanup > timedelta(hours=1):
            # Run cleanup tasks
            cleanup_inactive_sessions()
            cleanup_old_sessions()

            # Update last cleanup time
            cache.set('last_session_cleanup', timezone.now(), timeout=None)

            return True

    except Exception as e:
        logger.error(f"Error in maintenance trigger: {str(e)}")

    return False

# =============================================================================
# SECURITY FUNCTIONS
# =============================================================================

def handle_suspicious_activity(user, session, indicators):
    """
    Handle suspicious activity detection
    """
    try:
        if not indicators:
            return

        # Log suspicious activity
        for indicator in indicators:
            logger.warning(
                f"Suspicious activity detected for user {user.username}: "
                f"{indicator.get('type', 'unknown')} (severity: {indicator.get('severity', 'unknown')})"
            )

        # Update session with security flags
        if session and hasattr(session, 'security_data'):
            try:
                security_data = session.security_data or {}
                security_data['suspicious_activity'] = indicators
                security_data['last_security_check'] = timezone.now().isoformat()
                session.security_data = security_data
                session.save()
            except Exception as e:
                logger.error(f"Error updating session security data: {str(e)}")

    except Exception as e:
        logger.error(f"Error handling suspicious activity: {str(e)}")

# =============================================================================
# UTILITY FUNCTIONS FOR MIDDLEWARE
# =============================================================================

def get_cached_session(user_id):
    """
    Get cached session for user
    """
    try:
        cache_key = f"opt_session:{user_id}:current"
        return cache.get(cache_key)
    except Exception as e:
        logger.error(f"Error getting cached session: {str(e)}")
        return None

def cache_session(user_id, session):
    """
    Cache session for user
    """
    try:
        cache_key = f"opt_session:{user_id}:current"
        cache.set(cache_key, session, timeout=300)  # 5 minutes
    except Exception as e:
        logger.error(f"Error caching session: {str(e)}")

def invalidate_user_caches(user_id):
    """
    Invalidate all caches for a user
    """
    try:
        cache_keys = [
            f"opt_session:{user_id}",
            f"opt_session:{user_id}:current",
            f"opt_status:{user_id}",
            f"opt_heartbeat:{user_id}",
            f"opt_analytics:{user_id}",
        ]

        for key in cache_keys:
            cache.delete(key)

    except Exception as e:
        logger.error(f"Error invalidating user caches: {str(e)}")

# =============================================================================
# MANAGEMENT COMMAND HELPERS
# =============================================================================

def run_maintenance_tasks():
    """
    Run all maintenance tasks - can be called from management command
    """
    results = {
        'inactive_sessions_closed': cleanup_inactive_sessions(),
        'old_sessions_deleted': cleanup_old_sessions(),
        'timestamp': timezone.now().isoformat()
    }

    logger.info(f"Maintenance tasks completed: {results}")
    return results

def get_session_stats():
    """
    Get session statistics for monitoring
    """
    try:
        from trueAlign.models import UserSession

        stats = {
            'total_sessions': UserSession.objects.count(),
            'active_sessions': UserSession.objects.filter(is_active=True).count(),
            'sessions_today': UserSession.objects.filter(
                start_time__date=timezone.now().date()
            ).count(),
            'unique_users_today': UserSession.objects.filter(
                start_time__date=timezone.now().date()
            ).values('user').distinct().count(),
        }

        return stats

    except Exception as e:
        logger.error(f"Error getting session stats: {str(e)}")
        return {}

# =============================================================================
# SIGNAL INITIALIZATION
# =============================================================================

def initialize_session_signals():
    """
    Initialize session-related signals
    """
    try:
        from trueAlign.models import UserSession

        # Connect signals
        post_save.connect(handle_session_save, sender=UserSession)
        pre_delete.connect(handle_session_delete, sender=UserSession)

        # Initialize cleanup scheduler
        cache.set('last_session_cleanup', timezone.now(), timeout=None)
        cache.set('cleanup_schedule_active', True, timeout=None)

        logger.info("Session signals initialized successfully")

    except ImportError:
        logger.warning("UserSession model not available, skipping signal initialization")
    except Exception as e:
        logger.error(f"Error initializing session signals: {str(e)}")

# Initialize signals when module is imported
initialize_session_signals()
