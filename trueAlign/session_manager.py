"""
Session Manager Module for TrueAlign
Provides session management functionality with logging and validation capabilities.
"""

import logging
from typing import Optional, Any, Dict
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone

# Try to import the enhanced session manager from core
try:
    from trueAlign.core.session_manager import EnhancedSessionManager, get_session_manager
    _core_session_manager = get_session_manager()
    CORE_AVAILABLE = True
except ImportError:
    _core_session_manager = None
    CORE_AVAILABLE = False

# Set up logging
logger = logging.getLogger(__name__)


class SessionLogger:
    """Logger for session-related activities"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.session")

    def log_session_start(self, user_id: int, session_id: str, **kwargs):
        """Log session start event"""
        self.logger.info(f"Session started for user {user_id}, session {session_id}", extra=kwargs)

    def log_session_end(self, user_id: int, session_id: str, duration: Optional[timedelta] = None, **kwargs):
        """Log session end event"""
        duration_str = f", duration: {duration}" if duration else ""
        self.logger.info(f"Session ended for user {user_id}, session {session_id}{duration_str}", extra=kwargs)

    def log_activity(self, user_id: int, session_id: str, activity: str, **kwargs):
        """Log general session activity"""
        self.logger.debug(f"User {user_id} session {session_id}: {activity}", extra=kwargs)

    def log_location_update(self, user_id: int, session_id: str, location_data: Dict[str, Any], **kwargs):
        """Log location update events"""
        self.logger.info(f"Location update for user {user_id}, session {session_id}: {location_data}", extra=kwargs)

    def queue_location_update(self, user_id: int, session_id: str, location_data: Dict[str, Any], **kwargs):
        """Queue location update for processing"""
        self.logger.debug(f"Queued location update for user {user_id}, session {session_id}", extra=kwargs)

    def add_activity(self, user_id: int, session_id: str, activity_type: str, details: Dict[str, Any] = None, **kwargs):
        """Add activity to session log"""
        details_str = f", details: {details}" if details else ""
        self.logger.info(f"Activity added for user {user_id}, session {session_id}: {activity_type}{details_str}", extra=kwargs)


class SessionValidator:
    """Validator for session-related operations"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.validator")

    def validate_session_data(self, session_data: Dict[str, Any]) -> bool:
        """Validate session data structure"""
        required_fields = ['user_id', 'session_id', 'created_at']
        for field in required_fields:
            if field not in session_data:
                self.logger.warning(f"Missing required field in session data: {field}")
                return False
        return True

    def validate_user_permissions(self, user: User, action: str) -> bool:
        """Validate user permissions for session actions"""
        if not user or not user.is_active:
            self.logger.warning(f"Invalid or inactive user attempting action: {action}")
            return False
        return True

    def validate_session_timeout(self, last_activity: datetime, timeout_minutes: int = 30) -> bool:
        """Validate if session has timed out"""
        if not last_activity:
            return False

        timeout_threshold = timezone.now() - timedelta(minutes=timeout_minutes)
        if last_activity < timeout_threshold:
            self.logger.info(f"Session timed out. Last activity: {last_activity}")
            return False
        return True


class SessionManager:
    """
    Main session manager class that provides a unified interface
    for session management, logging, and validation.
    """

    def __init__(self):
        self.logger = SessionLogger()
        self.validator = SessionValidator()
        self._core_manager = _core_session_manager if CORE_AVAILABLE else None
        self._internal_logger = logging.getLogger(__name__)

    def get_or_create_session(self, user, request=None, **kwargs):
        """Get or create a session for the user"""
        if self._core_manager:
            try:
                return self._core_manager.get_or_create_session(user, request, **kwargs)
            except Exception as e:
                self._internal_logger.error(f"Error using core session manager: {e}")
                # Fallback to basic session creation
                return self._create_basic_session(user, **kwargs)
        else:
            return self._create_basic_session(user, **kwargs)

    def _create_basic_session(self, user, **kwargs):
        """Basic session creation fallback"""
        from django.contrib.sessions.models import Session
        import uuid

        session_key = str(uuid.uuid4())
        session_data = {
            'user_id': user.id,
            'session_id': session_key,
            'created_at': timezone.now().isoformat(),
            **kwargs
        }

        self.logger.log_session_start(user.id, session_key, **session_data)
        return session_data

    def end_session(self, session_id: str, user_id: int = None, **kwargs):
        """End a session"""
        if self._core_manager:
            try:
                return self._core_manager.end_session(session_id, **kwargs)
            except Exception as e:
                self._internal_logger.error(f"Error ending session with core manager: {e}")

        if user_id:
            self.logger.log_session_end(user_id, session_id, **kwargs)

    def log_activity(self, user_id: int, session_id: str, activity: str, **kwargs):
        """Log session activity"""
        self.logger.log_activity(user_id, session_id, activity, **kwargs)

    def validate_session(self, session_data: Dict[str, Any]) -> bool:
        """Validate session data"""
        return self.validator.validate_session_data(session_data)

    def get_metrics(self):
        """Get session metrics"""
        if self._core_manager:
            try:
                return self._core_manager.get_metrics()
            except Exception as e:
                self._internal_logger.error(f"Error getting metrics from core manager: {e}")

        return {
            'active_sessions': 0,
            'total_sessions': 0,
            'avg_session_duration': 0,
            'core_manager_available': CORE_AVAILABLE
        }

    def invalidate_session_cache(self, session_id: str = None):
        """Invalidate session cache"""
        if self._core_manager:
            try:
                return self._core_manager.invalidate_session_cache(session_id)
            except Exception as e:
                self._internal_logger.error(f"Error invalidating cache with core manager: {e}")


# Create default instances
default_session_manager = SessionManager()
session_logger = default_session_manager.logger
session_validator = default_session_manager.validator

# For backward compatibility
SessionManager = SessionManager
