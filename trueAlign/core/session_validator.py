import logging
import time
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.db import transaction
import threading

logger = logging.getLogger(__name__)

class SessionDurationValidator:
    """
    Session duration validation system to prevent short-lived sessions and ensure data quality
    """
    
    def __init__(self):
        # Configuration
        self.config = {
            'min_session_duration': getattr(settings, 'MIN_SESSION_DURATION', 10),  # 10 seconds
            'max_session_duration': getattr(settings, 'MAX_SESSION_DURATION', 43200),  # 12 hours
            'grace_period': getattr(settings, 'SESSION_GRACE_PERIOD', 5),  # 5 seconds
            'validation_interval': getattr(settings, 'SESSION_VALIDATION_INTERVAL', 300),  # 5 minutes
            'auto_extend_threshold': getattr(settings, 'SESSION_AUTO_EXTEND_THRESHOLD', 30),  # 30 seconds
            'suspicious_threshold': getattr(settings, 'SESSION_SUSPICIOUS_THRESHOLD', 3),  # 3 seconds
        }
        
        # Tracking structures
        self._session_tracking = {}
        self._tracking_lock = threading.RLock()
        
        # Validation statistics
        self._stats = {
            'validated_sessions': 0,
            'extended_sessions': 0,
            'terminated_sessions': 0,
            'suspicious_sessions': 0,
            'total_validations': 0
        }
        self._stats_lock = threading.RLock()
        
        # Background validation
        self._shutdown_event = threading.Event()
        self._validation_thread = None
        
        # Start background validation
        self._start_validation_thread()
        
        logger.info("Session Duration Validator initialized with config: %s", self.config)
    
    def register_session(self, session):
        """
        Register a session for duration validation
        """
        try:
            with self._tracking_lock:
                self._session_tracking[session.id] = {
                    'session': session,
                    'start_time': session.created_at or timezone.now(),
                    'last_validation': timezone.now(),
                    'validation_count': 0,
                    'auto_extended': False,
                    'warning_sent': False,
                    'status': 'active'
                }
            
            logger.debug(f"Registered session {session.id} for validation")
            
        except Exception as e:
            logger.error(f"Error registering session {session.id}: {str(e)}")
    
    def validate_session(self, session):
        """
        Validate a specific session's duration
        """
        from trueAlign.core.enhanced_logger import get_session_logger
        
        try:
            session_logger = get_session_logger()
            current_time = timezone.now()
            
            with self._tracking_lock:
                tracking_info = self._session_tracking.get(session.id)
                if not tracking_info:
                    self.register_session(session)
                    tracking_info = self._session_tracking[session.id]
                
                # Update tracking info
                tracking_info['last_validation'] = current_time
                tracking_info['validation_count'] += 1
            
            # Calculate session duration
            start_time = tracking_info['start_time']
            duration = (current_time - start_time).total_seconds()
            
            # Update statistics
            with self._stats_lock:
                self._stats['total_validations'] += 1
            
            # Validate minimum duration for ending sessions
            if not session.is_active and duration < self.config['min_session_duration']:
                return self._handle_short_session(session, duration, session_logger, tracking_info)
            
            # Check for suspicious very short sessions
            if duration < self.config['suspicious_threshold'] and session.is_active:
                return self._handle_suspicious_session(session, duration, session_logger, tracking_info)
            
            # Check for maximum duration exceeded
            if duration > self.config['max_session_duration']:
                return self._handle_long_session(session, duration, session_logger, tracking_info)
            
            # Auto-extend sessions that are close to minimum
            if (duration < self.config['auto_extend_threshold'] and 
                session.is_active and not tracking_info['auto_extended']):
                return self._auto_extend_session(session, duration, session_logger, tracking_info)
            
            # Regular validation passed
            with self._stats_lock:
                self._stats['validated_sessions'] += 1
            
            logger.debug(f"Session {session.id} validation passed: {duration:.2f}s")
            
            return {
                'valid': True,
                'duration': duration,
                'action': 'none',
                'message': 'Session validation passed'
            }
            
        except Exception as e:
            logger.error(f"Error validating session {session.id}: {str(e)}")
            return {
                'valid': False,
                'duration': 0,
                'action': 'error',
                'message': f'Validation error: {str(e)}'
            }
    
    def _handle_short_session(self, session, duration, session_logger, tracking_info):
        """
        Handle sessions that are too short
        """
        # Check if within grace period
        if duration >= (self.config['min_session_duration'] - self.config['grace_period']):
            # Allow with warning
            session_logger.log_short_session(
                session.user, session.id, duration, 'within_grace_period'
            )
            
            return {
                'valid': True,
                'duration': duration,
                'action': 'grace_allowed',
                'message': f'Short session allowed within grace period: {duration:.2f}s'
            }
        
        # Session is definitely too short
        session_logger.log_short_session(
            session.user, session.id, duration, 'below_minimum_duration'
        )
        
        # Mark session as invalid
        with transaction.atomic():
            session.end_reason = 'duration_too_short'
            session.is_active = False
            session.save(update_fields=['end_reason', 'is_active'])
        
        # Update tracking
        tracking_info['status'] = 'terminated_short'
        
        with self._stats_lock:
            self._stats['terminated_sessions'] += 1
        
        logger.warning(f"Terminated short session {session.id}: {duration:.2f}s")
        
        return {
            'valid': False,
            'duration': duration,
            'action': 'terminated',
            'message': f'Session too short: {duration:.2f}s < {self.config["min_session_duration"]}s'
        }
    
    def _handle_suspicious_session(self, session, duration, session_logger, tracking_info):
        """
        Handle suspicious very short active sessions
        """
        session_logger.log_short_session(
            session.user, session.id, duration, 'suspicious_short_active'
        )
        
        # Flag as suspicious but don't terminate yet
        tracking_info['status'] = 'suspicious'
        
        with self._stats_lock:
            self._stats['suspicious_sessions'] += 1
        
        # Cache warning for monitoring
        cache.set(f"suspicious_session_{session.id}", {
            'duration': duration,
            'timestamp': timezone.now().isoformat(),
            'user_id': session.user.id
        }, 3600)  # 1 hour
        
        logger.warning(f"Flagged suspicious session {session.id}: {duration:.2f}s")
        
        return {
            'valid': True,  # Don't terminate yet, just flag
            'duration': duration,
            'action': 'flagged_suspicious',
            'message': f'Session flagged as suspicious: {duration:.2f}s'
        }
    
    def _handle_long_session(self, session, duration, session_logger, tracking_info):
        """
        Handle sessions that exceed maximum duration
        """
        # Send warning if not sent yet
        if not tracking_info['warning_sent']:
            self._send_session_warning(session, 'max_duration_exceeded')
            tracking_info['warning_sent'] = True
        
        # Terminate session
        with transaction.atomic():
            session.end_reason = 'max_duration_exceeded'
            session.is_active = False
            session.ended_at = timezone.now()
            session.save(update_fields=['end_reason', 'is_active', 'ended_at'])
        
        # Update tracking
        tracking_info['status'] = 'terminated_long'
        
        with self._stats_lock:
            self._stats['terminated_sessions'] += 1
        
        logger.warning(f"Terminated long session {session.id}: {duration:.2f}s")
        
        return {
            'valid': False,
            'duration': duration,
            'action': 'terminated',
            'message': f'Session exceeded maximum duration: {duration:.2f}s > {self.config["max_session_duration"]}s'
        }
    
    def _auto_extend_session(self, session, duration, session_logger, tracking_info):
        """
        Auto-extend sessions that are close to minimum duration
        """
        # Calculate extension time
        extension_needed = self.config['min_session_duration'] - duration + self.config['grace_period']
        
        # Update session timestamps to extend duration
        with transaction.atomic():
            # Extend the session by adjusting creation time backwards
            new_created_at = session.created_at - timedelta(seconds=extension_needed)
            session.created_at = new_created_at
            session.save(update_fields=['created_at'])
        
        # Update tracking
        tracking_info['auto_extended'] = True
        tracking_info['start_time'] = new_created_at
        
        with self._stats_lock:
            self._stats['extended_sessions'] += 1
        
        logger.info(f"Auto-extended session {session.id} by {extension_needed:.2f}s")
        
        return {
            'valid': True,
            'duration': duration + extension_needed,
            'action': 'auto_extended',
            'message': f'Session auto-extended by {extension_needed:.2f}s'
        }
    
    def _send_session_warning(self, session, warning_type):
        """
        Send warning about session duration issues
        """
        try:
            # Store warning in cache for frontend to display
            warning_data = {
                'type': warning_type,
                'session_id': str(session.id),
                'user_id': session.user.id,
                'timestamp': timezone.now().isoformat(),
                'message': self._get_warning_message(warning_type)
            }
            
            cache.set(f"session_warning_{session.id}", warning_data, 3600)  # 1 hour
            
            logger.info(f"Sent {warning_type} warning for session {session.id}")
            
        except Exception as e:
            logger.error(f"Error sending session warning: {str(e)}")
    
    def _get_warning_message(self, warning_type):
        """
        Get warning message for different warning types
        """
        messages = {
            'max_duration_exceeded': 'Your session has exceeded the maximum duration and will be terminated.',
            'approaching_limit': 'Your session is approaching the maximum duration limit.',
            'suspicious_activity': 'Unusual session activity detected.',
        }
        return messages.get(warning_type, 'Session warning')
    
    def _start_validation_thread(self):
        """
        Start background validation thread
        """
        self._validation_thread = threading.Thread(target=self._validation_worker, daemon=True)
        self._validation_thread.start()
        logger.info("Session validation thread started")
    
    def _validation_worker(self):
        """
        Background worker for periodic session validation
        """
        while not self._shutdown_event.is_set():
            try:
                self._validate_all_tracked_sessions()
                self._cleanup_old_tracking_data()
                
                # Sleep for validation interval
                self._shutdown_event.wait(self.config['validation_interval'])
                
            except Exception as e:
                logger.error(f"Error in session validation worker: {str(e)}")
                self._shutdown_event.wait(30)
    
    def _validate_all_tracked_sessions(self):
        """
        Validate all currently tracked sessions
        """
        with self._tracking_lock:
            session_ids = list(self._session_tracking.keys())
        
        for session_id in session_ids:
            try:
                tracking_info = self._session_tracking.get(session_id)
                if tracking_info and tracking_info['status'] == 'active':
                    # Refresh session from database
                    session = tracking_info['session']
                    session.refresh_from_db()
                    
                    # Validate session
                    self.validate_session(session)
                    
            except Exception as e:
                logger.error(f"Error validating tracked session {session_id}: {str(e)}")
    
    def _cleanup_old_tracking_data(self):
        """
        Clean up old tracking data
        """
        cutoff_time = timezone.now() - timedelta(hours=24)
        
        with self._tracking_lock:
            expired_sessions = [
                session_id for session_id, tracking_info in self._session_tracking.items()
                if tracking_info['last_validation'] < cutoff_time
            ]
            
            for session_id in expired_sessions:
                del self._session_tracking[session_id]
        
        if expired_sessions:
            logger.debug(f"Cleaned up {len(expired_sessions)} old session tracking records")
    
    def get_validation_stats(self):
        """
        Get validation statistics
        """
        with self._stats_lock:
            stats = self._stats.copy()
        
        with self._tracking_lock:
            stats['currently_tracked'] = len(self._session_tracking)
            stats['active_sessions'] = len([
                t for t in self._session_tracking.values() 
                if t['status'] == 'active'
            ])
        
        return stats
    
    def unregister_session(self, session_id):
        """
        Unregister a session from validation tracking
        """
        with self._tracking_lock:
            if session_id in self._session_tracking:
                del self._session_tracking[session_id]
                logger.debug(f"Unregistered session {session_id} from validation")
    
    def force_validate_session(self, session_id):
        """
        Force immediate validation of a specific session
        """
        tracking_info = self._session_tracking.get(session_id)
        if tracking_info:
            return self.validate_session(tracking_info['session'])
        else:
            logger.warning(f"Session {session_id} not found in tracking data")
            return {
                'valid': False,
                'duration': 0,
                'action': 'not_tracked',
                'message': 'Session not found in tracking data'
            }
    
    def shutdown(self):
        """
        Graceful shutdown
        """
        logger.info("Shutting down Session Duration Validator...")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Wait for validation thread
        if self._validation_thread and self._validation_thread.is_alive():
            self._validation_thread.join(timeout=30)
        
        logger.info("Session Duration Validator shutdown complete")

# Global instance
_session_validator_instance = None

def get_session_validator():
    """
    Get singleton session validator instance
    """
    global _session_validator_instance
    if _session_validator_instance is None:
        _session_validator_instance = SessionDurationValidator()
    return _session_validator_instance