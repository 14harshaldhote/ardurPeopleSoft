default_app_config = 'trueAlign.core.apps.CoreConfig'

# Factory functions for enhanced session components
# These help avoid circular imports and provide fallback behavior

_session_manager = None
_batch_writer = None
_session_logger = None
_location_synchronizer = None
_session_validator = None

def get_session_manager():
    """Get or create enhanced session manager instance"""
    global _session_manager
    if _session_manager is None:
        try:
            from .session_manager import EnhancedSessionManager
            _session_manager = EnhancedSessionManager()
        except ImportError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Enhanced session manager not available: {e}")
            _session_manager = None
    return _session_manager

def get_batch_writer():
    """Get or create enhanced batch writer instance"""
    global _batch_writer
    if _batch_writer is None:
        try:
            from .optimized_batch_writer import EnhancedBatchWriter
            _batch_writer = EnhancedBatchWriter()
        except ImportError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Enhanced batch writer not available: {e}")
            _batch_writer = None
    return _batch_writer

def get_session_logger():
    """Get or create enhanced session logger instance"""
    global _session_logger
    if _session_logger is None:
        try:
            from .enhanced_logger import EnhancedSessionLogger
            _session_logger = EnhancedSessionLogger()
        except ImportError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Enhanced session logger not available: {e}")
            _session_logger = None
    return _session_logger

def get_location_synchronizer():
    """Get or create location synchronizer instance"""
    global _location_synchronizer
    if _location_synchronizer is None:
        try:
            from .location_sync import LocationDataSynchronizer
            _location_synchronizer = LocationDataSynchronizer()
        except ImportError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Location synchronizer not available: {e}")
            _location_synchronizer = None
    return _location_synchronizer

def get_session_validator():
    """Get or create session validator instance"""
    global _session_validator
    if _session_validator is None:
        try:
            from .session_validator import SessionDurationValidator
            _session_validator = SessionDurationValidator()
        except ImportError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Session validator not available: {e}")
            _session_validator = None
    return _session_validator

# Convenience function to reset all components (useful for testing)
def reset_session_components():
    """Reset all session components to force re-initialization"""
    global _session_manager, _batch_writer, _session_logger, _location_synchronizer, _session_validator
    _session_manager = None
    _batch_writer = None
    _session_logger = None
    _location_synchronizer = None
    _session_validator = None
