"""
Session Tracking Configuration
Optimized for GoDaddy shared hosting environment
"""

import os
from datetime import timedelta
from django.conf import settings

# Base configuration class
class SessionTrackingConfig:
    """
    Configuration for optimized session tracking system
    Designed for shared hosting environments with limited resources
    """

    # =============================================================================
    # THROTTLING CONFIGURATION
    # =============================================================================

    # Middleware throttling intervals (in seconds)
    MIDDLEWARE_THROTTLE_INTERVAL = 10 * 60  # 10 minutes
    HEARTBEAT_THROTTLE_INTERVAL = 30        # 30 seconds
    ACTIVITY_THROTTLE_INTERVAL = 60         # 1 minute
    SESSION_CHECK_THROTTLE = 2 * 60         # 2 minutes

    # Frontend throttling intervals (in milliseconds)
    FRONTEND_HEARTBEAT_INTERVAL = 30000     # 30 seconds
    FRONTEND_BATCH_FLUSH_INTERVAL = 5 * 60 * 1000  # 5 minutes
    FRONTEND_ACTIVITY_THROTTLE = 60000      # 1 minute

    # =============================================================================
    # BUFFER CONFIGURATION
    # =============================================================================

    # Maximum buffer sizes (prevents memory issues)
    MAX_BUFFER_SIZE = 100
    MAX_CLICKS_BUFFER = 50
    MAX_SCROLLS_BUFFER = 30
    MAX_KEYBOARD_BUFFER = 100
    MAX_VISIBILITY_BUFFER = 20
    MAX_IDLE_STATES_BUFFER = 10
    MAX_PAGE_VIEWS_BUFFER = 20

    # Activity sampling rates (to reduce data volume)
    MOUSE_SAMPLE_RATE = 0.1      # Sample 10% of mouse movements
    SCROLL_SAMPLE_RATE = 0.3     # Sample 30% of scroll events
    KEYBOARD_SAMPLE_RATE = 0.8   # Sample 80% of keyboard events

    # Buffer flush thresholds
    BUFFER_FLUSH_THRESHOLD = 80  # Flush when buffer is 80% full
    FORCE_FLUSH_THRESHOLD = 95   # Force flush when buffer is 95% full

    # =============================================================================
    # CACHE CONFIGURATION
    # =============================================================================

    # Cache timeouts (in seconds)
    SESSION_CACHE_TIMEOUT = 5 * 60          # 5 minutes
    STATUS_CACHE_TIMEOUT = 30               # 30 seconds
    HEARTBEAT_CACHE_TIMEOUT = 30            # 30 seconds
    ANALYTICS_CACHE_TIMEOUT = 10 * 60       # 10 minutes
    AUTH_STATUS_CACHE_TIMEOUT = 5 * 60      # 5 minutes

    # Cache key prefixes
    SESSION_CACHE_PREFIX = 'opt_session'
    STATUS_CACHE_PREFIX = 'opt_status'
    HEARTBEAT_CACHE_PREFIX = 'opt_heartbeat'
    ANALYTICS_CACHE_PREFIX = 'opt_analytics'
    THROTTLE_CACHE_PREFIX = 'opt_throttle'

    # =============================================================================
    # SESSION MANAGEMENT
    # =============================================================================

    # Session timeout configuration
    SESSION_TIMEOUT_MINUTES = 30
    SESSION_WARNING_MINUTES = 25
    SESSION_EXTEND_MINUTES = 5

    # Auto-logout configuration
    AUTO_LOGOUT_ENABLED = True
    AUTO_LOGOUT_IDLE_MINUTES = 30
    SHOW_IDLE_WARNING = True
    IDLE_WARNING_MINUTES = 25

    # Session cleanup
    CLEANUP_INTERVAL = 5 * 60               # 5 minutes
    CLEANUP_OLD_SESSIONS_DAYS = 30          # 30 days

    # =============================================================================
    # PERFORMANCE MONITORING
    # =============================================================================

    # Performance metrics collection
    COLLECT_PERFORMANCE_METRICS = True
    PERFORMANCE_SAMPLE_RATE = 0.1           # Sample 10% of requests

    # Memory monitoring
    MEMORY_THRESHOLD_MB = 100               # Alert if memory usage > 100MB
    BUFFER_MEMORY_LIMIT_MB = 50             # Limit buffer memory usage

    # Request monitoring
    MAX_REQUEST_TIME_MS = 5000              # Alert if request > 5 seconds
    MAX_DB_QUERIES_PER_REQUEST = 10         # Alert if > 10 queries per request

    # =============================================================================
    # RETRY AND ERROR HANDLING
    # =============================================================================

    # Retry configuration
    MAX_RETRY_ATTEMPTS = 3
    RETRY_DELAY_SECONDS = 30
    RETRY_BACKOFF_MULTIPLIER = 2

    # Error handling
    LOG_FAILED_REQUESTS = True
    LOG_SLOW_REQUESTS = True
    LOG_BUFFER_OVERFLOWS = True

    # Graceful degradation
    FALLBACK_TO_BASIC_TRACKING = True
    DISABLE_ON_HIGH_LOAD = True
    LOAD_THRESHOLD_PERCENT = 80

    # =============================================================================
    # DATABASE OPTIMIZATION
    # =============================================================================

    # Query optimization
    USE_SELECT_RELATED = True
    USE_PREFETCH_RELATED = True
    USE_ONLY_FIELDS = True

    # Batch operations
    BATCH_SIZE = 100
    USE_BULK_CREATE = True
    USE_BULK_UPDATE = True

    # Connection pooling (if available)
    USE_CONNECTION_POOLING = getattr(settings, 'USE_CONNECTION_POOLING', False)

    # =============================================================================
    # SHARED HOSTING OPTIMIZATIONS
    # =============================================================================

    # CPU usage optimization
    REDUCE_CPU_INTENSIVE_OPERATIONS = True
    LIMIT_CONCURRENT_SESSIONS = 100

    # Memory usage optimization
    OPTIMIZE_MEMORY_USAGE = True
    CLEAR_BUFFERS_FREQUENTLY = True

    # Disk I/O optimization
    MINIMIZE_DISK_WRITES = True
    BATCH_DISK_OPERATIONS = True

    # =============================================================================
    # LOGGING CONFIGURATION
    # =============================================================================

    # Log levels
    LOG_LEVEL = getattr(settings, 'LOG_LEVEL', 'INFO')

    # Log categories
    LOG_CATEGORIES = {
        'session_creation': True,
        'session_updates': False,      # Disabled to reduce logs
        'heartbeat': False,            # Disabled to reduce logs
        'buffer_flushes': True,
        'errors': True,
        'performance': True,
        'security': True,
        'cleanup': True
    }

    # Log formatting
    LOG_FORMAT = '[%(asctime)s] %(levelname)s [%(name)s] %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

    # =============================================================================
    # SECURITY CONFIGURATION
    # =============================================================================

    # Security checks
    ENABLE_SECURITY_CHECKS = True
    CHECK_IP_CHANGES = True
    CHECK_USER_AGENT_CHANGES = True
    CHECK_SUSPICIOUS_ACTIVITY = True

    # Rate limiting
    ENABLE_RATE_LIMITING = True
    RATE_LIMIT_REQUESTS_PER_MINUTE = 60
    RATE_LIMIT_BURST_SIZE = 10

    # Fingerprinting
    ENABLE_BROWSER_FINGERPRINTING = True
    FINGERPRINT_CACHE_TIMEOUT = 24 * 60 * 60  # 24 hours

    # =============================================================================
    # ENVIRONMENT-SPECIFIC SETTINGS
    # =============================================================================

    @classmethod
    def get_environment_config(cls):
        """Get configuration based on environment"""
        env = getattr(settings, 'ENVIRONMENT', 'production')

        if env == 'development':
            return cls.get_development_config()
        elif env == 'staging':
            return cls.get_staging_config()
        else:
            return cls.get_production_config()

    @classmethod
    def get_development_config(cls):
        """Development environment configuration"""
        config = cls()

        # More aggressive throttling in development
        config.MIDDLEWARE_THROTTLE_INTERVAL = 5 * 60  # 5 minutes
        config.HEARTBEAT_THROTTLE_INTERVAL = 15       # 15 seconds

        # Smaller buffers for testing
        config.MAX_BUFFER_SIZE = 50

        # More detailed logging
        config.LOG_CATEGORIES.update({
            'session_updates': True,
            'heartbeat': True
        })

        # Disable some optimizations for debugging
        config.REDUCE_CPU_INTENSIVE_OPERATIONS = False
        config.COLLECT_PERFORMANCE_METRICS = True

        return config

    @classmethod
    def get_staging_config(cls):
        """Staging environment configuration"""
        config = cls()

        # Moderate throttling
        config.MIDDLEWARE_THROTTLE_INTERVAL = 8 * 60  # 8 minutes
        config.HEARTBEAT_THROTTLE_INTERVAL = 20       # 20 seconds

        # Enable most optimizations
        config.REDUCE_CPU_INTENSIVE_OPERATIONS = True
        config.OPTIMIZE_MEMORY_USAGE = True

        return config

    @classmethod
    def get_production_config(cls):
        """Production environment configuration (GoDaddy shared hosting)"""
        config = cls()

        # Maximum throttling for shared hosting
        config.MIDDLEWARE_THROTTLE_INTERVAL = 15 * 60  # 15 minutes
        config.HEARTBEAT_THROTTLE_INTERVAL = 60        # 60 seconds
        config.ACTIVITY_THROTTLE_INTERVAL = 2 * 60     # 2 minutes

        # Larger buffers to reduce database writes
        config.MAX_BUFFER_SIZE = 200
        config.FRONTEND_BATCH_FLUSH_INTERVAL = 10 * 60 * 1000  # 10 minutes

        # Aggressive caching
        config.SESSION_CACHE_TIMEOUT = 10 * 60         # 10 minutes
        config.STATUS_CACHE_TIMEOUT = 60               # 1 minute

        # Enable all optimizations
        config.REDUCE_CPU_INTENSIVE_OPERATIONS = True
        config.OPTIMIZE_MEMORY_USAGE = True
        config.MINIMIZE_DISK_WRITES = True
        config.BATCH_DISK_OPERATIONS = True

        # Conservative logging
        config.LOG_CATEGORIES.update({
            'session_updates': False,
            'heartbeat': False,
            'buffer_flushes': False
        })

        # Higher thresholds for alerts
        config.MEMORY_THRESHOLD_MB = 200
        config.MAX_REQUEST_TIME_MS = 10000

        return config

    # =============================================================================
    # FEATURE FLAGS
    # =============================================================================

    # Feature toggles
    ENABLE_ANALYTICS = True
    ENABLE_PRODUCTIVITY_SCORING = True
    ENABLE_ENGAGEMENT_SCORING = True
    ENABLE_LOCATION_TRACKING = True
    ENABLE_DEVICE_TRACKING = True
    ENABLE_PERFORMANCE_TRACKING = True
    ENABLE_CROSS_TAB_TRACKING = True

    # Advanced features (may impact performance)
    ENABLE_ADVANCED_ANALYTICS = False
    ENABLE_REAL_TIME_SCORING = False
    ENABLE_DETAILED_MOUSE_TRACKING = False

    # =============================================================================
    # INTEGRATION SETTINGS
    # =============================================================================

    # External integrations
    ENABLE_GEOLOCATION_API = False  # Disabled for shared hosting
    ENABLE_WEATHER_API = False      # Disabled for shared hosting
    ENABLE_THIRD_PARTY_ANALYTICS = False

    # Internal integrations
    ENABLE_ATTENDANCE_INTEGRATION = True
    ENABLE_NOTIFICATION_SYSTEM = True
    ENABLE_REPORTING_SYSTEM = True

    # =============================================================================
    # UTILITY METHODS
    # =============================================================================

    @classmethod
    def get_cache_key(cls, prefix, *args):
        """Generate cache key with prefix"""
        return f"{prefix}:{'_'.join(str(arg) for arg in args)}"

    @classmethod
    def get_throttle_key(cls, user_id, action, *args):
        """Generate throttle key"""
        return cls.get_cache_key(
            cls.THROTTLE_CACHE_PREFIX,
            action,
            user_id,
            *args
        )

    @classmethod
    def should_sample(cls, sample_rate):
        """Determine if an event should be sampled"""
        import random
        return random.random() < sample_rate

    @classmethod
    def get_buffer_limit(cls, buffer_type):
        """Get buffer limit for specific type"""
        limits = {
            'clicks': cls.MAX_CLICKS_BUFFER,
            'scrolls': cls.MAX_SCROLLS_BUFFER,
            'keyboard': cls.MAX_KEYBOARD_BUFFER,
            'visibility': cls.MAX_VISIBILITY_BUFFER,
            'idle_states': cls.MAX_IDLE_STATES_BUFFER,
            'page_views': cls.MAX_PAGE_VIEWS_BUFFER
        }
        return limits.get(buffer_type, cls.MAX_BUFFER_SIZE)

    @classmethod
    def is_feature_enabled(cls, feature_name):
        """Check if a feature is enabled"""
        return getattr(cls, f'ENABLE_{feature_name.upper()}', False)

    @classmethod
    def should_log_category(cls, category):
        """Check if a log category should be logged"""
        return cls.LOG_CATEGORIES.get(category, False)


# Environment-specific configuration instance
CONFIG = SessionTrackingConfig.get_environment_config()

# Export commonly used values
THROTTLE_INTERVAL = CONFIG.MIDDLEWARE_THROTTLE_INTERVAL
HEARTBEAT_INTERVAL = CONFIG.HEARTBEAT_THROTTLE_INTERVAL
MAX_BUFFER_SIZE = CONFIG.MAX_BUFFER_SIZE
SESSION_TIMEOUT = CONFIG.SESSION_TIMEOUT_MINUTES
CACHE_TIMEOUT = CONFIG.SESSION_CACHE_TIMEOUT
