# Session Tracking Optimization Settings
# Add these to your main settings.py or import this file

import logging

# Enhanced Batch Writer Configuration
BATCH_WRITER_BATCH_SIZE = 50
BATCH_WRITER_FLUSH_INTERVAL = 300  # 5 minutes
BATCH_WRITER_MAX_BUFFER_SIZE = 1000
BATCH_WRITER_RETRY_ATTEMPTS = 3
BATCH_WRITER_RETRY_DELAY = 30
BATCH_WRITER_ENABLE_COMPRESSION = True
BATCH_WRITER_ENABLE_METRICS = True

# Session Manager Configuration
SESSION_TIMEOUT = 1800  # 30 minutes
MIN_SESSION_DURATION = 10  # 10 seconds
MAX_SESSION_DURATION = 43200  # 12 hours
MAX_CONCURRENT_SESSIONS = 10
SESSION_CACHE_TIMEOUT = 300  # 5 minutes
SESSION_LOCK_TIMEOUT = 10  # 10 seconds
SESSION_DUPLICATE_WINDOW = 1000  # 1 second (milliseconds)

# Location Synchronization Configuration
LOCATION_SYNC_INTERVAL = 60  # 1 minute
LOCATION_MAX_ACCURACY = 1000  # 1km (meters)
LOCATION_MIN_ACCURACY = 10  # 10m (meters)
LOCATION_TIMEOUT = 3600  # 1 hour
LOCATION_MAX_HISTORY = 100
LOCATION_ENABLE_VALIDATION = True
LOCATION_BATCH_SIZE = 50

# Enhanced Logging Configuration
SESSION_LOG_LEVEL = logging.INFO
SESSION_LOG_BUFFER_SIZE = 1000
SESSION_ALERT_THRESHOLD = 10
SESSION_ANOMALY_WINDOW = 300  # 5 minutes
SESSION_ENABLE_ALERTS = True
SESSION_LOG_FILE = 'logs/session_tracking.log'

# Session Validation Configuration
SESSION_VALIDATION_INTERVAL = 300  # 5 minutes
SESSION_GRACE_PERIOD = 5  # 5 seconds
SESSION_AUTO_EXTEND_THRESHOLD = 30  # 30 seconds
SESSION_SUSPICIOUS_THRESHOLD = 3  # 3 seconds

# Activity Tracking Configuration
ACTIVITY_THROTTLE_INTERVAL = 30  # 30 seconds
ACTIVITY_BATCH_SIZE = 50
ACTIVITY_MAX_RETRIES = 3

# Middleware Configuration
SESSION_MIDDLEWARE_ENABLED = True
SESSION_MIDDLEWARE_EXEMPT_PATHS = [
    '/admin/', '/static/', '/media/', '/favicon.ico',
    '/robots.txt', '/sitemap.xml', '/.well-known/'
]

# Performance Monitoring
ENABLE_SESSION_PERFORMANCE_MONITORING = True
ENABLE_SESSION_ANALYTICS = True

# Security Configuration
ENABLE_SESSION_FINGERPRINTING = True
ENABLE_SUSPICIOUS_ACTIVITY_DETECTION = True

# Cache Configuration (recommended)
# Ensure you have Redis or similar cache backend configured
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'OPTIONS': {
            'MAX_ENTRIES': 10000,
            'CULL_FREQUENCY': 10,
        }
    }
}

# For production, use Redis:
# CACHES = {
#     'default': {
#         'BACKEND': 'django_redis.cache.RedisCache',
#         'LOCATION': 'redis://localhost:6379/1',
#         'OPTIONS': {
#             'CLIENT_CLASS': 'django_redis.client.DefaultClient',
#         }
#     }
# }