import threading
import time
import logging
from datetime import datetime, timedelta
from django.core.cache import cache
from django.db import transaction, IntegrityError
from django.utils import timezone
from django.conf import settings
import json
import uuid
import hashlib

logger = logging.getLogger(__name__)

class EnhancedSessionManager:
    """
    Enhanced session manager with:
    - Race condition prevention using database locks
    - Advanced caching strategies
    - Request deduplication
    - Session duration validation
    - Real-time monitoring
    """
    
    def __init__(self):
        # Configuration
        self.config = {
            'session_timeout': getattr(settings, 'SESSION_TIMEOUT', 1800),  # 30 minutes
            'min_session_duration': getattr(settings, 'MIN_SESSION_DURATION', 5),  # 5 seconds
            'max_concurrent_sessions': getattr(settings, 'MAX_CONCURRENT_SESSIONS', 10),
            'cache_timeout': getattr(settings, 'SESSION_CACHE_TIMEOUT', 300),  # 5 minutes
            'lock_timeout': getattr(settings, 'SESSION_LOCK_TIMEOUT', 10),  # 10 seconds
            'duplicate_window': getattr(settings, 'SESSION_DUPLICATE_WINDOW', 1000),  # 1 second
        }
        
        # Thread-safe locks for session creation
        self._creation_locks = {}
        self._locks_lock = threading.RLock()
        
        # Request deduplication cache
        self._request_cache = {}
        self._request_cache_lock = threading.RLock()
        
        # Performance metrics
        self._metrics = {
            'sessions_created': 0,
            'sessions_reused': 0,
            'race_conditions_prevented': 0,
            'duplicate_requests_blocked': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'lock_timeouts': 0,
            'validation_failures': 0
        }
        self._metrics_lock = threading.RLock()
        
        logger.info("Enhanced Session Manager initialized with config: %s", self.config)
    
    def get_or_create_session(self, user, tab_id=None, parent_session_id=None, client_data=None, **kwargs):
        """
        Get or create session with race condition prevention and enhanced validation
        """
        start_time = time.time()
        
        try:
            # Generate unique request identifier for deduplication
            request_hash = self._generate_request_hash(user.id, tab_id, parent_session_id, client_data)
            
            # Check for duplicate request
            if self._is_duplicate_request(request_hash):
                with self._metrics_lock:
                    self._metrics['duplicate_requests_blocked'] += 1
                logger.debug(f"Duplicate request blocked for user {user.username}")
                return self._get_cached_result(request_hash)
            
            # Try cache first for existing sessions
            cache_result = self._get_cached_session(user, tab_id, parent_session_id, client_data)
            if cache_result:
                with self._metrics_lock:
                    self._metrics['cache_hits'] += 1
                    self._metrics['sessions_reused'] += 1
                logger.debug(f"Session found in cache for user {user.username}")
                return cache_result, False
            
            with self._metrics_lock:
                self._metrics['cache_misses'] += 1
            
            # Use lock for thread-safe session creation
            lock_key = f"session_creation_{user.id}_{tab_id or 'default'}"
            
            with self._get_creation_lock(lock_key):
                # Double-check cache after acquiring lock
                cache_result = self._get_cached_session(user, tab_id, parent_session_id, client_data)
                if cache_result:
                    with self._metrics_lock:
                        self._metrics['sessions_reused'] += 1
                    return cache_result, False
                
                # Create new session with database-level race condition prevention
                session, created = self._create_session_with_lock(
                    user, tab_id, parent_session_id, client_data, **kwargs
                )
                
                if created:
                    with self._metrics_lock:
                        self._metrics['sessions_created'] += 1
                    logger.info(f"Created new session {session.id} for user {user.username}")
                else:
                    with self._metrics_lock:
                        self._metrics['sessions_reused'] += 1
                        self._metrics['race_conditions_prevented'] += 1
                    logger.debug(f"Reused existing session {session.id} for user {user.username}")
                
                # Cache the result
                self._cache_session_result(user, tab_id, parent_session_id, client_data, session)
                
                # Store result for deduplication
                self._store_request_result(request_hash, session)
                
                processing_time = time.time() - start_time
                logger.debug(f"Session processing completed in {processing_time:.3f}s")
                
                return session, created
                
        except Exception as e:
            logger.error(f"Error in get_or_create_session for user {user.username}: {str(e)}")
            raise
    
    def _generate_request_hash(self, user_id, tab_id, parent_session_id, client_data):
        """
        Generate unique hash for request deduplication
        """
        request_data = {
            'user_id': user_id,
            'tab_id': tab_id,
            'parent_session_id': str(parent_session_id) if parent_session_id else None,
            'fingerprint': client_data.get('session_fingerprint') if client_data else None,
            'timestamp': int(time.time() * 1000)  # millisecond precision
        }
        
        request_string = json.dumps(request_data, sort_keys=True)
        return hashlib.md5(request_string.encode()).hexdigest()
    
    def _is_duplicate_request(self, request_hash):
        """
        Check if request is a duplicate within the window
        """
        current_time = time.time() * 1000  # milliseconds
        
        with self._request_cache_lock:
            # Clean old entries
            self._cleanup_request_cache(current_time)
            
            # Check for duplicate
            if request_hash in self._request_cache:
                last_time = self._request_cache[request_hash]['timestamp']
                if current_time - last_time < self.config['duplicate_window']:
                    return True
            
            # Store current request
            self._request_cache[request_hash] = {
                'timestamp': current_time,
                'result': None
            }
            
            return False
    
    def _cleanup_request_cache(self, current_time):
        """
        Clean old entries from request cache
        """
        cutoff_time = current_time - (self.config['duplicate_window'] * 10)  # Keep 10x window
        
        expired_keys = [
            key for key, data in self._request_cache.items()
            if data['timestamp'] < cutoff_time
        ]
        
        for key in expired_keys:
            del self._request_cache[key]
    
    def _get_cached_result(self, request_hash):
        """
        Get cached result for duplicate request
        """
        with self._request_cache_lock:
            cached_data = self._request_cache.get(request_hash, {})
            return cached_data.get('result')
    
    def _store_request_result(self, request_hash, result):
        """
        Store result for future duplicate requests
        """
        with self._request_cache_lock:
            if request_hash in self._request_cache:
                self._request_cache[request_hash]['result'] = result
    
    def _get_cached_session(self, user, tab_id, parent_session_id, client_data):
        """
        Get session from cache with multiple lookup strategies
        """
        cache_keys = self._generate_cache_keys(user, tab_id, parent_session_id, client_data)
        
        for cache_key in cache_keys:
            session = cache.get(cache_key)
            if session and self._validate_cached_session(session):
                # Update session activity
                session.last_activity = timezone.now()
                session.save(update_fields=['last_activity'])
                return session
        
        return None
    
    def _generate_cache_keys(self, user, tab_id, parent_session_id, client_data):
        """
        Generate multiple cache keys for session lookup
        """
        keys = []
        
        # Primary key by tab_id
        if tab_id:
            keys.append(f"session_tab_{user.id}_{tab_id}")
        
        # Key by parent_session_id and fingerprint
        if parent_session_id and client_data:
            fingerprint = client_data.get('session_fingerprint')
            if fingerprint:
                keys.append(f"session_parent_{user.id}_{parent_session_id}_{fingerprint}")
        
        # Key by fingerprint only
        if client_data:
            fingerprint = client_data.get('session_fingerprint')
            if fingerprint:
                keys.append(f"session_fingerprint_{user.id}_{fingerprint}")
        
        # Fallback key by user
        keys.append(f"session_user_{user.id}")
        
        return keys
    
    def _validate_cached_session(self, session):
        """
        Validate that cached session is still valid
        """
        if not session or not session.is_active:
            return False
        
        # Check session timeout
        if session.last_activity:
            time_diff = (timezone.now() - session.last_activity).total_seconds()
            if time_diff > self.config['session_timeout']:
                return False
        
        return True
    
    def _cache_session_result(self, user, tab_id, parent_session_id, client_data, session):
        """
        Cache session with multiple keys for efficient lookup
        """
        cache_keys = self._generate_cache_keys(user, tab_id, parent_session_id, client_data)
        
        for cache_key in cache_keys:
            cache.set(cache_key, session, self.config['cache_timeout'])
        
        # Also cache by session ID
        cache.set(f"session_obj_{session.id}", session, self.config['cache_timeout'])
    
    def _get_creation_lock(self, lock_key):
        """
        Get thread-safe creation lock
        """
        with self._locks_lock:
            if lock_key not in self._creation_locks:
                self._creation_locks[lock_key] = threading.RLock()
            return self._creation_locks[lock_key]
    
    def _create_session_with_lock(self, user, tab_id, parent_session_id, client_data, **kwargs):
        """
        Create session with database-level race condition prevention
        """
        # Import here to avoid circular imports
        from trueAlign.models import UserSession
        
        max_attempts = 3
        attempt = 0
        
        while attempt < max_attempts:
            try:
                with transaction.atomic():
                    # First, try to find existing session with SELECT FOR UPDATE
                    existing_session = None
                    
                    if tab_id:
                        try:
                            existing_session = UserSession.objects.select_for_update().get(
                                user=user, tab_id=tab_id, is_active=True
                            )
                        except UserSession.DoesNotExist:
                            pass
                    
                    # If found existing, update and return
                    if existing_session:
                        if self._validate_session_duration(existing_session):
                            existing_session.last_activity = timezone.now()
                            existing_session.save(update_fields=['last_activity'])
                            return existing_session, False
                        else:
                            # End invalid session
                            self._end_invalid_session(existing_session)
                    
                    # Check for session by parent_session_id and fingerprint
                    if parent_session_id and client_data:
                        fingerprint = client_data.get('session_fingerprint')
                        if fingerprint:
                            try:
                                existing_session = UserSession.objects.select_for_update().get(
                                    user=user,
                                    parent_session_id=parent_session_id,
                                    session_fingerprint=fingerprint,
                                    is_active=True
                                )
                                if self._validate_session_duration(existing_session):
                                    existing_session.last_activity = timezone.now()
                                    existing_session.save(update_fields=['last_activity'])
                                    return existing_session, False
                                else:
                                    self._end_invalid_session(existing_session)
                            except UserSession.DoesNotExist:
                                pass
                    
                    # Clean up old sessions before creating new one
                    self._cleanup_old_sessions(user)
                    
                    # Validate session limits
                    if not self._validate_session_limits(user):
                        raise ValueError(f"User {user.username} has too many active sessions")
                    
                    # Create new session
                    session_data = self._prepare_session_data(user, tab_id, parent_session_id, client_data, **kwargs)
                    
                    new_session = UserSession.objects.create(**session_data)
                    logger.info(f"Created new session {new_session.id} for user {user.username}")
                    
                    return new_session, True
                    
            except IntegrityError as e:
                attempt += 1
                logger.warning(f"Race condition detected for user {user.username}, attempt {attempt}: {str(e)}")
                
                if attempt >= max_attempts:
                    # Fall back to finding existing session
                    try:
                        if tab_id:
                            existing_session = UserSession.objects.get(
                                user=user, tab_id=tab_id, is_active=True
                            )
                            return existing_session, False
                    except UserSession.DoesNotExist:
                        pass
                    
                    raise ValueError(f"Failed to create session after {max_attempts} attempts")
                
                # Wait before retry
                time.sleep(0.1 * attempt)
            
            except Exception as e:
                logger.error(f"Unexpected error creating session for user {user.username}: {str(e)}")
                raise
    
    def _validate_session_duration(self, session):
        """
        Validate session has minimum duration using session validator
        """
        try:
            from . import get_session_validator
            validator = get_session_validator()
            if validator:
                return validator.validate_session(session)
        except ImportError:
            pass
        
        # Fallback validation
        if not session.created_at:
            return True
        
        duration = (timezone.now() - session.created_at).total_seconds()
        
        # If session is too short and not active, it might be invalid
        if duration < self.config['min_session_duration'] and not session.last_activity:
            with self._metrics_lock:
                self._metrics['validation_failures'] += 1
            return False
        
        return True
    
    def _end_invalid_session(self, session):
        """
        End invalid session
        """
        session.is_active = False
        session.ended_at = timezone.now()
        session.end_reason = 'validation_failure'
        session.save(update_fields=['is_active', 'ended_at', 'end_reason'])
        logger.info(f"Ended invalid session {session.id}")
    
    def _cleanup_old_sessions(self, user):
        """
        Clean up old inactive sessions
        """
        cutoff_time = timezone.now() - timedelta(hours=24)
        
        old_sessions = user.sessions.filter(
            is_active=True,
            last_activity__lt=cutoff_time
        )
        
        count = old_sessions.update(
            is_active=False,
            ended_at=timezone.now(),
            end_reason='auto_cleanup'
        )
        
        if count > 0:
            logger.info(f"Cleaned up {count} old sessions for user {user.username}")
    
    def _validate_session_limits(self, user):
        """
        Validate user doesn't exceed concurrent session limits
        """
        active_count = user.sessions.filter(is_active=True).count()
        
        if active_count >= self.config['max_concurrent_sessions']:
            # End oldest session
            oldest_session = user.sessions.filter(is_active=True).order_by('last_activity').first()
            if oldest_session:
                self._end_invalid_session(oldest_session)
                logger.info(f"Ended oldest session for user {user.username} due to session limit")
        
        return True
    
    def _prepare_session_data(self, user, tab_id, parent_session_id, client_data, **kwargs):
        """
        Prepare session data for creation
        """
        from trueAlign.models import UserSession
        
        session_data = {
            'user': user,
            'tab_id': tab_id,
            'parent_session_id': parent_session_id or uuid.uuid4(),
            'session_key': UserSession.generate_session_key(),
            'is_primary_tab': True,
            'login_time': timezone.now(),
            'last_activity': timezone.now(),
            **kwargs
        }
        
        # Add client data if available
        if client_data:
            session_data.update({
                'session_fingerprint': client_data.get('session_fingerprint'),
                'ip_address': client_data.get('ip_address'),
                'user_agent': client_data.get('user_agent'),
                'browser_fingerprint': client_data.get('browser_fingerprint'),
                'device_type': client_data.get('device_type'),
                'screen_resolution': client_data.get('screen_resolution'),
                'timezone_offset': client_data.get('timezone_offset'),
                'language': client_data.get('language'),
            })
        
        return session_data
    
    def invalidate_session_cache(self, session):
        """
        Invalidate all cache entries for a session
        """
        user = session.user
        tab_id = session.tab_id
        parent_session_id = session.parent_session_id
        
        # Create dummy client_data for cache key generation
        client_data = {
            'session_fingerprint': session.session_fingerprint
        }
        
        cache_keys = self._generate_cache_keys(user, tab_id, parent_session_id, client_data)
        cache_keys.append(f"session_obj_{session.id}")
        
        for cache_key in cache_keys:
            cache.delete(cache_key)
        
        logger.debug(f"Invalidated cache for session {session.id}")
    
    def end_session(self, session, reason='user_logout'):
        """
        End session with proper cleanup and cache invalidation
        """
        session.is_active = False
        session.ended_at = timezone.now()
        session.logout_time = timezone.now()
        session.end_reason = reason
        session.save(update_fields=['is_active', 'ended_at', 'logout_time', 'end_reason'])
        
        # Invalidate cache
        self.invalidate_session_cache(session)
        
        logger.info(f"Ended session {session.id} with reason: {reason}")
    
    def get_metrics(self):
        """
        Get performance metrics
        """
        with self._metrics_lock:
            metrics = self._metrics.copy()
        
        # Add additional stats
        with self._request_cache_lock:
            metrics['request_cache_size'] = len(self._request_cache)
        
        with self._locks_lock:
            metrics['active_locks'] = len(self._creation_locks)
        
        return metrics
    
    def reset_metrics(self):
        """
        Reset performance metrics
        """
        with self._metrics_lock:
            for key in self._metrics:
                if key != 'last_reset':
                    self._metrics[key] = 0
            self._metrics['last_reset'] = time.time()

# Global instance
_session_manager_instance = None

def get_session_manager():
    """
    Get singleton session manager instance
    """
    global _session_manager_instance
    if _session_manager_instance is None:
        _session_manager_instance = EnhancedSessionManager()
    return _session_manager_instance