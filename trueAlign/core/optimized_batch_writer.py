import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from django.core.cache import cache
from django.db import transaction, connection
from django.utils import timezone
from django.conf import settings
import json
import uuid

logger = logging.getLogger(__name__)

class EnhancedBatchWriter:
    """
    Enhanced batch writing system for session activities with:
    - Configurable flush intervals
    - Memory-efficient buffering
    - Automatic retries
    - Performance monitoring
    - Real-time logging
    """
    
    def __init__(self):
        # Configuration
        self.config = {
            'batch_size': getattr(settings, 'BATCH_WRITER_BATCH_SIZE', 50),
            'flush_interval': getattr(settings, 'BATCH_WRITER_FLUSH_INTERVAL', 300),  # 5 minutes
            'max_buffer_size': getattr(settings, 'BATCH_WRITER_MAX_BUFFER_SIZE', 1000),
            'retry_attempts': getattr(settings, 'BATCH_WRITER_RETRY_ATTEMPTS', 3),
            'retry_delay': getattr(settings, 'BATCH_WRITER_RETRY_DELAY', 30),
            'enable_compression': getattr(settings, 'BATCH_WRITER_ENABLE_COMPRESSION', True),
            'enable_metrics': getattr(settings, 'BATCH_WRITER_ENABLE_METRICS', True),
        }
        
        # Thread-safe data structures
        self._buffer_lock = threading.RLock()
        self._metrics_lock = threading.RLock()
        
        # Activity buffers by user_id
        self._activity_buffers = defaultdict(lambda: {
            'session_activities': deque(maxlen=self.config['max_buffer_size']),
            'location_updates': deque(maxlen=50),
            'heartbeats': deque(maxlen=20),
            'last_flush': time.time(),
            'total_activities': 0,
            'failed_writes': 0
        })
        
        # Retry queue for failed writes
        self._retry_queue = deque(maxlen=500)
        
        # Performance metrics
        self._metrics = {
            'total_writes': 0,
            'successful_writes': 0,
            'failed_writes': 0,
            'avg_batch_size': 0,
            'avg_write_time': 0,
            'buffer_overflows': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'last_reset': time.time()
        }
        
        # Background thread management
        self._shutdown_event = threading.Event()
        self._flush_thread = None
        self._retry_thread = None
        
        # Start background threads
        self._start_background_threads()
        
        logger.info("Enhanced Batch Writer initialized with config: %s", self.config)
    
    def add_activity(self, user_id, session_id, activity_type, activity_data, location_data=None, url=None, title=None):
        """
        Add activity to buffer with enhanced validation and deduplication
        """
        try:
            with self._buffer_lock:
                buffer = self._activity_buffers[user_id]
                
                # Check buffer overflow
                if len(buffer['session_activities']) >= self.config['max_buffer_size']:
                    logger.warning(f"Buffer overflow for user {user_id}, forcing flush")
                    self._force_flush_user_buffer(user_id)
                    with self._metrics_lock:
                        self._metrics['buffer_overflows'] += 1
                
                # Create activity record
                activity_record = {
                    'session_id': session_id,
                    'activity_type': activity_type,
                    'activity_data': activity_data or {},
                    'location_data': location_data,
                    'url': url,
                    'title': title,
                    'timestamp': timezone.now().isoformat(),
                    'user_id': user_id,
                    'record_id': str(uuid.uuid4()),
                    'retry_count': 0
                }
                
                # Add deduplication check
                if not self._is_duplicate_activity(buffer, activity_record):
                    buffer['session_activities'].append(activity_record)
                    buffer['total_activities'] += 1
                    
                    # Handle location updates specially
                    if location_data:
                        buffer['location_updates'].append({
                            'session_id': session_id,
                            'location_data': location_data,
                            'timestamp': timezone.now().isoformat()
                        })
                    
                    # Handle heartbeats specially
                    if activity_type == 'heartbeat':
                        buffer['heartbeats'].append(activity_record)
                    
                    logger.debug(f"Added activity {activity_type} for user {user_id}, buffer size: {len(buffer['session_activities'])}")
                    
                    # Check if immediate flush is needed
                    self._check_immediate_flush(user_id, buffer)
                else:
                    logger.debug(f"Duplicate activity ignored for user {user_id}: {activity_type}")
                
        except Exception as e:
            logger.error(f"Error adding activity for user {user_id}: {str(e)}")
            self._add_to_retry_queue(user_id, session_id, activity_type, activity_data, location_data, url, title)
    
    def _is_duplicate_activity(self, buffer, new_activity):
        """
        Check if activity is a duplicate within a time window
        """
        if not buffer['session_activities']:
            return False
        
        # Check last few activities for duplicates
        check_count = min(5, len(buffer['session_activities']))
        recent_activities = list(buffer['session_activities'])[-check_count:]
        
        for activity in recent_activities:
            if (activity['activity_type'] == new_activity['activity_type'] and
                activity['session_id'] == new_activity['session_id']):
                
                # For heartbeats, check timestamp difference
                if new_activity['activity_type'] == 'heartbeat':
                    activity_time = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00'))
                    new_time = datetime.fromisoformat(new_activity['timestamp'].replace('Z', '+00:00'))
                    if abs((new_time - activity_time).total_seconds()) < 10:  # 10 second window
                        return True
                
                # For other activities, check data similarity
                elif activity['activity_data'] == new_activity['activity_data']:
                    activity_time = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00'))
                    new_time = datetime.fromisoformat(new_activity['timestamp'].replace('Z', '+00:00'))
                    if abs((new_time - activity_time).total_seconds()) < 5:  # 5 second window
                        return True
        
        return False
    
    def _check_immediate_flush(self, user_id, buffer):
        """
        Check if buffer should be flushed immediately
        """
        should_flush = False
        
        # Flush if buffer is getting full
        if len(buffer['session_activities']) >= self.config['batch_size']:
            should_flush = True
            logger.debug(f"Triggering flush for user {user_id}: batch size reached")
        
        # Flush if it's been too long since last flush
        elif time.time() - buffer['last_flush'] > self.config['flush_interval']:
            should_flush = True
            logger.debug(f"Triggering flush for user {user_id}: flush interval reached")
        
        # Flush if there are critical activities (location updates, errors)
        elif any(activity['activity_type'] in ['error', 'security_alert', 'session_end'] 
                for activity in buffer['session_activities']):
            should_flush = True
            logger.debug(f"Triggering flush for user {user_id}: critical activity detected")
        
        if should_flush:
            self._flush_user_buffer(user_id)
    
    def _flush_user_buffer(self, user_id):
        """
        Flush activities for a specific user
        """
        try:
            with self._buffer_lock:
                buffer = self._activity_buffers[user_id]
                
                if not buffer['session_activities']:
                    return
                
                # Get activities to flush
                activities_to_flush = list(buffer['session_activities'])
                location_updates = list(buffer['location_updates'])
                
                # Clear buffers
                buffer['session_activities'].clear()
                buffer['location_updates'].clear()
                buffer['last_flush'] = time.time()
            
            # Perform batch write
            success = self._perform_batch_write(user_id, activities_to_flush, location_updates)
            
            if success:
                logger.info(f"Successfully flushed {len(activities_to_flush)} activities for user {user_id}")
                with self._metrics_lock:
                    self._metrics['successful_writes'] += len(activities_to_flush)
            else:
                # Add failed activities to retry queue
                for activity in activities_to_flush:
                    self._add_to_retry_queue(
                        user_id, activity['session_id'], activity['activity_type'],
                        activity['activity_data'], activity['location_data'],
                        activity['url'], activity['title']
                    )
                
        except Exception as e:
            logger.error(f"Error flushing buffer for user {user_id}: {str(e)}")
    
    def _perform_batch_write(self, user_id, activities, location_updates):
        """
        Perform optimized batch database write
        """
        if not activities:
            return True
        
        start_time = time.time()
        
        try:
            from trueAlign.models import SessionActivity, UserSession
            
            with transaction.atomic():
                # Batch create session activities
                activity_objects = []
                session_updates = defaultdict(dict)
                
                for activity in activities:
                    try:
                        # Get session with caching
                        session = self._get_cached_session(activity['session_id'])
                        if not session:
                            logger.warning(f"Session {activity['session_id']} not found for activity")
                            continue
                        
                        # Create activity object with correct field names
                        activity_obj = SessionActivity(
                            session=session,
                            user=session.user,
                            activity_type=activity['activity_type'],
                            activity_data=activity['activity_data'],
                            url=activity['url'],
                            title=activity['title'],
                            location_latitude=activity['location_data'].get('latitude') if activity.get('location_data') else None,
                            location_longitude=activity['location_data'].get('longitude') if activity.get('location_data') else None,
                            location_accuracy=activity['location_data'].get('accuracy') if activity.get('location_data') else None,
                            activity_time=datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00'))
                        )
                        activity_objects.append(activity_obj)
                        
                        # Collect session updates
                        if activity['location_data']:
                            location_data = activity['location_data']
                            if 'latitude' in location_data and 'longitude' in location_data:
                                session_updates[activity['session_id']].update({
                                    'location_latitude': location_data['latitude'],
                                    'location_longitude': location_data['longitude'],
                                    'location_accuracy': location_data.get('accuracy'),
                                    'location_type': 'geo_location'
                                })
                        
                        # Update last activity
                        session_updates[activity['session_id']]['last_activity'] = timezone.now()
                        
                    except Exception as activity_error:
                        logger.error(f"Error processing activity {activity['record_id']}: {str(activity_error)}")
                
                # Bulk create activities
                if activity_objects:
                    SessionActivity.objects.bulk_create(activity_objects, batch_size=self.config['batch_size'])
                    logger.debug(f"Bulk created {len(activity_objects)} activities")
                
                # Bulk update sessions
                if session_updates:
                    self._bulk_update_sessions(session_updates)
                
                # Process location updates
                if location_updates:
                    self._process_location_updates(location_updates)
            
            write_time = time.time() - start_time
            
            # Update metrics
            with self._metrics_lock:
                self._metrics['total_writes'] += len(activities)
                self._metrics['avg_write_time'] = (
                    (self._metrics['avg_write_time'] * self._metrics['successful_writes'] + write_time) /
                    (self._metrics['successful_writes'] + 1)
                )
                self._metrics['avg_batch_size'] = (
                    (self._metrics['avg_batch_size'] * self._metrics['successful_writes'] + len(activities)) /
                    (self._metrics['successful_writes'] + 1)
                )
            
            logger.debug(f"Batch write completed in {write_time:.3f}s for {len(activities)} activities")
            return True
            
        except Exception as e:
            logger.error(f"Batch write failed for user {user_id}: {str(e)}")
            with self._metrics_lock:
                self._metrics['failed_writes'] += len(activities)
            return False
    
    def _get_cached_session(self, session_id):
        """
        Get session with caching
        """
        cache_key = f"session_obj_{session_id}"
        session = cache.get(cache_key)
        
        if session:
            with self._metrics_lock:
                self._metrics['cache_hits'] += 1
            return session
        
        try:
            from trueAlign.models import UserSession
            session = UserSession.objects.get(id=session_id)
            cache.set(cache_key, session, 300)  # Cache for 5 minutes
            
            with self._metrics_lock:
                self._metrics['cache_misses'] += 1
            return session
            
        except Exception as e:
            logger.error(f"Error fetching session {session_id}: {str(e)}")
            return None
    
    def _bulk_update_sessions(self, session_updates):
        """
        Efficiently bulk update sessions
        """
        try:
            from trueAlign.models import UserSession
            
            for session_id, updates in session_updates.items():
                UserSession.objects.filter(id=session_id).update(**updates)
                
                # Update cache
                cache_key = f"session_obj_{session_id}"
                cached_session = cache.get(cache_key)
                if cached_session:
                    for field, value in updates.items():
                        setattr(cached_session, field, value)
                    cache.set(cache_key, cached_session, 300)
            
            logger.debug(f"Bulk updated {len(session_updates)} sessions")
            
        except Exception as e:
            logger.error(f"Error in bulk session update: {str(e)}")
    
    def _process_location_updates(self, location_updates):
        """
        Process location updates with enhanced validation
        """
        try:
            from trueAlign.models import UserSession
            
            for update in location_updates:
                session_id = update['session_id']
                location_data = update['location_data']
                
                if 'latitude' in location_data and 'longitude' in location_data:
                    UserSession.objects.filter(id=session_id).update(
                        location_latitude=location_data['latitude'],
                        location_longitude=location_data['longitude'],
                        location_accuracy=location_data.get('accuracy'),
                        location_type='geo_location'
                    )
                    
                    logger.debug(f"Updated location for session {session_id}")
                    
        except Exception as e:
            logger.error(f"Error processing location updates: {str(e)}")
    
    def _add_to_retry_queue(self, user_id, session_id, activity_type, activity_data, location_data, url, title):
        """
        Add failed activity to retry queue
        """
        retry_item = {
            'user_id': user_id,
            'session_id': session_id,
            'activity_type': activity_type,
            'activity_data': activity_data,
            'location_data': location_data,
            'url': url,
            'title': title,
            'timestamp': timezone.now().isoformat(),
            'retry_count': 0,
            'next_retry': time.time() + self.config['retry_delay']
        }
        
        self._retry_queue.append(retry_item)
        logger.debug(f"Added activity to retry queue for user {user_id}")
    
    def _start_background_threads(self):
        """
        Start background threads for flushing and retrying
        """
        self._flush_thread = threading.Thread(target=self._flush_worker, daemon=True)
        self._flush_thread.start()
        
        self._retry_thread = threading.Thread(target=self._retry_worker, daemon=True)
        self._retry_thread.start()
        
        logger.info("Background threads started")
    
    def _flush_worker(self):
        """
        Background worker for periodic flushing
        """
        while not self._shutdown_event.is_set():
            try:
                current_time = time.time()
                
                with self._buffer_lock:
                    users_to_flush = []
                    for user_id, buffer in self._activity_buffers.items():
                        if (buffer['session_activities'] and 
                            current_time - buffer['last_flush'] > self.config['flush_interval']):
                            users_to_flush.append(user_id)
                
                for user_id in users_to_flush:
                    self._flush_user_buffer(user_id)
                
                # Sleep for a portion of flush interval
                self._shutdown_event.wait(min(30, self.config['flush_interval'] // 4))
                
            except Exception as e:
                logger.error(f"Error in flush worker: {str(e)}")
                self._shutdown_event.wait(30)
    
    def _retry_worker(self):
        """
        Background worker for retrying failed operations
        """
        while not self._shutdown_event.is_set():
            try:
                current_time = time.time()
                items_to_retry = []
                
                # Get items ready for retry
                while self._retry_queue:
                    item = self._retry_queue.popleft()
                    if current_time >= item['next_retry']:
                        if item['retry_count'] < self.config['retry_attempts']:
                            items_to_retry.append(item)
                        else:
                            logger.error(f"Max retries exceeded for activity: {item}")
                    else:
                        # Put back in queue
                        self._retry_queue.appendleft(item)
                        break
                
                # Retry items
                for item in items_to_retry:
                    try:
                        item['retry_count'] += 1
                        self.add_activity(
                            item['user_id'], item['session_id'], item['activity_type'],
                            item['activity_data'], item['location_data'],
                            item['url'], item['title']
                        )
                        logger.debug(f"Retried activity for user {item['user_id']}")
                    except Exception as retry_error:
                        logger.error(f"Retry failed: {str(retry_error)}")
                        item['next_retry'] = current_time + self.config['retry_delay'] * (2 ** item['retry_count'])
                        self._retry_queue.append(item)
                
                self._shutdown_event.wait(30)
                
            except Exception as e:
                logger.error(f"Error in retry worker: {str(e)}")
                self._shutdown_event.wait(30)
    
    def _force_flush_user_buffer(self, user_id):
        """
        Force flush buffer for specific user
        """
        self._flush_user_buffer(user_id)
    
    def force_flush_all(self):
        """
        Force flush all buffers
        """
        with self._buffer_lock:
            user_ids = list(self._activity_buffers.keys())
        
        for user_id in user_ids:
            self._flush_user_buffer(user_id)
        
        logger.info("Force flushed all buffers")
    
    def get_metrics(self):
        """
        Get performance metrics
        """
        with self._metrics_lock:
            metrics = self._metrics.copy()
        
        # Add buffer stats
        with self._buffer_lock:
            total_buffered = sum(len(buffer['session_activities']) for buffer in self._activity_buffers.values())
            metrics['total_buffered_activities'] = total_buffered
            metrics['active_users'] = len(self._activity_buffers)
            metrics['retry_queue_size'] = len(self._retry_queue)
        
        return metrics
    
    def shutdown(self):
        """
        Graceful shutdown
        """
        logger.info("Shutting down Enhanced Batch Writer...")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Force flush all buffers
        self.force_flush_all()
        
        # Wait for threads
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=30)
        
        if self._retry_thread and self._retry_thread.is_alive():
            self._retry_thread.join(timeout=30)
        
        logger.info("Enhanced Batch Writer shutdown complete")

# Global instance
_batch_writer_instance = None

def get_batch_writer():
    """
    Get singleton batch writer instance
    """
    global _batch_writer_instance
    if _batch_writer_instance is None:
        _batch_writer_instance = EnhancedBatchWriter()
    return _batch_writer_instance