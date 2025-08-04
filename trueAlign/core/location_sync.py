import threading
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from django.conf import settings
import json

logger = logging.getLogger(__name__)

class LocationDataSynchronizer:
    """
    Location data synchronization system to ensure:
    - Location data flows from SessionActivity to UserSession
    - Automatic validation and cleanup of location data
    - Real-time location tracking with accuracy validation
    - Location history maintenance
    """
    
    def __init__(self):
        # Configuration
        self.config = {
            'sync_interval': getattr(settings, 'LOCATION_SYNC_INTERVAL', 60),  # 1 minute
            'max_accuracy_threshold': getattr(settings, 'LOCATION_MAX_ACCURACY', 1000),  # 1km
            'min_accuracy_threshold': getattr(settings, 'LOCATION_MIN_ACCURACY', 10),  # 10m
            'location_timeout': getattr(settings, 'LOCATION_TIMEOUT', 3600),  # 1 hour
            'max_history_entries': getattr(settings, 'LOCATION_MAX_HISTORY', 100),
            'enable_validation': getattr(settings, 'LOCATION_ENABLE_VALIDATION', True),
            'batch_size': getattr(settings, 'LOCATION_BATCH_SIZE', 50),
        }
        
        # Thread-safe data structures
        self._sync_lock = threading.RLock()
        self._pending_lock = threading.RLock()
        
        # Pending location updates by session_id
        self._pending_updates = defaultdict(lambda: {
            'updates': deque(maxlen=10),
            'last_sync': 0,
            'total_updates': 0,
            'failed_syncs': 0
        })
        
        # Location validation cache
        self._validation_cache = {}
        self._validation_cache_lock = threading.RLock()
        
        # Performance metrics
        self._metrics = {
            'total_syncs': 0,
            'successful_syncs': 0,
            'failed_syncs': 0,
            'validation_failures': 0,
            'accuracy_improvements': 0,
            'location_corrections': 0,
            'duplicate_locations_filtered': 0,
        }
        self._metrics_lock = threading.RLock()
        
        # Background thread management
        self._shutdown_event = threading.Event()
        self._sync_thread = None
        
        # Start background synchronization
        self._start_sync_thread()
        
        logger.info("Location Data Synchronizer initialized with config: %s", self.config)
    
    def queue_location_update(self, session_id, activity_id, location_data, timestamp=None):
        """
        Queue location update for processing
        """
        if not location_data:
            return False
        
        try:
            # Validate location data
            if not self._validate_location_data(location_data):
                with self._metrics_lock:
                    self._metrics['validation_failures'] += 1
                logger.warning(f"Invalid location data for session {session_id}: {location_data}")
                return False
            
            # Create update record
            update_record = {
                'session_id': session_id,
                'activity_id': activity_id,
                'location_data': location_data,
                'timestamp': timestamp or timezone.now(),
                'processed': False,
                'attempts': 0,
                'created_at': time.time()
            }
            
            with self._pending_lock:
                pending = self._pending_updates[session_id]
                
                # Check for duplicate location
                if self._is_duplicate_location(pending['updates'], location_data):
                    with self._metrics_lock:
                        self._metrics['duplicate_locations_filtered'] += 1
                    logger.debug(f"Duplicate location filtered for session {session_id}")
                    return False
                
                pending['updates'].append(update_record)
                pending['total_updates'] += 1
                
                # Trigger immediate sync if high accuracy location
                accuracy = location_data.get('accuracy', float('inf'))
                if accuracy <= self.config['min_accuracy_threshold']:
                    self._process_session_location_updates(session_id, force=True)
            
            logger.debug(f"Queued location update for session {session_id} with accuracy {accuracy}m")
            return True
            
        except Exception as e:
            logger.error(f"Error queuing location update for session {session_id}: {str(e)}")
            return False
    
    def _validate_location_data(self, location_data):
        """
        Validate location data structure and values
        """
        if not isinstance(location_data, dict):
            return False
        
        # Check required fields
        required_fields = ['latitude', 'longitude']
        if not all(field in location_data for field in required_fields):
            return False
        
        try:
            lat = float(location_data['latitude'])
            lng = float(location_data['longitude'])
            
            # Validate coordinate ranges
            if not (-90 <= lat <= 90):
                return False
            if not (-180 <= lng <= 180):
                return False
            
            # Validate accuracy if present
            if 'accuracy' in location_data:
                accuracy = float(location_data['accuracy'])
                if accuracy < 0 or accuracy > self.config['max_accuracy_threshold']:
                    return False
            
            return True
            
        except (ValueError, TypeError):
            return False
    
    def _is_duplicate_location(self, existing_updates, new_location_data):
        """
        Check if location is a duplicate of recent updates
        """
        if not existing_updates:
            return False
        
        try:
            new_lat = float(new_location_data['latitude'])
            new_lng = float(new_location_data['longitude'])
            
            # Check last few updates
            recent_updates = list(existing_updates)[-3:]  # Check last 3 updates
            
            for update in recent_updates:
                if update['processed']:
                    continue
                
                existing_data = update['location_data']
                existing_lat = float(existing_data['latitude'])
                existing_lng = float(existing_data['longitude'])
                
                # Calculate approximate distance (simplified)
                lat_diff = abs(new_lat - existing_lat)
                lng_diff = abs(new_lng - existing_lng)
                
                # If coordinates are very close (within ~10 meters)
                if lat_diff < 0.0001 and lng_diff < 0.0001:
                    # Check if new location has better accuracy
                    new_accuracy = new_location_data.get('accuracy', float('inf'))
                    existing_accuracy = existing_data.get('accuracy', float('inf'))
                    
                    if new_accuracy >= existing_accuracy:
                        return True  # Duplicate with same or worse accuracy
            
            return False
            
        except (ValueError, TypeError, KeyError):
            return False
    
    def _start_sync_thread(self):
        """
        Start background synchronization thread
        """
        self._sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self._sync_thread.start()
        logger.info("Location synchronization thread started")
    
    def _sync_worker(self):
        """
        Background worker for location synchronization
        """
        while not self._shutdown_event.is_set():
            try:
                # Process pending updates
                self._process_pending_updates()
                
                # Clean up old data
                self._cleanup_old_data()
                
                # Sleep for sync interval
                self._shutdown_event.wait(self.config['sync_interval'])
                
            except Exception as e:
                logger.error(f"Error in location sync worker: {str(e)}")
                self._shutdown_event.wait(30)
    
    def _process_pending_updates(self):
        """
        Process all pending location updates
        """
        with self._pending_lock:
            session_ids = list(self._pending_updates.keys())
        
        for session_id in session_ids:
            try:
                self._process_session_location_updates(session_id)
            except Exception as e:
                logger.error(f"Error processing location updates for session {session_id}: {str(e)}")
    
    def _process_session_location_updates(self, session_id, force=False):
        """
        Process location updates for a specific session
        """
        with self._pending_lock:
            pending = self._pending_updates[session_id]
            
            if not pending['updates']:
                return
            
            # Check if sync is needed
            current_time = time.time()
            if not force and (current_time - pending['last_sync']) < self.config['sync_interval']:
                return
            
            # Get updates to process
            updates_to_process = [update for update in pending['updates'] if not update['processed']]
            
            if not updates_to_process:
                return
        
        # Process updates in batch
        success_count = 0
        for update in updates_to_process:
            try:
                if self._sync_location_to_session(session_id, update):
                    update['processed'] = True
                    success_count += 1
                else:
                    update['attempts'] += 1
                    if update['attempts'] >= 3:
                        update['processed'] = True  # Give up after 3 attempts
                        
            except Exception as e:
                logger.error(f"Error syncing location update {update.get('activity_id')}: {str(e)}")
                update['attempts'] += 1
        
        # Update metrics and state
        with self._pending_lock:
            pending['last_sync'] = current_time
            if success_count > 0:
                with self._metrics_lock:
                    self._metrics['successful_syncs'] += success_count
            
            failed_count = len(updates_to_process) - success_count
            if failed_count > 0:
                pending['failed_syncs'] += failed_count
                with self._metrics_lock:
                    self._metrics['failed_syncs'] += failed_count
        
        logger.debug(f"Processed {success_count}/{len(updates_to_process)} location updates for session {session_id}")
    
    def _sync_location_to_session(self, session_id, update):
        """
        Synchronize location data to UserSession
        """
        try:
            from trueAlign.models import UserSession
            from trueAlign.core.enhanced_logger import get_session_logger
            
            session_logger = get_session_logger()
            location_data = update['location_data']
            
            with transaction.atomic():
                # Get session with lock
                try:
                    session = UserSession.objects.select_for_update().get(id=session_id)
                except UserSession.DoesNotExist:
                    logger.warning(f"Session {session_id} not found for location sync")
                    return False
                
                # Check if this is a better location
                should_update = self._should_update_session_location(session, location_data)
                
                if should_update:
                    # Update session location
                    old_accuracy = session.location_accuracy
                    
                    session.location_latitude = float(location_data['latitude'])
                    session.location_longitude = float(location_data['longitude'])
                    session.location_accuracy = location_data.get('accuracy')
                    session.location_type = location_data.get('type', 'geo_location')
                    
                    # Update location history
                    location_history = session.location_history or []
                    location_entry = {
                        'latitude': session.location_latitude,
                        'longitude': session.location_longitude,
                        'accuracy': session.location_accuracy,
                        'timestamp': update['timestamp'].isoformat(),
                        'source': 'activity_sync'
                    }
                    
                    location_history.append(location_entry)
                    
                    # Limit history size
                    if len(location_history) > self.config['max_history_entries']:
                        location_history = location_history[-self.config['max_history_entries']:]
                    
                    session.location_history = location_history
                    
                    # Save session
                    session.save(update_fields=[
                        'location_latitude', 'location_longitude', 'location_accuracy',
                        'location_type', 'location_history'
                    ])
                    
                    # Log successful sync
                    session_logger.log_location_update(
                        session.user, session_id, location_data, success=True
                    )
                    
                    # Check if accuracy improved
                    if old_accuracy and session.location_accuracy:
                        if session.location_accuracy < old_accuracy:
                            with self._metrics_lock:
                                self._metrics['accuracy_improvements'] += 1
                    
                    logger.debug(f"Updated location for session {session_id}")
                    
                    # Update cache
                    cache_key = f"session_location_{session_id}"
                    cache.set(cache_key, {
                        'latitude': session.location_latitude,
                        'longitude': session.location_longitude,
                        'accuracy': session.location_accuracy,
                        'updated_at': timezone.now().isoformat()
                    }, 300)  # 5 minutes
                    
                    return True
                else:
                    logger.debug(f"Location not updated for session {session_id} (not better than existing)")
                    return True  # Still consider it processed
                    
        except Exception as e:
            logger.error(f"Error syncing location to session {session_id}: {str(e)}")
            return False
    
    def _should_update_session_location(self, session, new_location_data):
        """
        Determine if session location should be updated
        """
        # Always update if no location exists
        if not session.location_latitude or not session.location_longitude:
            return True
        
        # Check if new location has better accuracy
        new_accuracy = new_location_data.get('accuracy')
        current_accuracy = session.location_accuracy
        
        if new_accuracy and current_accuracy:
            if new_accuracy < current_accuracy:
                return True  # Better accuracy
        elif new_accuracy and not current_accuracy:
            return True  # First time we have accuracy data
        
        # Check age of current location
        if session.location_history:
            try:
                last_location = session.location_history[-1]
                last_timestamp = datetime.fromisoformat(last_location['timestamp'])
                time_diff = (timezone.now() - last_timestamp).total_seconds()
                
                # Update if location is old
                if time_diff > self.config['location_timeout']:
                    return True
            except (KeyError, ValueError, TypeError):
                pass
        
        # Check distance from current location
        try:
            new_lat = float(new_location_data['latitude'])
            new_lng = float(new_location_data['longitude'])
            current_lat = float(session.location_latitude)
            current_lng = float(session.location_longitude)
            
            # Simple distance check (approximate)
            lat_diff = abs(new_lat - current_lat)
            lng_diff = abs(new_lng - current_lng)
            
            # If significant movement (>100m approximately)
            if lat_diff > 0.001 or lng_diff > 0.001:
                with self._metrics_lock:
                    self._metrics['location_corrections'] += 1
                return True
                
        except (ValueError, TypeError):
            pass
        
        return False
    
    def _cleanup_old_data(self):
        """
        Clean up old pending updates and validation cache
        """
        current_time = time.time()
        cutoff_time = current_time - (2 * self.config['sync_interval'])
        
        with self._pending_lock:
            sessions_to_remove = []
            
            for session_id, pending in self._pending_updates.items():
                # Remove old processed updates
                pending['updates'] = deque(
                    [update for update in pending['updates'] 
                     if not update['processed'] or (current_time - update['created_at']) < cutoff_time],
                    maxlen=10
                )
                
                # Remove session if no pending updates
                if not pending['updates']:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self._pending_updates[session_id]
        
        # Clean validation cache
        with self._validation_cache_lock:
            expired_keys = [
                key for key, data in self._validation_cache.items()
                if (current_time - data.get('timestamp', 0)) > 300  # 5 minutes
            ]
            
            for key in expired_keys:
                del self._validation_cache[key]
        
        if sessions_to_remove or expired_keys:
            logger.debug(f"Cleaned up {len(sessions_to_remove)} session queues and {len(expired_keys)} cache entries")
    
    def force_sync_session(self, session_id):
        """
        Force immediate synchronization for a session
        """
        self._process_session_location_updates(session_id, force=True)
    
    def get_pending_count(self, session_id=None):
        """
        Get count of pending updates
        """
        with self._pending_lock:
            if session_id:
                pending = self._pending_updates.get(session_id, {})
                return len([u for u in pending.get('updates', []) if not u['processed']])
            else:
                total = 0
                for pending in self._pending_updates.values():
                    total += len([u for u in pending['updates'] if not u['processed']])
                return total
    
    def get_metrics(self):
        """
        Get synchronization metrics
        """
        with self._metrics_lock:
            metrics = self._metrics.copy()
        
        # Add current state
        with self._pending_lock:
            metrics['pending_sessions'] = len(self._pending_updates)
            metrics['total_pending_updates'] = self.get_pending_count()
        
        return metrics
    
    def shutdown(self):
        """
        Graceful shutdown
        """
        logger.info("Shutting down Location Data Synchronizer...")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Process remaining updates
        try:
            self._process_pending_updates()
        except Exception as e:
            logger.error(f"Error processing final updates during shutdown: {str(e)}")
        
        # Wait for thread
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=30)
        
        logger.info("Location Data Synchronizer shutdown complete")

# Global instance
_location_sync_instance = None

def get_location_synchronizer():
    """
    Get singleton location synchronizer instance
    """
    global _location_sync_instance
    if _location_sync_instance is None:
        _location_sync_instance = LocationDataSynchronizer()
    return _location_sync_instance