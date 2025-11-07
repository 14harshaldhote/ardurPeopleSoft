"""
Distributed Locking Utility for Cron Jobs

This module provides a decorator-based locking mechanism to ensure only one instance
of a cron job runs at a time. Uses Django's cache backend for distributed locking.

Usage:
    from .locking import with_cron_lock
    
    @with_cron_lock('my_job_name', timeout=1800)
    def my_cron_job():
        # Your cron job code here
        pass
"""

from django.core.cache import cache
from functools import wraps
from django.utils import timezone
import logging
import time

logger = logging.getLogger('cron')


def with_cron_lock(lock_name, timeout=3600, retry_count=0, retry_delay=5):
    """
    Decorator to ensure only one instance of cron job runs at a time.
    
    Args:
        lock_name (str): Unique identifier for the lock (e.g., 'daily_creation')
        timeout (int): Lock timeout in seconds (default 1 hour)
        retry_count (int): Number of times to retry if lock is held (default 0)
        retry_delay (int): Seconds to wait between retries (default 5)
    
    Returns:
        Function wrapper that implements locking
    
    Example:
        @with_cron_lock('auto_marking', timeout=1800)
        def do(self):
            # Process attendance
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            lock_key = f'cron_lock_{lock_name}'
            lock_value = {
                'acquired_at': timezone.now().isoformat(),
                'timeout': timeout,
                'function': func.__name__
            }
            
            attempts = 0
            max_attempts = retry_count + 1
            
            while attempts < max_attempts:
                # Try to acquire lock
                if cache.add(lock_key, lock_value, timeout=timeout):
                    logger.info(f"✓ [{lock_name}] Lock acquired (timeout: {timeout}s)")
                    
                    try:
                        # Execute the function
                        start_time = time.time()
                        result = func(*args, **kwargs)
                        execution_time = time.time() - start_time
                        
                        logger.info(
                            f"✓ [{lock_name}] Completed successfully "
                            f"(execution time: {execution_time:.2f}s)"
                        )
                        return result
                        
                    except Exception as e:
                        logger.error(f"✗ [{lock_name}] Failed with error: {str(e)}")
                        raise
                        
                    finally:
                        # Always release lock
                        cache.delete(lock_key)
                        logger.info(f"✓ [{lock_name}] Lock released")
                
                else:
                    # Lock already held
                    lock_holder = cache.get(lock_key)
                    attempts += 1
                    
                    if attempts < max_attempts:
                        logger.warning(
                            f"⏳ [{lock_name}] Lock held (attempt {attempts}/{max_attempts}). "
                            f"Retrying in {retry_delay}s... "
                            f"Lock holder: {lock_holder}"
                        )
                        time.sleep(retry_delay)
                    else:
                        logger.warning(
                            f"✗ [{lock_name}] Lock held by another process. Skipping execution. "
                            f"Lock holder: {lock_holder}"
                        )
                        return {
                            'success': False,
                            'message': 'Job already running',
                            'lock_holder': lock_holder,
                            'skipped': True
                        }
            
            # Should never reach here, but just in case
            return {
                'success': False,
                'message': 'Failed to acquire lock after retries',
                'skipped': True
            }
        
        return wrapper
    return decorator


def release_lock(lock_name):
    """
    Manually release a lock (for emergency situations).
    
    Args:
        lock_name (str): Name of the lock to release
    
    Returns:
        bool: True if lock was released, False if no lock found
    """
    lock_key = f'cron_lock_{lock_name}'
    if cache.get(lock_key):
        cache.delete(lock_key)
        logger.info(f"✓ [{lock_name}] Lock manually released")
        return True
    else:
        logger.warning(f"⚠ [{lock_name}] No lock found to release")
        return False


def release_all_cron_locks():
    """
    Release all cron locks (emergency cleanup).
    
    Warning: This should only be used in emergency situations or during maintenance.
    It assumes lock keys follow the pattern 'cron_lock_*'.
    
    Returns:
        int: Number of locks released
    """
    # Note: This is a safety mechanism. Django's cache may not support
    # pattern-based deletion depending on backend (e.g., Memcached doesn't).
    # For production, consider using Redis with key pattern matching.
    
    logger.warning("⚠ Emergency: Attempting to release all cron locks")
    
    # List of known lock names
    known_locks = [
        'daily_creation',
        'auto_marking',
        'notifications',
        'cleanup'
    ]
    
    released_count = 0
    for lock_name in known_locks:
        if release_lock(lock_name):
            released_count += 1
    
    logger.warning(f"⚠ Released {released_count} cron locks")
    return released_count


def get_lock_status(lock_name):
    """
    Check if a lock is currently held.
    
    Args:
        lock_name (str): Name of the lock to check
    
    Returns:
        dict: Lock status information or None if not locked
    """
    lock_key = f'cron_lock_{lock_name}'
    lock_data = cache.get(lock_key)
    
    if lock_data:
        return {
            'locked': True,
            'lock_name': lock_name,
            'data': lock_data
        }
    else:
        return {
            'locked': False,
            'lock_name': lock_name,
            'data': None
        }


def get_all_lock_statuses():
    """
    Get status of all known cron locks.
    
    Returns:
        list: List of lock status dictionaries
    """
    known_locks = [
        'daily_creation',
        'auto_marking',
        'notifications',
        'cleanup'
    ]
    
    return [get_lock_status(lock_name) for lock_name in known_locks]


# Cleanup function for expired locks
def cleanup_expired_locks():
    """
    Clean up any expired locks (safety mechanism).
    
    Note: Django's cache automatically handles expiration, but this
    function can be called manually if needed.
    
    Returns:
        dict: Cleanup status
    """
    # Cache automatically handles expiration
    # This is just a placeholder for manual intervention if needed
    logger.info("Cache backend handles lock expiration automatically")
    
    return {
        'success': True,
        'message': 'Lock expiration is handled automatically by cache backend'
    }
