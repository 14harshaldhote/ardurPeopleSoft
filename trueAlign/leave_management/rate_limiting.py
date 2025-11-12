"""
Rate limiting for leave management API endpoints
"""
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
from functools import wraps
import hashlib

class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded"""
    pass

def rate_limit(requests_per_minute=60, requests_per_hour=1000):
    """
    Rate limiting decorator for API endpoints
    
    Args:
        requests_per_minute: Maximum requests per minute per user
        requests_per_hour: Maximum requests per hour per user
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return JsonResponse({'error': 'Authentication required'}, status=401)
            
            user_id = request.user.id
            now = timezone.now()
            
            # Create cache keys
            minute_key = f"rate_limit_minute_{user_id}_{now.strftime('%Y%m%d%H%M')}"
            hour_key = f"rate_limit_hour_{user_id}_{now.strftime('%Y%m%d%H')}"
            
            # Check minute limit
            minute_count = cache.get(minute_key, 0)
            if minute_count >= requests_per_minute:
                return JsonResponse({
                    'error': 'Rate limit exceeded',
                    'message': f'Maximum {requests_per_minute} requests per minute allowed'
                }, status=429)
            
            # Check hour limit
            hour_count = cache.get(hour_key, 0)
            if hour_count >= requests_per_hour:
                return JsonResponse({
                    'error': 'Rate limit exceeded',
                    'message': f'Maximum {requests_per_hour} requests per hour allowed'
                }, status=429)
            
            # Increment counters
            cache.set(minute_key, minute_count + 1, 60)  # 1 minute
            cache.set(hour_key, hour_count + 1, 3600)    # 1 hour
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator

def api_rate_limit(view_func):
    """Standard rate limit for API endpoints"""
    return rate_limit(requests_per_minute=30, requests_per_hour=500)(view_func)

def strict_rate_limit(view_func):
    """Strict rate limit for sensitive operations"""
    return rate_limit(requests_per_minute=10, requests_per_hour=100)(view_func)
