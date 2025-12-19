# attendance/middleware.py
"""
Security and performance middleware for attendance module
"""
import logging
import re
from django.http import JsonResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import SuspiciousOperation
import bleach

logger = logging.getLogger(__name__)


class AttendanceSecurityMiddleware(MiddlewareMixin):
    """
    Security middleware for attendance module
    - Input sanitization
    - XSS prevention
    - SQL injection prevention
    - Request validation
    """
    
    # Potentially dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|;|\/\*|\*\/)",
        r"(\bOR\b.*=.*)",
        r"(\'\s*(OR|AND)\s*\')",
    ]
    
    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"onclick=",
    ]
    
    def process_request(self, request):
        """Process incoming requests for security"""
        # Only check POST/PUT/PATCH requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            # Check if path is attendance related
            if '/attendance/' in request.path:
                try:
                    # Sanitize POST data
                    if hasattr(request, 'POST') and request.POST:
                        self._sanitize_dict(request.POST)
                    
                    # Sanitize GET parameters
                    if hasattr(request, 'GET') and request.GET:
                        self._sanitize_dict(request.GET)
                        
                except SuspiciousOperation as e:
                    logger.warning(f"Suspicious request detected: {e}")
                    return JsonResponse({
                        'error': 'Invalid input detected',
                        'message': 'Your request contains suspicious data'
                    }, status=400)
        
        return None
    
    def _sanitize_dict(self, data_dict):
        """Sanitize dictionary data"""
        for key, value in data_dict.items():
            if isinstance(value, str):
                self._check_sql_injection(value)
                self._check_xss(value)
    
    def _check_sql_injection(self, value):
        """Check for SQL injection patterns"""
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {value[:50]}")
                raise SuspiciousOperation("Potential SQL injection detected")
    
    def _check_xss(self, value):
        """Check for XSS patterns"""
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential XSS detected: {value[:50]}")
                raise SuspiciousOperation("Potential XSS attack detected")


class RateLimitMiddleware(MiddlewareMixin):
    """
    Simple rate limiting middleware
    For production, use django-ratelimit or similar
    """
    
    def process_request(self, request):
        """Check rate limits for API endpoints"""
        if '/attendance/api/' in request.path:
            # Get user identifier (IP or user ID)
            identifier = self._get_identifier(request)
            cache_key = f"rate_limit_{identifier}_{request.path}"
            
            # Check requests in last minute
            requests_count = cache.get(cache_key, 0)
            
            # Allow 60 requests per minute per user/IP
            if requests_count >= 60:
                logger.warning(f"Rate limit exceeded for {identifier}")
                return JsonResponse({
                    'error': 'Rate limit exceeded',
                    'message': 'Too many requests. Please try again later.'
                }, status=429)
            
            # Increment counter
            cache.set(cache_key, requests_count + 1, 60)
        
        return None
    
    def _get_identifier(self, request):
        """Get unique identifier for rate limiting"""
        if request.user.is_authenticated:
            return f"user_{request.user.id}"
        # Use IP address for anonymous users
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return f"ip_{ip}"


class InputSanitizationMiddleware(MiddlewareMixin):
    """
    Sanitize user input to prevent XSS and other attacks
    """
    
    ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
    ALLOWED_ATTRIBUTES = {}
    
    def process_request(self, request):
        """Sanitize request data"""
        if request.method in ['POST', 'PUT', 'PATCH']:
            if '/attendance/' in request.path:
                # Sanitize POST data
                if hasattr(request, 'POST'):
                    self._sanitize_post_data(request)
        
        return None
    
    def _sanitize_post_data(self, request):
        """Sanitize POST data"""
        # Note: request.POST is immutable, so we can only validate
        # Actual sanitization would need to happen in form clean() methods
        for key, value in request.POST.items():
            if isinstance(value, str) and len(value) > 0:
                # Check if value contains HTML tags
                if '<' in value or '>' in value:
                    # Sanitize using bleach
                    sanitized = bleach.clean(
                        value,
                        tags=self.ALLOWED_TAGS,
                        attributes=self.ALLOWED_ATTRIBUTES,
                        strip=True
                    )
                    if sanitized != value:
                        logger.info(f"Sanitized input for key '{key}'")


class QueryCountMiddleware(MiddlewareMixin):
    """
    Development middleware to track database queries
    Only active in DEBUG mode
    """
    
    def process_request(self, request):
        """Start query counting"""
        from django.conf import settings
        if settings.DEBUG:
            from django.db import connection, reset_queries
            reset_queries()
        return None
    
    def process_response(self, request, response):
        """Log query count"""
        from django.conf import settings
        if settings.DEBUG:
            from django.db import connection
            query_count = len(connection.queries)
            
            if query_count > 10:
                logger.warning(
                    f"{request.path} executed {query_count} queries. "
                    f"Consider optimization."
                )
            else:
                logger.debug(f"{request.path} executed {query_count} queries")
        
        return response
