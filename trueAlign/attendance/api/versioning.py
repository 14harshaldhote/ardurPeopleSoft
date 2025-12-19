# attendance/api/versioning.py
"""
API Versioning Utilities

Provides version management for the Attendance API.
"""

from django.http import JsonResponse
from functools import wraps


def api_version_header(version='1.0'):
    """
    Decorator to add API version to response headers
    
    Usage:
        @api_version_header('1.0')
        def my_api_view(request):
            return JsonResponse({...})
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            if hasattr(response, '__setitem__'):
                response['X-API-Version'] = version
            return response
        return wrapper
    return decorator


def deprecated_endpoint(deprecation_message=None, sunset_date=None):
    """
    Decorator to mark an API endpoint as deprecated
    
    Usage:
        @deprecated_endpoint(
            deprecation_message="Use /api/v1/attendance/ instead",
            sunset_date="2026-01-01"
        )
        def old_api_view(request):
            return JsonResponse({...})
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            
            if hasattr(response, '__setitem__'):
                response['Warning'] = '299 - "Deprecated API"'
                
                if deprecation_message:
                    response['X-API-Deprecation-Info'] = deprecation_message
                
                if sunset_date:
                    response['Sunset'] = sunset_date
                    
            return response
        return wrapper
    return decorator


def get_api_version(request):
    """
    Extract API version from request
    
    Checks in order:
    1. URL path (/api/v1/, /api/v2/)
    2. Accept header (application/vnd.truealign.v1+json)
    3. X-API-Version header
    4. Default to v1
    """
    # Check URL path
    path = request.path
    if '/v1/' in path:
        return 'v1'
    elif '/v2/' in path:
        return 'v2'
    
    # Check Accept header
    accept = request.META.get('HTTP_ACCEPT', '')
    if 'vnd.truealign.v1+json' in accept:
        return 'v1'
    elif 'vnd.truealign.v2+json' in accept:
        return 'v2'
    
    # Check X-API-Version header
    version_header = request.META.get('HTTP_X_API_VERSION', '')
    if version_header:
        return version_header.lower()
    
    # Default
    return 'v1'


# Version constants
API_VERSION_1 = '1.0.0'
API_VERSION_2 = '2.0.0'
CURRENT_API_VERSION = API_VERSION_1

# Supported versions
SUPPORTED_API_VERSIONS = ['v1']
DEPRECATED_API_VERSIONS = []
