# attendance/api_responses.py
"""
API Response Utilities

Standardized API response format for consistency.
"""

from django.http import JsonResponse
from typing import Any, Optional, List, Dict


def success_response(
    data: Any = None, message: Optional[str] = None, status: int = 200
) -> JsonResponse:
    """
    Standard success response

    Args:
        data: Response data (dict, list, or primitive)
        message: Optional success message
        status: HTTP status code (default 200)

    Returns:
        JsonResponse with standard format
    """
    response = {
        "success": True,
        "data": data,
    }

    if message:
        response["message"] = message

    return JsonResponse(response, status=status)


def error_response(
    message: str,
    code: int = 400,
    errors: Optional[List[str]] = None,
    field_errors: Optional[Dict[str, List[str]]] = None,
) -> JsonResponse:
    """
    Standard error response

    Args:
        message: Error message
        code: HTTP status code
        errors: List of error messages
        field_errors: Dict of field-specific errors

    Returns:
        JsonResponse with standard error format
    """
    response = {
        "success": False,
        "message": message,
    }

    if errors:
        response["errors"] = errors

    if field_errors:
        response["field_errors"] = field_errors

    return JsonResponse(response, status=code)


def validation_error_response(
    field_errors: Dict[str, List[str]], message: str = "Validation failed"
) -> JsonResponse:
    """
    Validation error response

    Args:
        field_errors: Dict mapping field names to error lists
        message: Overall error message

    Returns:
        JsonResponse with validation errors
    """
    return error_response(message=message, code=422, field_errors=field_errors)


def not_found_response(resource: str = "Resource") -> JsonResponse:
    """
    Not found error response

    Args:
        resource: Name of resource that wasn't found

    Returns:
        JsonResponse with 404 status
    """
    return error_response(message=f"{resource} not found", code=404)


def unauthorized_response(message: str = "Unauthorized") -> JsonResponse:
    """
    Unauthorized error response

    Returns:
        JsonResponse with 403 status
    """
    return error_response(message=message, code=403)


def server_error_response(message: str = "Internal server error") -> JsonResponse:
    """
    Server error response

    Returns:
        JsonResponse with 500 status
    """
    return error_response(message=message, code=500)
