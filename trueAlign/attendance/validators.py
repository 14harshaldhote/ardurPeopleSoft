# attendance/validators.py
"""
Input validation utilities for attendance module
"""
import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional
from django.core.exceptions import ValidationError
from django.utils import timezone
import pytz


IST = pytz.timezone('Asia/Kolkata')


class AttendanceValidator:
    """Centralized validation for attendance operations"""
    
    @staticmethod
    def validate_date_range(start_date: date, end_date: date, max_days: int = 365):
        """
        Validate date range
        
        Args:
            start_date: Start date
            end_date: End date
            max_days: Maximum allowed days in range
            
        Raises:
            ValidationError: If validation fails
        """
        if not start_date or not end_date:
            raise ValidationError("Both start and end dates are required")
        
        if start_date > end_date:
            raise ValidationError("Start date cannot be after end date")
        
        if (end_date - start_date).days > max_days:
            raise ValidationError(f"Date range cannot exceed {max_days} days")
        
        # Prevent future dates
        today = timezone.now().astimezone(IST).date()
        if end_date > today:
            raise ValidationError("End date cannot be in the future")
    
    @staticmethod
    def validate_user_ids(user_ids: List[int], max_users: int = 100):
        """
        Validate user ID list for bulk operations
        
        Args:
            user_ids: List of user IDs
            max_users: Maximum allowed users
            
        Raises:
            ValidationError: If validation fails
        """
        if not user_ids:
            raise ValidationError("At least one user must be selected")
        
        if len(user_ids) > max_users:
            raise ValidationError(f"Cannot process more than {max_users} users at once")
        
        # Validate all IDs are positive integers
        if not all(isinstance(uid, int) and uid > 0 for uid in user_ids):
            raise ValidationError("Invalid user IDs provided")
    
    @staticmethod
    def validate_status(status: str):
        """
        Validate attendance status
        
        Args:
            status: Attendance status
            
        Raises:
            ValidationError: If status is invalid
        """
        valid_statuses = [
            'Present', 'Present & Late', 'Absent', 'On Leave',
            'Work From Home', 'Weekend', 'Holiday', 'Half Day', 'Not Marked'
        ]
        
        if status not in valid_statuses:
            raise ValidationError(f"Invalid status: {status}")
    
    @staticmethod
    def validate_time_string(time_str: str):
        """
        Validate time string format (HH:MM)
        
        Args:
            time_str: Time string
            
        Raises:
            ValidationError: If format is invalid
        """
        if not time_str:
            return
        
        pattern = r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$'
        if not re.match(pattern, time_str):
            raise ValidationError("Time must be in HH:MM format")
    
    @staticmethod
    def validate_reason(reason: str, min_length: int = 10, max_length: int = 500):
        """
        Validate reason/comments text
        
        Args:
            reason: Reason text
            min_length: Minimum required length
            max_length: Maximum allowed length
            
        Raises:
            ValidationError: If validation fails
        """
        if not reason or not reason.strip():
            raise ValidationError("Reason is required")
        
        if len(reason.strip()) < min_length:
            raise ValidationError(f"Reason must be at least {min_length} characters")
        
        if len(reason) > max_length:
            raise ValidationError(f"Reason cannot exceed {max_length} characters")
        
        # Check for suspicious patterns
        suspicious_patterns = ['<script', 'javascript:', 'onerror=']
        for pattern in suspicious_patterns:
            if pattern.lower() in reason.lower():
                raise ValidationError("Reason contains invalid content")
    
    @staticmethod
    def validate_export_format(format: str):
        """
        Validate export format
        
        Args:
            format: Export format
            
        Raises:
            ValidationError: If format is invalid
        """
        valid_formats = ['csv', 'excel', 'xlsx', 'xls']
        if format.lower() not in valid_formats:
            raise ValidationError(f"Invalid export format: {format}")
    
    @staticmethod
    def sanitize_search_query(query: str) -> str:
        """
        Sanitize search query
        
        Args:
            query: Search query string
            
        Returns:
            Sanitized query string
        """
        if not query:
            return ""
        
        # Remove special SQL characters
        query = query.strip()
        query = re.sub(r'[;\'\"\\]', '', query)
        
        # Limit length
        return query[:100]
    
    @staticmethod
    def validate_pagination(page: int, per_page: int):
        """
        Validate pagination parameters
        
        Args:
            page: Page number
            per_page: Items per page
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if page < 1:
            raise ValidationError("Page number must be at least 1")
        
        if per_page < 1 or per_page > 100:
            raise ValidationError("Items per page must be between 1 and 100")


def validate_attendance_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate attendance form data
    
    Args:
        data: Dictionary of form data
        
    Returns:
        Validated and sanitized data
        
    Raises:
        ValidationError: If validation fails
    """
    validator = AttendanceValidator()
    
    # Validate required fields
    if 'date' in data and data['date']:
        if isinstance(data['date'], str):
            try:
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                raise ValidationError("Invalid date format. Use YYYY-MM-DD")
    
    # Validate status
    if 'status' in data and data['status']:
        validator.validate_status(data['status'])
    
    # Validate times
    if 'clock_in_time' in data and data['clock_in_time']:
        validator.validate_time_string(data['clock_in_time'])
    
    if 'clock_out_time' in data and data['clock_out_time']:
        validator.validate_time_string(data['clock_out_time'])
    
    # Validate reason/comments
    if 'reason' in data and data['reason']:
        validator.validate_reason(data['reason'])
    
    return data


def validate_bulk_operation_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate bulk operation data
    
    Args:
        data: Dictionary of form data
        
    Returns:
        Validated data
        
    Raises:
        ValidationError: If validation fails
    """
    validator = AttendanceValidator()
    
    # Validate user IDs
    if 'user_ids' not in data or not data['user_ids']:
        raise ValidationError("Please select at least one employee")
    
    user_ids = data['user_ids']
    if isinstance(user_ids, str):
        user_ids = [int(uid) for uid in user_ids.split(',') if uid.strip()]
    
    validator.validate_user_ids(user_ids)
    
    # Validate date
    if 'target_date' in data and data['target_date']:
        if isinstance(data['target_date'], str):
            try:
                target_date = datetime.strptime(data['target_date'], '%Y-%m-%d').date()
            except ValueError:
                raise ValidationError("Invalid date format")
            
            # Prevent future dates
            today = timezone.now().astimezone(IST).date()
            if target_date > today:
                raise ValidationError("Cannot perform bulk operations on future dates")
            
            data['target_date'] = target_date
    
    # Validate operation
    valid_operations = ['mark_present', 'mark_absent', 'mark_holiday', 'mark_weekend']
    if 'operation' not in data or data['operation'] not in valid_operations:
        raise ValidationError("Invalid operation selected")
    
    return data


def validate_report_filters(filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate report filter parameters
    
    Args:
        filters: Dictionary of filter parameters
        
    Returns:
        Validated filters
        
    Raises:
        ValidationError: If validation fails
    """
    validator = AttendanceValidator()
    
    # Validate date range
    if 'start_date' in filters and 'end_date' in filters:
        if filters['start_date'] and filters['end_date']:
            validator.validate_date_range(
                filters['start_date'],
                filters['end_date']
            )
    
    # Validate export format
    if 'export_format' in filters and filters['export_format']:
        validator.validate_export_format(filters['export_format'])
    
    # Sanitize search query
    if 'search' in filters and filters['search']:
        filters['search'] = validator.sanitize_search_query(filters['search'])
    
    # Validate pagination
    if 'page' in filters and 'per_page' in filters:
        validator.validate_pagination(
            int(filters.get('page', 1)),
            int(filters.get('per_page', 20))
        )
    
    return filters
