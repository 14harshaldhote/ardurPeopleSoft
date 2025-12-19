# attendance/exceptions.py
"""
Attendance Custom Exceptions

Standardized exception classes for attendance module.
"""


class AttendanceError(Exception):
    """Base exception for attendance module"""

    pass


class InvalidDateRangeError(AttendanceError):
    """Invalid date range provided"""

    def __init__(self, message="Invalid date range"):
        self.message = message
        super().__init__(self.message)


class AttendanceNotFoundError(AttendanceError):
    """Attendance record not found"""

    def __init__(self, user=None, date=None):
        if user and date:
            self.message = f"Attendance record not found for {user} on {date}"
        else:
            self.message = "Attendance record not found"
        super().__init__(self.message)


class UnauthorizedActionError(AttendanceError):
    """User not authorized for action"""

    def __init__(self, action=None):
        if action:
            self.message = f"Not authorized to perform action: {action}"
        else:
            self.message = "Unauthorized action"
        super().__init__(self.message)


class RegularizationError(AttendanceError):
    """Regularization request error"""

    pass


class BulkOperationError(AttendanceError):
    """Bulk operation error"""

    pass


class ValidationError(AttendanceError):
    """Data validation error"""

    def __init__(self, field=None, message=None):
        if field and message:
            self.message = f"Validation error in {field}: {message}"
        elif message:
            self.message = message
        else:
            self.message = "Validation error"
        super().__init__(self.message)
