"""
Audit logging for leave management operations
"""
import logging
from django.contrib.auth.models import User
from django.utils import timezone
from typing import Dict, Any, Optional

# Create audit logger
audit_logger = logging.getLogger('leave_management.audit')

class LeaveAuditLogger:
    """Centralized audit logging for leave management"""
    
    @staticmethod
    def log_leave_application(user: User, leave_request, result: Dict[str, Any]):
        """Log leave application attempt"""
        audit_logger.info(
            f"LEAVE_APPLICATION | User: {user.username} | "
            f"Type: {leave_request.leave_type.name if leave_request.leave_type else 'N/A'} | "
            f"Dates: {leave_request.start_date} to {leave_request.end_date} | "
            f"Status: {'SUCCESS' if result.get('is_valid') else 'FAILED'} | "
            f"Errors: {result.get('errors', [])} | "
            f"Request ID: {getattr(leave_request, 'id', 'N/A')} | "
            f"Timestamp: {timezone.now()}"
        )
    
    @staticmethod
    def log_leave_approval(approver: User, leave_request, action: str, comments: str = ""):
        """Log leave approval/rejection"""
        audit_logger.info(
            f"LEAVE_{action.upper()} | Approver: {approver.username} | "
            f"Employee: {leave_request.user.username} | "
            f"Request ID: {leave_request.id} | "
            f"Type: {leave_request.leave_type.name} | "
            f"Dates: {leave_request.start_date} to {leave_request.end_date} | "
            f"Comments: {comments} | "
            f"Timestamp: {timezone.now()}"
        )
    
    @staticmethod
    def log_leave_cancellation(user: User, leave_request, reason: str = ""):
        """Log leave cancellation"""
        audit_logger.info(
            f"LEAVE_CANCELLATION | User: {user.username} | "
            f"Request ID: {leave_request.id} | "
            f"Type: {leave_request.leave_type.name} | "
            f"Dates: {leave_request.start_date} to {leave_request.end_date} | "
            f"Reason: {reason} | "
            f"Timestamp: {timezone.now()}"
        )
    
    @staticmethod
    def log_balance_adjustment(admin_user: User, target_user: User, leave_type, 
                             adjustment_type: str, amount: float, reason: str = ""):
        """Log manual balance adjustments"""
        audit_logger.info(
            f"BALANCE_ADJUSTMENT | Admin: {admin_user.username} | "
            f"Target User: {target_user.username} | "
            f"Leave Type: {leave_type.name} | "
            f"Adjustment: {adjustment_type} {amount} days | "
            f"Reason: {reason} | "
            f"Timestamp: {timezone.now()}"
        )
    
    @staticmethod
    def log_comp_off_request(user: User, comp_off_request, result: Dict[str, Any]):
        """Log comp-off request"""
        audit_logger.info(
            f"COMP_OFF_REQUEST | User: {user.username} | "
            f"Worked Date: {comp_off_request.worked_date} | "
            f"Hours: {comp_off_request.hours_worked} | "
            f"Status: {'SUCCESS' if result.get('success') else 'FAILED'} | "
            f"Request ID: {result.get('request_id', 'N/A')} | "
            f"Timestamp: {timezone.now()}"
        )
    
    @staticmethod
    def log_security_event(user: User, event_type: str, details: str):
        """Log security-related events"""
        audit_logger.warning(
            f"SECURITY_EVENT | User: {user.username} | "
            f"Event: {event_type} | "
            f"Details: {details} | "
            f"IP: {getattr(user, 'last_login_ip', 'N/A')} | "
            f"Timestamp: {timezone.now()}"
        )
    
    @staticmethod
    def log_data_access(user: User, accessed_user: Optional[User], data_type: str):
        """Log data access events"""
        target = accessed_user.username if accessed_user else "SYSTEM"
        audit_logger.info(
            f"DATA_ACCESS | Accessor: {user.username} | "
            f"Target: {target} | "
            f"Data Type: {data_type} | "
            f"Timestamp: {timezone.now()}"
        )
