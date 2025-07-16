"""
Enhanced Logging System for Smart Ticketing
Provides structured, role-aware logging with audit trail capabilities
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
from django.conf import settings
import traceback


class TicketLogger:
    """
    Enhanced logging system for ticket operations with structured JSON logging
    """

    def __init__(self, logger_name: str = 'ticket_system'):
        self.logger = logging.getLogger(logger_name)
        self.setup_logger()

    def setup_logger(self):
        """Configure structured logging with JSON format"""
        if not self.logger.handlers:
            # Create file handler
            log_file = getattr(settings, 'TICKET_LOG_FILE', 'logs/ticket_system.log')
            handler = logging.FileHandler(log_file)
            handler.setLevel(logging.INFO)

            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)

            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def create_log_entry(self,
                        action: str,
                        user: User,
                        ticket_id: str = None,
                        details: Dict[str, Any] = None,
                        level: str = 'INFO',
                        request_id: str = None) -> Dict[str, Any]:
        """
        Create structured log entry
        """
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'request_id': request_id or str(uuid.uuid4()),
            'action': action,
            'user': {
                'id': user.id if user else None,
                'username': user.username if user else 'system',
                'email': user.email if user else None,
                'groups': [g.name for g in user.groups.all()] if user else [],
                'is_staff': user.is_staff if user else False,
                'is_superuser': user.is_superuser if user else False
            },
            'ticket_id': ticket_id,
            'details': details or {},
            'level': level,
            'system_info': {
                'django_version': getattr(settings, 'DJANGO_VERSION', 'unknown'),
                'environment': getattr(settings, 'ENVIRONMENT', 'development')
            }
        }

        return log_entry

    def log_ticket_creation(self, user: User, ticket, request_id: str = None):
        """Log ticket creation event"""
        log_entry = self.create_log_entry(
            action='TICKET_CREATED',
            user=user,
            ticket_id=ticket.ticket_id,
            details={
                'issue_type': ticket.issue_type,
                'priority': ticket.priority,
                'subject': ticket.subject,
                'assigned_group': ticket.assigned_group,
                'assigned_to': ticket.assigned_to_user.username if ticket.assigned_to_user else None,
                'sla_target': ticket.sla_target_date.isoformat() if ticket.sla_target_date else None
            },
            request_id=request_id
        )

        self.logger.info(json.dumps(log_entry))

        # Store in database for audit trail
        AuditLog.objects.create(
            action='TICKET_CREATED',
            user=user,
            ticket_id=ticket.ticket_id,
            log_data=log_entry
        )

    def log_status_change(self, user: User, ticket, old_status: str, new_status: str, request_id: str = None):
        """Log ticket status change"""
        log_entry = self.create_log_entry(
            action='STATUS_CHANGED',
            user=user,
            ticket_id=ticket.ticket_id,
            details={
                'old_status': old_status,
                'new_status': new_status,
                'reason': 'User initiated',
                'sla_status': ticket.sla_status,
                'is_overdue': ticket.is_overdue
            },
            request_id=request_id
        )

        self.logger.info(json.dumps(log_entry))

        AuditLog.objects.create(
            action='STATUS_CHANGED',
            user=user,
            ticket_id=ticket.ticket_id,
            log_data=log_entry
        )

    def log_assignment(self, user: User, ticket, assigned_to: User, request_id: str = None):
        """Log ticket assignment"""
        log_entry = self.create_log_entry(
            action='TICKET_ASSIGNED',
            user=user,
            ticket_id=ticket.ticket_id,
            details={
                'assigned_to': {
                    'id': assigned_to.id,
                    'username': assigned_to.username,
                    'email': assigned_to.email,
                    'groups': [g.name for g in assigned_to.groups.all()]
                },
                'assignment_reason': 'Manual assignment',
                'workload_before': self._get_agent_workload(assigned_to),
                'priority': ticket.priority
            },
            request_id=request_id
        )

        self.logger.info(json.dumps(log_entry))

        AuditLog.objects.create(
            action='TICKET_ASSIGNED',
            user=user,
            ticket_id=ticket.ticket_id,
            log_data=log_entry
        )

    def log_bulk_operation(self, user: User, operation: str, ticket_ids: List[str],
                          details: Dict[str, Any], request_id: str = None):
        """Log bulk operations"""
        log_entry = self.create_log_entry(
            action=f'BULK_{operation.upper()}',
            user=user,
            details={
                'operation': operation,
                'ticket_count': len(ticket_ids),
                'ticket_ids': ticket_ids,
                'operation_details': details,
                'success_count': details.get('success_count', 0),
                'error_count': details.get('error_count', 0)
            },
            request_id=request_id
        )

        self.logger.info(json.dumps(log_entry))

        AuditLog.objects.create(
            action=f'BULK_{operation.upper()}',
            user=user,
            log_data=log_entry
        )

    def log_sla_violation(self, ticket, violation_type: str, request_id: str = None):
        """Log SLA violations"""
        log_entry = self.create_log_entry(
            action='SLA_VIOLATION',
            user=None,  # System event
            ticket_id=ticket.ticket_id,
            details={
                'violation_type': violation_type,
                'sla_target': ticket.sla_target_date.isoformat() if ticket.sla_target_date else None,
                'current_time': timezone.now().isoformat(),
                'priority': ticket.priority,
                'assigned_to': ticket.assigned_to_user.username if ticket.assigned_to_user else None,
                'age_hours': self._calculate_ticket_age_hours(ticket)
            },
            level='WARNING',
            request_id=request_id
        )

        self.logger.warning(json.dumps(log_entry))

        AuditLog.objects.create(
            action='SLA_VIOLATION',
            ticket_id=ticket.ticket_id,
            log_data=log_entry
        )

    def log_escalation(self, user: User, ticket, escalation_level: int, request_id: str = None):
        """Log ticket escalation"""
        log_entry = self.create_log_entry(
            action='TICKET_ESCALATED',
            user=user,
            ticket_id=ticket.ticket_id,
            details={
                'escalation_level': escalation_level,
                'reason': 'SLA breach' if ticket.sla_breach else 'Manual escalation',
                'priority': ticket.priority,
                'age_hours': self._calculate_ticket_age_hours(ticket),
                'assigned_to': ticket.assigned_to_user.username if ticket.assigned_to_user else None
            },
            level='WARNING',
            request_id=request_id
        )

        self.logger.warning(json.dumps(log_entry))

        AuditLog.objects.create(
            action='TICKET_ESCALATED',
            user=user,
            ticket_id=ticket.ticket_id,
            log_data=log_entry
        )

    def log_error(self, user: User, action: str, error: Exception,
                 ticket_id: str = None, request_id: str = None):
        """Log system errors"""
        log_entry = self.create_log_entry(
            action=f'ERROR_{action.upper()}',
            user=user,
            ticket_id=ticket_id,
            details={
                'error_type': type(error).__name__,
                'error_message': str(error),
                'traceback': traceback.format_exc(),
                'action_attempted': action
            },
            level='ERROR',
            request_id=request_id
        )

        self.logger.error(json.dumps(log_entry))

        AuditLog.objects.create(
            action=f'ERROR_{action.upper()}',
            user=user,
            ticket_id=ticket_id,
            log_data=log_entry
        )

    def log_user_activity(self, user: User, activity: str, details: Dict[str, Any],
                         request_id: str = None):
        """Log user activities"""
        log_entry = self.create_log_entry(
            action=f'USER_{activity.upper()}',
            user=user,
            details=details,
            request_id=request_id
        )

        self.logger.info(json.dumps(log_entry))

        AuditLog.objects.create(
            action=f'USER_{activity.upper()}',
            user=user,
            log_data=log_entry
        )

    def _get_agent_workload(self, user: User) -> int:
        """Get current workload for an agent"""
        from trueAlign.models import Support
        return Support.objects.filter(
            assigned_to_user=user,
            status__in=['Open', 'In Progress', 'Pending User Response']
        ).count()

    def _calculate_ticket_age_hours(self, ticket) -> float:
        """Calculate ticket age in hours"""
        if ticket.created_at:
            return (timezone.now() - ticket.created_at).total_seconds() / 3600
        return 0


class AuditLog(models.Model):
    """
    Database model for storing audit logs
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    action = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ticket_id = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    log_data = models.JSONField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        db_table = 'support_audit_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ticket_id', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.action} - {self.user.username if self.user else 'System'} - {self.timestamp}"


class LogAnalyzer:
    """
    Analyzer for ticket logs to provide insights
    """

    @staticmethod
    def get_user_activity_summary(user: User, start_date: datetime, end_date: datetime) -> Dict:
        """Get user activity summary"""
        logs = AuditLog.objects.filter(
            user=user,
            timestamp__range=[start_date, end_date]
        ).values('action').annotate(
            count=models.Count('id')
        ).order_by('-count')

        return {
            'total_actions': sum(log['count'] for log in logs),
            'action_breakdown': list(logs),
            'most_common_action': logs[0]['action'] if logs else None
        }

    @staticmethod
    def get_ticket_activity_timeline(ticket_id: str) -> List[Dict]:
        """Get complete activity timeline for a ticket"""
        return list(AuditLog.objects.filter(
            ticket_id=ticket_id
        ).order_by('timestamp').values(
            'action', 'timestamp', 'user__username', 'log_data'
        ))

    @staticmethod
    def get_sla_violation_trends(days: int = 30) -> Dict:
        """Get SLA violation trends"""
        start_date = timezone.now() - timezone.timedelta(days=days)

        violations = AuditLog.objects.filter(
            action='SLA_VIOLATION',
            timestamp__gte=start_date
        ).extra(
            select={'day': 'DATE(timestamp)'}
        ).values('day').annotate(
            count=models.Count('id')
        ).order_by('day')

        return {
            'total_violations': sum(v['count'] for v in violations),
            'daily_breakdown': list(violations),
            'trend_analysis': 'increasing' if len(violations) > 1 and violations[-1]['count'] > violations[0]['count'] else 'stable'
        }


# Global logger instance
ticket_logger = TicketLogger()
