"""
Advanced SLA Management Engine
Monitor SLAs with respect to business hours
Enable automatic escalation based on ticket age and severity
Notify managers before SLA violations
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from django.contrib.auth.models import User, Group
from django.db.models import Q, Count, Avg, F
from django.utils import timezone
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
from trueAlign.models import Support, UserDetails
from .logging_system import ticket_logger


class SLAEngine:
    """
    Advanced SLA management engine for ticket system
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cache_timeout = 300  # 5 minutes cache

        # Business hours configuration
        self.business_hours = {
            'start': 9,  # 9 AM
            'end': 18,   # 6 PM
            'weekdays': [0, 1, 2, 3, 4],  # Monday to Friday
            'timezone': timezone.get_current_timezone()
        }

        # SLA targets in business hours
        self.sla_targets = {
            Support.Priority.CRITICAL: {
                'response_time': 1,  # 1 hour
                'resolution_time': 4,  # 4 hours
                'escalation_levels': [2, 4, 6]  # Hours for each escalation level
            },
            Support.Priority.HIGH: {
                'response_time': 2,  # 2 hours
                'resolution_time': 8,  # 8 hours
                'escalation_levels': [4, 8, 12]
            },
            Support.Priority.MEDIUM: {
                'response_time': 4,  # 4 hours
                'resolution_time': 24,  # 24 hours
                'escalation_levels': [8, 16, 24]
            },
            Support.Priority.LOW: {
                'response_time': 8,  # 8 hours
                'resolution_time': 48,  # 48 hours
                'escalation_levels': [16, 32, 48]
            }
        }

    def calculate_sla_target(self, ticket: Support) -> datetime:
        """
        Calculate SLA target date considering business hours
        """
        try:
            priority = ticket.priority
            resolution_hours = self.sla_targets[priority]['resolution_time']

            # Start from ticket creation time
            start_time = ticket.created_at
            target_time = self._add_business_hours(start_time, resolution_hours)

            return target_time

        except KeyError:
            # Default to 24 hours for unknown priorities
            return self._add_business_hours(ticket.created_at, 24)

    def calculate_response_sla_target(self, ticket: Support) -> datetime:
        """
        Calculate response SLA target date considering business hours
        """
        try:
            priority = ticket.priority
            response_hours = self.sla_targets[priority]['response_time']

            return self._add_business_hours(ticket.created_at, response_hours)

        except KeyError:
            # Default to 4 hours for unknown priorities
            return self._add_business_hours(ticket.created_at, 4)

    def _add_business_hours(self, start_time: datetime, hours_to_add: int) -> datetime:
        """
        Add business hours to a datetime, skipping weekends and non-business hours
        """
        current_time = start_time
        remaining_hours = hours_to_add

        while remaining_hours > 0:
            # If current time is outside business hours, move to next business hour
            if not self._is_business_time(current_time):
                current_time = self._next_business_hour(current_time)
                continue

            # Calculate hours until end of business day
            hours_until_end = self._hours_until_business_end(current_time)

            if remaining_hours <= hours_until_end:
                # Can fit remaining hours in current business day
                current_time += timedelta(hours=remaining_hours)
                remaining_hours = 0
            else:
                # Need to continue to next business day
                remaining_hours -= hours_until_end
                current_time = self._next_business_hour(
                    current_time + timedelta(days=1)
                )

        return current_time

    def _is_business_time(self, dt: datetime) -> bool:
        """
        Check if datetime is within business hours
        """
        # Check if it's a weekday
        if dt.weekday() not in self.business_hours['weekdays']:
            return False

        # Check if it's within business hours
        hour = dt.hour
        return self.business_hours['start'] <= hour < self.business_hours['end']

    def _next_business_hour(self, dt: datetime) -> datetime:
        """
        Get the next business hour from given datetime
        """
        # Set to start of business hours
        next_dt = dt.replace(hour=self.business_hours['start'], minute=0, second=0, microsecond=0)

        # If it's weekend, move to next Monday
        while next_dt.weekday() not in self.business_hours['weekdays']:
            next_dt += timedelta(days=1)

        return next_dt

    def _hours_until_business_end(self, dt: datetime) -> float:
        """
        Calculate hours until end of business day
        """
        end_time = dt.replace(hour=self.business_hours['end'], minute=0, second=0, microsecond=0)
        return (end_time - dt).total_seconds() / 3600

    def check_sla_violations(self) -> Dict:
        """
        Check for SLA violations across all active tickets
        """
        violations = {
            'response_violations': [],
            'resolution_violations': [],
            'escalation_candidates': [],
            'summary': {
                'total_violations': 0,
                'critical_violations': 0,
                'high_violations': 0
            }
        }

        # Get all active tickets
        active_tickets = Support.objects.filter(
            status__in=['New', 'Open', 'In Progress', 'Pending User Response'],
            is_deleted=False
        )

        for ticket in active_tickets:
            # Check response SLA
            if not ticket.response_time:
                response_target = self.calculate_response_sla_target(ticket)
                if timezone.now() > response_target:
                    violations['response_violations'].append({
                        'ticket': ticket,
                        'target': response_target,
                        'breach_time': timezone.now() - response_target
                    })

            # Check resolution SLA
            if ticket.sla_target_date and timezone.now() > ticket.sla_target_date:
                violations['resolution_violations'].append({
                    'ticket': ticket,
                    'target': ticket.sla_target_date,
                    'breach_time': timezone.now() - ticket.sla_target_date
                })

            # Check escalation candidates
            escalation_candidate = self._check_escalation_needed(ticket)
            if escalation_candidate:
                violations['escalation_candidates'].append(escalation_candidate)

        # Update summary
        violations['summary']['total_violations'] = (
            len(violations['response_violations']) +
            len(violations['resolution_violations'])
        )

        for violation in violations['response_violations'] + violations['resolution_violations']:
            if violation['ticket'].priority == Support.Priority.CRITICAL:
                violations['summary']['critical_violations'] += 1
            elif violation['ticket'].priority == Support.Priority.HIGH:
                violations['summary']['high_violations'] += 1

        return violations

    def _check_escalation_needed(self, ticket: Support) -> Optional[Dict]:
        """
        Check if ticket needs escalation based on age and priority
        """
        priority = ticket.priority
        escalation_levels = self.sla_targets.get(priority, {}).get('escalation_levels', [])

        if not escalation_levels:
            return None

        # Calculate ticket age in business hours
        age_hours = self._calculate_business_hours_age(ticket)

        # Determine escalation level needed
        needed_escalation = 0
        for level, threshold in enumerate(escalation_levels, 1):
            if age_hours >= threshold:
                needed_escalation = level
            else:
                break

        if needed_escalation > ticket.escalation_level:
            return {
                'ticket': ticket,
                'current_level': ticket.escalation_level,
                'needed_level': needed_escalation,
                'age_hours': age_hours,
                'threshold': escalation_levels[needed_escalation - 1]
            }

        return None

    def _calculate_business_hours_age(self, ticket: Support) -> float:
        """
        Calculate ticket age in business hours only
        """
        start_time = ticket.created_at
        end_time = timezone.now()

        total_business_hours = 0
        current_time = start_time

        while current_time < end_time:
            if self._is_business_time(current_time):
                # Add one hour if we're in business time
                next_hour = current_time + timedelta(hours=1)
                if next_hour <= end_time:
                    total_business_hours += 1
                    current_time = next_hour
                else:
                    # Add partial hour
                    partial_hours = (end_time - current_time).total_seconds() / 3600
                    total_business_hours += partial_hours
                    break
            else:
                # Jump to next business hour
                current_time = self._next_business_hour(current_time)

        return total_business_hours

    def escalate_ticket(self, ticket: Support, escalation_level: int, user: User = None) -> bool:
        """
        Escalate ticket to specified level
        """
        try:
            old_level = ticket.escalation_level
            ticket.escalation_level = escalation_level
            ticket.save()

            # Create escalation activity
            from trueAlign.models import TicketActivity
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.ESCALATED,
                user=user,
                details=f"Escalated from level {old_level} to level {escalation_level}"
            )

            # Notify escalation recipients
            self._notify_escalation(ticket, escalation_level, user)

            # Log escalation
            ticket_logger.log_escalation(user, ticket, escalation_level)

            return True

        except Exception as e:
            self.logger.error(f"Escalation failed for ticket {ticket.ticket_id}: {str(e)}")
            if user:
                ticket_logger.log_error(user, "ESCALATION", e, ticket.ticket_id)
            return False

    def _notify_escalation(self, ticket: Support, escalation_level: int, user: User = None):
        """
        Send escalation notifications
        """
        try:
            # Get escalation recipients based on level
            recipients = self._get_escalation_recipients(ticket, escalation_level)

            if not recipients:
                return

            subject = f"Ticket Escalated - {ticket.ticket_id} (Level {escalation_level})"
            message = f"""
            Ticket {ticket.ticket_id} has been escalated to Level {escalation_level}.

            Subject: {ticket.subject}
            Priority: {ticket.priority}
            Issue Type: {ticket.issue_type}
            Created: {ticket.created_at}
            Assigned to: {ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'Unassigned'}

            Current Status: {ticket.status}
            SLA Target: {ticket.sla_target_date}

            Please take immediate action to resolve this ticket.
            """

            # Send email notifications
            for recipient in recipients:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [recipient.email],
                    fail_silently=True
                )

        except Exception as e:
            self.logger.error(f"Failed to send escalation notification: {str(e)}")

    def _get_escalation_recipients(self, ticket: Support, escalation_level: int) -> List[User]:
        """
        Get escalation recipients based on level
        """
        recipients = []

        try:
            if escalation_level == 1:
                # Level 1: Team leads/managers in the same group
                if ticket.assigned_group:
                    group = Group.objects.get(name=ticket.assigned_group)
                    # Get managers in the group
                    managers = group.user_set.filter(
                        groups__name='Manager',
                        is_active=True
                    )
                    recipients.extend(managers)

            elif escalation_level == 2:
                # Level 2: Department heads
                if ticket.assigned_group == 'HR':
                    hr_heads = User.objects.filter(
                        groups__name='HR',
                        is_staff=True,
                        is_active=True
                    )
                    recipients.extend(hr_heads)
                else:
                    admin_heads = User.objects.filter(
                        groups__name='Admin',
                        is_staff=True,
                        is_active=True
                    )
                    recipients.extend(admin_heads)

            elif escalation_level >= 3:
                # Level 3+: Senior management
                senior_managers = User.objects.filter(
                    is_superuser=True,
                    is_active=True
                )
                recipients.extend(senior_managers)

        except Group.DoesNotExist:
            pass

        return list(set(recipients))  # Remove duplicates

    def send_sla_warnings(self) -> Dict:
        """
        Send warnings before SLA violations
        """
        warnings_sent = {
            'response_warnings': 0,
            'resolution_warnings': 0,
            'escalation_warnings': 0
        }

        # Get tickets approaching SLA breach
        approaching_tickets = self._get_approaching_sla_tickets()

        for ticket_info in approaching_tickets:
            try:
                self._send_sla_warning(ticket_info)

                if ticket_info['warning_type'] == 'response':
                    warnings_sent['response_warnings'] += 1
                elif ticket_info['warning_type'] == 'resolution':
                    warnings_sent['resolution_warnings'] += 1
                elif ticket_info['warning_type'] == 'escalation':
                    warnings_sent['escalation_warnings'] += 1

            except Exception as e:
                self.logger.error(f"Failed to send SLA warning for ticket {ticket_info['ticket'].ticket_id}: {str(e)}")

        return warnings_sent

    def _get_approaching_sla_tickets(self) -> List[Dict]:
        """
        Get tickets approaching SLA breach
        """
        approaching_tickets = []
        warning_threshold = timedelta(hours=2)  # Warn 2 hours before breach

        active_tickets = Support.objects.filter(
            status__in=['New', 'Open', 'In Progress', 'Pending User Response'],
            is_deleted=False
        )

        for ticket in active_tickets:
            now = timezone.now()

            # Check response SLA
            if not ticket.response_time:
                response_target = self.calculate_response_sla_target(ticket)
                if now + warning_threshold >= response_target > now:
                    approaching_tickets.append({
                        'ticket': ticket,
                        'warning_type': 'response',
                        'target': response_target,
                        'time_remaining': response_target - now
                    })

            # Check resolution SLA
            if ticket.sla_target_date:
                if now + warning_threshold >= ticket.sla_target_date > now:
                    approaching_tickets.append({
                        'ticket': ticket,
                        'warning_type': 'resolution',
                        'target': ticket.sla_target_date,
                        'time_remaining': ticket.sla_target_date - now
                    })

            # Check escalation
            escalation_candidate = self._check_escalation_needed(ticket)
            if escalation_candidate:
                approaching_tickets.append({
                    'ticket': ticket,
                    'warning_type': 'escalation',
                    'escalation_info': escalation_candidate
                })

        return approaching_tickets

    def _send_sla_warning(self, ticket_info: Dict):
        """
        Send individual SLA warning
        """
        ticket = ticket_info['ticket']
        warning_type = ticket_info['warning_type']

        # Get recipients
        recipients = []
        if ticket.assigned_to_user:
            recipients.append(ticket.assigned_to_user)

        # Add managers
        if ticket.assigned_group:
            try:
                group = Group.objects.get(name=ticket.assigned_group)
                managers = group.user_set.filter(
                    groups__name='Manager',
                    is_active=True
                )
                recipients.extend(managers)
            except Group.DoesNotExist:
                pass

        if not recipients:
            return

        # Prepare message based on warning type
        if warning_type == 'response':
            subject = f"SLA Warning - Response Due Soon - {ticket.ticket_id}"
            time_remaining = ticket_info['time_remaining']
            message = f"""
            URGENT: Response SLA for ticket {ticket.ticket_id} is due in {time_remaining}.

            Subject: {ticket.subject}
            Priority: {ticket.priority}
            Created: {ticket.created_at}
            Response Due: {ticket_info['target']}

            Please respond to this ticket immediately to avoid SLA breach.
            """
        elif warning_type == 'resolution':
            subject = f"SLA Warning - Resolution Due Soon - {ticket.ticket_id}"
            time_remaining = ticket_info['time_remaining']
            message = f"""
            URGENT: Resolution SLA for ticket {ticket.ticket_id} is due in {time_remaining}.

            Subject: {ticket.subject}
            Priority: {ticket.priority}
            Created: {ticket.created_at}
            Resolution Due: {ticket_info['target']}

            Please resolve this ticket immediately to avoid SLA breach.
            """
        else:  # escalation
            subject = f"SLA Warning - Escalation Required - {ticket.ticket_id}"
            escalation_info = ticket_info['escalation_info']
            message = f"""
            URGENT: Ticket {ticket.ticket_id} requires escalation to Level {escalation_info['needed_level']}.

            Subject: {ticket.subject}
            Priority: {ticket.priority}
            Current Level: {escalation_info['current_level']}
            Required Level: {escalation_info['needed_level']}
            Ticket Age: {escalation_info['age_hours']:.1f} business hours

            Please escalate this ticket immediately.
            """

        # Send notifications
        for recipient in recipients:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [recipient.email],
                fail_silently=True
            )

    def update_ticket_sla_status(self, ticket: Support):
        """
        Update SLA status for a ticket
        """
        now = timezone.now()

        # Check if ticket is resolved
        if ticket.status in ['Resolved', 'Closed']:
            if ticket.resolved_at and ticket.sla_target_date:
                if ticket.resolved_at <= ticket.sla_target_date:
                    ticket.sla_status = Support.SLAStatus.WITHIN_SLA
                    ticket.sla_breach = False
                else:
                    ticket.sla_status = Support.SLAStatus.BREACHED
                    ticket.sla_breach = True
        else:
            # Active ticket - check if SLA is breached
            if ticket.sla_target_date and now > ticket.sla_target_date:
                ticket.sla_status = Support.SLAStatus.BREACHED
                ticket.sla_breach = True
            else:
                ticket.sla_status = Support.SLAStatus.WITHIN_SLA
                ticket.sla_breach = False

        ticket.save(update_fields=['sla_status', 'sla_breach'])

    def get_sla_metrics(self, days: int = 30) -> Dict:
        """
        Get SLA performance metrics
        """
        start_date = timezone.now() - timedelta(days=days)

        # Get completed tickets in the period
        completed_tickets = Support.objects.filter(
            status__in=['Resolved', 'Closed'],
            resolved_at__gte=start_date
        )

        total_tickets = completed_tickets.count()

        if total_tickets == 0:
            return {
                'total_tickets': 0,
                'sla_compliance_rate': 0,
                'average_resolution_time': 0,
                'priority_breakdown': {}
            }

        # Calculate compliance rate
        within_sla = completed_tickets.filter(sla_status=Support.SLAStatus.WITHIN_SLA).count()
        compliance_rate = (within_sla / total_tickets) * 100

        # Calculate average resolution time
        avg_resolution = completed_tickets.aggregate(
            avg_time=Avg('resolution_time')
        )['avg_time']

        # Priority breakdown
        priority_breakdown = {}
        for priority in Support.Priority.choices:
            priority_tickets = completed_tickets.filter(priority=priority[0])
            priority_count = priority_tickets.count()
            priority_within_sla = priority_tickets.filter(sla_status=Support.SLAStatus.WITHIN_SLA).count()

            if priority_count > 0:
                priority_breakdown[priority[0]] = {
                    'total': priority_count,
                    'within_sla': priority_within_sla,
                    'compliance_rate': (priority_within_sla / priority_count) * 100
                }

        return {
            'total_tickets': total_tickets,
            'sla_compliance_rate': compliance_rate,
            'average_resolution_time': avg_resolution.total_seconds() / 3600 if avg_resolution else 0,
            'priority_breakdown': priority_breakdown,
            'period_days': days
        }

    def run_sla_monitoring(self) -> Dict:
        """
        Run complete SLA monitoring cycle
        """
        results = {
            'violations_checked': 0,
            'warnings_sent': 0,
            'escalations_processed': 0,
            'errors': []
        }

        try:
            # Check violations
            violations = self.check_sla_violations()
            results['violations_checked'] = violations['summary']['total_violations']

            # Send warnings
            warnings = self.send_sla_warnings()
            results['warnings_sent'] = sum(warnings.values())

            # Process escalations
            for escalation in violations['escalation_candidates']:
                try:
                    ticket = escalation['ticket']
                    needed_level = escalation['needed_level']

                    if self.escalate_ticket(ticket, needed_level):
                        results['escalations_processed'] += 1

                except Exception as e:
                    results['errors'].append({
                        'ticket_id': escalation['ticket'].ticket_id,
                        'error': str(e)
                    })

            # Log monitoring results
            ticket_logger.log_user_activity(
                None,  # System activity
                'SLA_MONITORING',
                results
            )

        except Exception as e:
            self.logger.error(f"SLA monitoring failed: {str(e)}")
            results['errors'].append({'system_error': str(e)})

        return results


# Global SLA engine instance
sla_engine = SLAEngine()
