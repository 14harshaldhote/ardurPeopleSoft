"""
Smart Prioritization Engine for Dynamic Ticket Priority Calculation
Dynamically calculates ticket priority using:
- User tier (VIP, Internal, External)
- Ticket impact (Business Critical, High, Medium, Low)
- Time sensitivity/business context
- Historical patterns
- SLA requirements
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg
from django.utils import timezone
from django.core.cache import cache
from trueAlign.models import Support, UserDetails
from .logging_system import ticket_logger


class PrioritizationEngine:
    """
    Core prioritization engine that dynamically calculates ticket priority
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cache_timeout = 600  # 10 minutes cache

    def calculate_priority(self, ticket: Support, user: User = None) -> Tuple[str, Dict]:
        """
        Calculate dynamic priority for a ticket

        Args:
            ticket: Support ticket instance
            user: User requesting priority calculation (for logging)

        Returns:
            Tuple of (priority_level, calculation_details)
        """
        try:
            # Get priority factors
            factors = self._get_priority_factors(ticket)

            # Calculate base priority score
            base_score = self._calculate_base_score(ticket, factors)

            # Apply modifiers
            modified_score = self._apply_modifiers(ticket, base_score, factors)

            # Determine priority level
            priority_level = self._score_to_priority(modified_score)

            # Create calculation details
            calculation_details = {
                'base_score': base_score,
                'modified_score': modified_score,
                'priority_level': priority_level,
                'factors': factors,
                'calculation_timestamp': timezone.now().isoformat()
            }

            # Log priority calculation
            if user:
                ticket_logger.log_user_activity(
                    user,
                    'PRIORITY_CALCULATED',
                    calculation_details,
                    None
                )

            return priority_level, calculation_details

        except Exception as e:
            self.logger.error(f"Priority calculation failed for ticket {ticket.ticket_id}: {str(e)}")
            if user:
                ticket_logger.log_error(user, "PRIORITY_CALCULATION", e, ticket.ticket_id)
            # Return default priority on error
            return Support.Priority.MEDIUM, {'error': str(e)}

    def _get_priority_factors(self, ticket: Support) -> Dict:
        """
        Get all factors that influence ticket priority
        """
        factors = {
            'user_tier': self._get_user_tier(ticket.user),
            'business_impact': self._assess_business_impact(ticket),
            'time_sensitivity': self._assess_time_sensitivity(ticket),
            'issue_severity': self._assess_issue_severity(ticket),
            'customer_satisfaction': self._get_customer_satisfaction_factor(ticket.user),
            'historical_escalation': self._get_historical_escalation_factor(ticket),
            'workload_factor': self._get_workload_factor(ticket),
            'business_hours': self._is_business_hours(),
            'department_priority': self._get_department_priority(ticket),
            'asset_criticality': self._get_asset_criticality(ticket)
        }

        return factors

    def _calculate_base_score(self, ticket: Support, factors: Dict) -> float:
        """
        Calculate base priority score (0-100)
        """
        score = 0.0

        # User tier scoring (25% weight)
        user_tier_score = self._score_user_tier(factors['user_tier'])
        score += user_tier_score * 0.25

        # Business impact scoring (30% weight)
        business_impact_score = self._score_business_impact(factors['business_impact'])
        score += business_impact_score * 0.30

        # Time sensitivity scoring (20% weight)
        time_sensitivity_score = self._score_time_sensitivity(factors['time_sensitivity'])
        score += time_sensitivity_score * 0.20

        # Issue severity scoring (15% weight)
        issue_severity_score = self._score_issue_severity(factors['issue_severity'])
        score += issue_severity_score * 0.15

        # Customer satisfaction scoring (10% weight)
        customer_score = self._score_customer_satisfaction(factors['customer_satisfaction'])
        score += customer_score * 0.10

        return min(100.0, max(0.0, score))

    def _apply_modifiers(self, ticket: Support, base_score: float, factors: Dict) -> float:
        """
        Apply modifiers to base score
        """
        modified_score = base_score

        # Historical escalation modifier
        if factors['historical_escalation'] > 0.7:
            modified_score += 15  # Boost for users with escalation history

        # Workload modifier
        if factors['workload_factor'] > 0.8:
            modified_score += 10  # Boost during high workload

        # Business hours modifier
        if not factors['business_hours']:
            if ticket.issue_type in [Support.IssueType.SECURITY, Support.IssueType.NETWORK]:
                modified_score += 20  # Critical issues outside business hours
            else:
                modified_score -= 5  # Non-critical issues outside business hours

        # Department priority modifier
        if factors['department_priority'] == 'high':
            modified_score += 10
        elif factors['department_priority'] == 'low':
            modified_score -= 5

        # Asset criticality modifier
        if factors['asset_criticality'] == 'critical':
            modified_score += 15
        elif factors['asset_criticality'] == 'high':
            modified_score += 8

        # SLA breach risk modifier
        if self._is_sla_breach_risk(ticket):
            modified_score += 25

        return min(100.0, max(0.0, modified_score))

    def _score_to_priority(self, score: float) -> str:
        """
        Convert numerical score to priority level
        """
        if score >= 80:
            return Support.Priority.CRITICAL
        elif score >= 60:
            return Support.Priority.HIGH
        elif score >= 30:
            return Support.Priority.MEDIUM
        else:
            return Support.Priority.LOW

    def _get_user_tier(self, user: User) -> str:
        """
        Determine user tier based on role and profile
        """
        # Check if user is VIP (C-level, managers, etc.)
        if user.is_superuser or user.groups.filter(name__in=['Manager', 'Admin']).exists():
            return 'VIP'

        # Check if user is internal employee
        try:
            user_details = UserDetails.objects.get(user=user)
            if user_details.user_type == 'Employee':
                return 'Internal'
        except UserDetails.DoesNotExist:
            pass

        # Check if user is HR
        if user.groups.filter(name='HR').exists():
            return 'Internal'

        # Default to external
        return 'External'

    def _assess_business_impact(self, ticket: Support) -> str:
        """
        Assess business impact of the ticket
        """
        high_impact_types = [
            Support.IssueType.SECURITY,
            Support.IssueType.NETWORK,
            Support.IssueType.APPLICATION
        ]

        medium_impact_types = [
            Support.IssueType.SOFTWARE,
            Support.IssueType.HARDWARE,
            Support.IssueType.ACCESS
        ]

        if ticket.issue_type in high_impact_types:
            return 'high'
        elif ticket.issue_type in medium_impact_types:
            return 'medium'
        else:
            return 'low'

    def _assess_time_sensitivity(self, ticket: Support) -> str:
        """
        Assess time sensitivity based on issue type and keywords
        """
        urgent_keywords = [
            'urgent', 'emergency', 'critical', 'asap', 'immediately',
            'down', 'outage', 'not working', 'broken', 'failed'
        ]

        ticket_text = f"{ticket.subject} {ticket.description}".lower()

        # Check for urgent keywords
        if any(keyword in ticket_text for keyword in urgent_keywords):
            return 'urgent'

        # Check issue type time sensitivity
        if ticket.issue_type in [Support.IssueType.SECURITY, Support.IssueType.NETWORK]:
            return 'high'
        elif ticket.issue_type in [Support.IssueType.APPLICATION, Support.IssueType.SOFTWARE]:
            return 'medium'
        else:
            return 'low'

    def _assess_issue_severity(self, ticket: Support) -> str:
        """
        Assess severity based on issue type and description
        """
        severity_keywords = {
            'critical': ['system down', 'complete failure', 'security breach', 'data loss'],
            'high': ['partial failure', 'performance issue', 'access denied', 'slow'],
            'medium': ['minor issue', 'enhancement', 'question', 'how to'],
            'low': ['cosmetic', 'suggestion', 'future enhancement']
        }

        ticket_text = f"{ticket.subject} {ticket.description}".lower()

        for severity, keywords in severity_keywords.items():
            if any(keyword in ticket_text for keyword in keywords):
                return severity

        # Default based on issue type
        if ticket.issue_type == Support.IssueType.SECURITY:
            return 'critical'
        elif ticket.issue_type in [Support.IssueType.NETWORK, Support.IssueType.APPLICATION]:
            return 'high'
        else:
            return 'medium'

    def _get_customer_satisfaction_factor(self, user: User) -> float:
        """
        Get customer satisfaction factor based on user history
        """
        # Check recent ticket satisfaction ratings
        recent_tickets = Support.objects.filter(
            user=user,
            status__in=['Resolved', 'Closed'],
            satisfaction_rating__isnull=False,
            resolved_at__gte=timezone.now() - timedelta(days=90)
        ).aggregate(
            avg_rating=Avg('satisfaction_rating'),
            total_tickets=Count('id')
        )

        if recent_tickets['total_tickets'] > 0:
            avg_rating = recent_tickets['avg_rating'] or 3.0
            if avg_rating < 3.0:
                return 0.8  # Unsatisfied customer gets higher priority
            elif avg_rating > 4.0:
                return 0.6  # Very satisfied customer
            else:
                return 0.7  # Neutral

        return 0.5  # No history

    def _get_historical_escalation_factor(self, ticket: Support) -> float:
        """
        Get historical escalation factor for this user
        """
        # Check escalation history
        escalated_tickets = Support.objects.filter(
            user=ticket.user,
            escalation_level__gt=0,
            created_at__gte=timezone.now() - timedelta(days=180)
        ).count()

        total_tickets = Support.objects.filter(
            user=ticket.user,
            created_at__gte=timezone.now() - timedelta(days=180)
        ).count()

        if total_tickets > 0:
            return escalated_tickets / total_tickets

        return 0.0

    def _get_workload_factor(self, ticket: Support) -> float:
        """
        Get current workload factor for the assigned group
        """
        if not ticket.assigned_group:
            return 0.5

        # Get active tickets for the group
        active_tickets = Support.objects.filter(
            assigned_group=ticket.assigned_group,
            status__in=['New', 'Open', 'In Progress', 'Pending User Response']
        ).count()

        # Get available agents in the group
        try:
            from django.contrib.auth.models import Group
            group = Group.objects.get(name=ticket.assigned_group)
            available_agents = group.user_set.filter(is_active=True).count()

            if available_agents > 0:
                workload_per_agent = active_tickets / available_agents
                # Normalize to 0-1 scale (higher workload = higher factor)
                return min(1.0, workload_per_agent / 10)  # Assuming 10 tickets per agent is high

        except Group.DoesNotExist:
            pass

        return 0.5

    def _is_business_hours(self) -> bool:
        """
        Check if current time is within business hours
        """
        now = timezone.now()
        # Business hours: 9 AM - 6 PM, Monday to Friday
        if now.weekday() >= 5:  # Weekend
            return False

        current_hour = now.hour
        return 9 <= current_hour <= 18

    def _get_department_priority(self, ticket: Support) -> str:
        """
        Get department priority level
        """
        try:
            user_details = UserDetails.objects.get(user=ticket.user)
            department = user_details.department

            # High priority departments
            if department in ['IT', 'Finance', 'Operations']:
                return 'high'
            # Medium priority departments
            elif department in ['HR', 'Marketing', 'Sales']:
                return 'medium'
            else:
                return 'low'

        except UserDetails.DoesNotExist:
            return 'medium'

    def _get_asset_criticality(self, ticket: Support) -> str:
        """
        Get asset criticality based on asset_id
        """
        if not ticket.asset_id:
            return 'medium'

        # This could be enhanced with actual asset management integration
        asset_id = ticket.asset_id.upper()

        # Critical assets (servers, network equipment)
        if any(prefix in asset_id for prefix in ['SRV', 'NET', 'FW', 'SW']):
            return 'critical'
        # High priority assets (workstations, laptops)
        elif any(prefix in asset_id for prefix in ['WS', 'LT', 'PC']):
            return 'high'
        # Medium priority assets (peripherals, mobile devices)
        elif any(prefix in asset_id for prefix in ['PR', 'MB', 'PH']):
            return 'medium'
        else:
            return 'low'

    def _is_sla_breach_risk(self, ticket: Support) -> bool:
        """
        Check if ticket is at risk of SLA breach
        """
        if not ticket.sla_target_date:
            return False

        now = timezone.now()
        time_remaining = ticket.sla_target_date - now

        # Risk if less than 2 hours remaining
        return time_remaining.total_seconds() < 7200

    def _score_user_tier(self, tier: str) -> float:
        """
        Convert user tier to score (0-100)
        """
        tier_scores = {
            'VIP': 90,
            'Internal': 60,
            'External': 30
        }
        return tier_scores.get(tier, 50)

    def _score_business_impact(self, impact: str) -> float:
        """
        Convert business impact to score (0-100)
        """
        impact_scores = {
            'high': 90,
            'medium': 60,
            'low': 30
        }
        return impact_scores.get(impact, 50)

    def _score_time_sensitivity(self, sensitivity: str) -> float:
        """
        Convert time sensitivity to score (0-100)
        """
        sensitivity_scores = {
            'urgent': 95,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        return sensitivity_scores.get(sensitivity, 50)

    def _score_issue_severity(self, severity: str) -> float:
        """
        Convert issue severity to score (0-100)
        """
        severity_scores = {
            'critical': 100,
            'high': 80,
            'medium': 50,
            'low': 25
        }
        return severity_scores.get(severity, 50)

    def _score_customer_satisfaction(self, satisfaction: float) -> float:
        """
        Convert customer satisfaction to score (0-100)
        """
        # Invert satisfaction - lower satisfaction = higher priority
        return (1.0 - satisfaction) * 100

    def recalculate_all_priorities(self, user: User) -> Dict:
        """
        Recalculate priorities for all active tickets
        """
        active_tickets = Support.objects.filter(
            status__in=['New', 'Open', 'In Progress', 'Pending User Response']
        )

        results = {
            'total_tickets': active_tickets.count(),
            'updated_tickets': 0,
            'priority_changes': [],
            'errors': []
        }

        for ticket in active_tickets:
            try:
                old_priority = ticket.priority
                new_priority, calculation_details = self.calculate_priority(ticket, user)

                if old_priority != new_priority:
                    ticket.priority = new_priority
                    ticket.save()

                    results['priority_changes'].append({
                        'ticket_id': ticket.ticket_id,
                        'old_priority': old_priority,
                        'new_priority': new_priority,
                        'score': calculation_details['modified_score']
                    })

                    # Log priority change
                    ticket_logger.log_user_activity(
                        user,
                        'PRIORITY_RECALCULATED',
                        {
                            'ticket_id': ticket.ticket_id,
                            'old_priority': old_priority,
                            'new_priority': new_priority,
                            'calculation_details': calculation_details
                        }
                    )

                results['updated_tickets'] += 1

            except Exception as e:
                results['errors'].append({
                    'ticket_id': ticket.ticket_id,
                    'error': str(e)
                })

        return results

    def get_priority_statistics(self, days: int = 30) -> Dict:
        """
        Get priority statistics for analysis
        """
        start_date = timezone.now() - timedelta(days=days)

        stats = Support.objects.filter(
            created_at__gte=start_date
        ).values('priority').annotate(
            count=Count('id'),
            avg_resolution_time=Avg('resolution_time')
        ).order_by('-count')

        return {
            'priority_distribution': list(stats),
            'total_tickets': sum(stat['count'] for stat in stats),
            'period_days': days
        }


# Global prioritization engine instance
prioritization_engine = PrioritizationEngine()
