"""
Intelligent Assignment Engine for Smart Ticketing System
Automatically assigns tickets using multi-factor rule engine based on:
- Agent availability
- Role permissions
- Ticket category
- Workload distribution
- Skills matching
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from django.contrib.auth.models import User, Group
from django.db.models import Q, Count, Avg
from django.utils import timezone
from django.core.cache import cache
from trueAlign.models import Support, UserDetails
from .logging_system import ticket_logger


class AssignmentEngine:
    """
    Core assignment engine that handles intelligent ticket distribution
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cache_timeout = 300  # 5 minutes cache

    def assign_ticket(self, ticket: Support, user: User = None) -> Tuple[User, str]:
        """
        Main method to assign ticket to best available agent

        Args:
            ticket: Support ticket instance
            user: User requesting assignment (for logging)

        Returns:
            Tuple of (assigned_user, assignment_reason)
        """
        try:
            # Get assignment rules for this ticket type
            rules = self._get_assignment_rules(ticket)

            # Get available agents
            available_agents = self._get_available_agents(ticket, rules)

            if not available_agents:
                # Fallback to group managers
                fallback_agent = self._get_fallback_agent(ticket)
                if fallback_agent:
                    self._assign_to_agent(ticket, fallback_agent, "Fallback assignment - no available agents")
                    return fallback_agent, "Fallback assignment"
                else:
                    raise ValueError("No available agents found for assignment")

            # Score and rank agents
            scored_agents = self._score_agents(ticket, available_agents, rules)

            # Select best agent
            best_agent = self._select_best_agent(scored_agents)

            # Assign ticket
            assignment_reason = self._get_assignment_reason(best_agent, scored_agents[0])
            self._assign_to_agent(ticket, best_agent, assignment_reason)

            # Log assignment
            ticket_logger.log_assignment(user, ticket, best_agent)

            return best_agent, assignment_reason

        except Exception as e:
            self.logger.error(f"Assignment failed for ticket {ticket.ticket_id}: {str(e)}")
            ticket_logger.log_error(user, "ASSIGNMENT", e, ticket.ticket_id)
            raise

    def _get_assignment_rules(self, ticket: Support) -> Dict:
        """
        Get assignment rules based on ticket properties
        """
        rules = {
            'priority_weight': 0.3,
            'workload_weight': 0.4,
            'skill_weight': 0.2,
            'availability_weight': 0.1,
            'max_tickets_per_agent': 10,
            'consider_office_hours': True,
            'escalation_threshold_hours': 24
        }

        # Adjust rules based on ticket priority
        if ticket.priority == Support.Priority.CRITICAL:
            rules['priority_weight'] = 0.5
            rules['max_tickets_per_agent'] = 15
        elif ticket.priority == Support.Priority.HIGH:
            rules['priority_weight'] = 0.4
            rules['max_tickets_per_agent'] = 12

        # Adjust rules based on issue type
        if ticket.issue_type in [Support.IssueType.SECURITY, Support.IssueType.NETWORK]:
            rules['skill_weight'] = 0.4
            rules['workload_weight'] = 0.3

        return rules

    def _get_available_agents(self, ticket: Support, rules: Dict) -> List[User]:
        """
        Get list of available agents for ticket assignment
        """
        cache_key = f"available_agents_{ticket.assigned_group}_{ticket.priority}"
        cached_agents = cache.get(cache_key)

        if cached_agents is not None:
            return cached_agents

        # Get users in the assigned group
        try:
            group = Group.objects.get(name=ticket.assigned_group)
            group_users = group.user_set.filter(is_active=True)
        except Group.DoesNotExist:
            self.logger.warning(f"Group {ticket.assigned_group} not found")
            return []

        available_agents = []

        for user in group_users:
            # Check if agent is available
            if self._is_agent_available(user, ticket, rules):
                available_agents.append(user)

        # Cache the result
        cache.set(cache_key, available_agents, self.cache_timeout)

        return available_agents

    def _is_agent_available(self, user: User, ticket: Support, rules: Dict) -> bool:
        """
        Check if agent is available for assignment
        """
        # Check if user has reached maximum ticket limit
        current_tickets = Support.objects.filter(
            assigned_to_user=user,
            status__in=['New', 'Open', 'In Progress', 'Pending User Response']
        ).count()

        if current_tickets >= rules['max_tickets_per_agent']:
            return False

        # Check office hours if enabled
        if rules['consider_office_hours'] and not self._is_office_hours():
            # Only assign critical tickets outside office hours
            if ticket.priority != Support.Priority.CRITICAL:
                return False

        # Check if agent has required skills for this ticket type
        if not self._has_required_skills(user, ticket):
            return False

        # Check if agent is not on leave (if integration exists)
        if self._is_agent_on_leave(user):
            return False

        return True

    def _score_agents(self, ticket: Support, agents: List[User], rules: Dict) -> List[Tuple[User, float]]:
        """
        Score agents based on various factors
        """
        scored_agents = []

        for agent in agents:
            score = 0.0

            # Workload score (lower workload = higher score)
            workload_score = self._calculate_workload_score(agent, rules)
            score += workload_score * rules['workload_weight']

            # Skill score (better skills = higher score)
            skill_score = self._calculate_skill_score(agent, ticket)
            score += skill_score * rules['skill_weight']

            # Priority handling score
            priority_score = self._calculate_priority_score(agent, ticket)
            score += priority_score * rules['priority_weight']

            # Availability score
            availability_score = self._calculate_availability_score(agent)
            score += availability_score * rules['availability_weight']

            scored_agents.append((agent, score))

        # Sort by score (highest first)
        scored_agents.sort(key=lambda x: x[1], reverse=True)

        return scored_agents

    def _calculate_workload_score(self, agent: User, rules: Dict) -> float:
        """
        Calculate workload score (0-1, higher is better)
        """
        current_tickets = Support.objects.filter(
            assigned_to_user=agent,
            status__in=['New', 'Open', 'In Progress', 'Pending User Response']
        ).count()

        max_tickets = rules['max_tickets_per_agent']

        # Normalize to 0-1 scale (inverted - fewer tickets = higher score)
        return max(0, 1 - (current_tickets / max_tickets))

    def _calculate_skill_score(self, agent: User, ticket: Support) -> float:
        """
        Calculate skill score based on agent's expertise
        """
        # Base score
        score = 0.5

        # Get agent's historical performance with this issue type
        past_tickets = Support.objects.filter(
            assigned_to_user=agent,
            issue_type=ticket.issue_type,
            status__in=['Resolved', 'Closed']
        ).aggregate(
            avg_resolution_time=Avg('resolution_time'),
            success_rate=Count('id')
        )

        if past_tickets['success_rate'] > 0:
            # Bonus for experience with this issue type
            score += 0.3

            # Bonus for fast resolution times
            if past_tickets['avg_resolution_time']:
                avg_hours = past_tickets['avg_resolution_time'].total_seconds() / 3600
                if avg_hours < 24:  # Fast resolution
                    score += 0.2

        # Check if agent has specific skills for this ticket type
        if self._has_specialized_skills(agent, ticket):
            score += 0.3

        return min(1.0, score)

    def _calculate_priority_score(self, agent: User, ticket: Support) -> float:
        """
        Calculate priority handling score
        """
        # Check agent's performance with similar priority tickets
        similar_tickets = Support.objects.filter(
            assigned_to_user=agent,
            priority=ticket.priority,
            status__in=['Resolved', 'Closed']
        ).count()

        if similar_tickets > 5:  # Experienced with this priority
            return 0.8
        elif similar_tickets > 2:  # Some experience
            return 0.6
        else:  # Limited experience
            return 0.4

    def _calculate_availability_score(self, agent: User) -> float:
        """
        Calculate availability score based on recent activity
        """
        # Check last activity (simplified - could integrate with session tracking)
        try:
            user_details = UserDetails.objects.get(user=agent)
            # If we have user details, assume they're available during work hours
            if self._is_office_hours():
                return 0.8
            else:
                return 0.3
        except UserDetails.DoesNotExist:
            return 0.5

    def _select_best_agent(self, scored_agents: List[Tuple[User, float]]) -> User:
        """
        Select the best agent from scored list
        """
        if not scored_agents:
            raise ValueError("No agents available for selection")

        # Return the highest scored agent
        return scored_agents[0][0]

    def _get_assignment_reason(self, agent: User, score_tuple: Tuple[User, float]) -> str:
        """
        Generate human-readable assignment reason
        """
        score = score_tuple[1]

        if score >= 0.8:
            return f"Best match - Optimal workload and skills (Score: {score:.2f})"
        elif score >= 0.6:
            return f"Good match - Suitable skills and availability (Score: {score:.2f})"
        elif score >= 0.4:
            return f"Available agent - Basic requirements met (Score: {score:.2f})"
        else:
            return f"Assigned by availability - Limited options (Score: {score:.2f})"

    def _assign_to_agent(self, ticket: Support, agent: User, reason: str):
        """
        Assign ticket to agent and update related fields
        """
        ticket.assigned_to_user = agent
        ticket.save()

        # Create activity log
        from trueAlign.models import TicketActivity
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ASSIGNED,
            user=agent,
            details=f"Auto-assigned: {reason}"
        )

    def _get_fallback_agent(self, ticket: Support) -> Optional[User]:
        """
        Get fallback agent when no one is available
        """
        try:
            # Try to get group manager or admin
            if ticket.assigned_group == 'Admin':
                admin_group = Group.objects.get(name='Admin')
                # Get least loaded admin
                return admin_group.user_set.filter(is_active=True).annotate(
                    ticket_count=Count('assigned_tickets')
                ).order_by('ticket_count').first()
            elif ticket.assigned_group == 'HR':
                hr_group = Group.objects.get(name='HR')
                # Get least loaded HR member
                return hr_group.user_set.filter(is_active=True).annotate(
                    ticket_count=Count('assigned_tickets')
                ).order_by('ticket_count').first()
        except Group.DoesNotExist:
            pass

        # Ultimate fallback - any admin user
        return User.objects.filter(is_staff=True, is_active=True).first()

    def _has_required_skills(self, user: User, ticket: Support) -> bool:
        """
        Check if user has required skills for ticket type
        """
        # Simplified skill check - in real implementation, this could be more sophisticated
        user_groups = [g.name for g in user.groups.all()]

        # HR issues require HR group membership
        if ticket.issue_type == Support.IssueType.HR:
            return 'HR' in user_groups

        # Security issues might require special permissions
        if ticket.issue_type == Support.IssueType.SECURITY:
            return user.is_staff or 'Admin' in user_groups

        # Other issues can be handled by assigned group
        return ticket.assigned_group in user_groups

    def _has_specialized_skills(self, user: User, ticket: Support) -> bool:
        """
        Check if user has specialized skills for this ticket type
        """
        # Check historical performance
        success_rate = Support.objects.filter(
            assigned_to_user=user,
            issue_type=ticket.issue_type,
            status__in=['Resolved', 'Closed']
        ).count()

        return success_rate > 3  # Has handled this type before

    def _is_office_hours(self) -> bool:
        """
        Check if current time is within office hours
        """
        now = timezone.now()
        # Simplified office hours check (9 AM - 6 PM weekdays)
        if now.weekday() >= 5:  # Weekend
            return False

        current_hour = now.hour
        return 9 <= current_hour <= 18

    def _is_agent_on_leave(self, user: User) -> bool:
        """
        Check if agent is on leave (integration with leave system)
        """
        try:
            from trueAlign.models import LeaveRequest
            today = timezone.now().date()

            # Check if user has approved leave for today
            leave_exists = LeaveRequest.objects.filter(
                user=user,
                status='Approved',
                from_date__lte=today,
                to_date__gte=today
            ).exists()

            return leave_exists
        except ImportError:
            # Leave system not available
            return False

    def get_assignment_statistics(self, days: int = 30) -> Dict:
        """
        Get assignment statistics for analysis
        """
        start_date = timezone.now() - timedelta(days=days)

        stats = {
            'total_assignments': Support.objects.filter(
                created_at__gte=start_date,
                assigned_to_user__isnull=False
            ).count(),
            'auto_assignments': Support.objects.filter(
                created_at__gte=start_date,
                assigned_to_user__isnull=False,
                ticket_activity__action='ASSIGNED',
                ticket_activity__details__contains='Auto-assigned'
            ).count(),
            'agent_workload': self._get_agent_workload_stats(),
            'assignment_distribution': self._get_assignment_distribution(start_date)
        }

        return stats

    def _get_agent_workload_stats(self) -> Dict:
        """
        Get current agent workload statistics
        """
        agents = User.objects.filter(
            groups__name__in=['Admin', 'HR'],
            is_active=True
        ).annotate(
            active_tickets=Count('assigned_tickets', filter=Q(
                assigned_tickets__status__in=['New', 'Open', 'In Progress', 'Pending User Response']
            ))
        )

        workload_stats = {}
        for agent in agents:
            workload_stats[agent.username] = {
                'active_tickets': agent.active_tickets,
                'groups': [g.name for g in agent.groups.all()]
            }

        return workload_stats

    def _get_assignment_distribution(self, start_date: datetime) -> Dict:
        """
        Get assignment distribution by issue type and priority
        """
        assignments = Support.objects.filter(
            created_at__gte=start_date,
            assigned_to_user__isnull=False
        ).values('issue_type', 'priority').annotate(
            count=Count('id')
        ).order_by('-count')

        return {
            'by_issue_type': list(assignments.values('issue_type', 'count')),
            'by_priority': list(assignments.values('priority', 'count'))
        }


# Global assignment engine instance
assignment_engine = AssignmentEngine()
