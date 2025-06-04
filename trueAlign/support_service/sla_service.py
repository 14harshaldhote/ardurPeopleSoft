# your_django_app/services/sla_service.py

from django.utils import timezone
from django.db import transaction
from django.db.models import Q, F, Case, When, DurationField
from django.core.cache import cache
from datetime import timedelta
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

from ..models import Support, TicketActivity
from .exceptions import SLAConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class SLAMetrics:
    """Data class for SLA metrics"""
    total_tickets: int
    within_sla: int
    breached: int
    paused: int
    breach_percentage: float
    avg_resolution_time: Optional[timedelta]


class SLACalculationType(Enum):
    """Enum for different SLA calculation types"""
    BUSINESS_HOURS = "business_hours"
    CALENDAR_HOURS = "calendar_hours"


class OptimizedSLAService:
    """
    Highly optimized service layer for managing Service Level Agreements (SLAs).
    Features bulk operations, caching, and efficient database queries.
    """

    # Cache keys
    CACHE_KEY_SLA_RULES = "sla_rules_cache"
    CACHE_KEY_SLA_METRICS = "sla_metrics_{group}_{days}"
    CACHE_TIMEOUT = 300  # 5 minutes

    # SLA target configurations (can be moved to database/settings)
    DEFAULT_SLA_TARGETS = {
        Support.Priority.CRITICAL: {'hours': 2, 'business_hours_only': False},
        Support.Priority.HIGH: {'hours': 4, 'business_hours_only': False},
        Support.Priority.MEDIUM: {'hours': 8, 'business_hours_only': True},
        Support.Priority.LOW: {'hours': 24, 'business_hours_only': True},
    }

    def __init__(self, calculation_type: SLACalculationType = SLACalculationType.CALENDAR_HOURS):
        self.calculation_type = calculation_type

    @transaction.atomic
    def bulk_set_sla_targets(self, tickets: List[Support]) -> List[Support]:
        """
        Efficiently set SLA targets for multiple tickets in bulk.
        """
        if not tickets:
            return []

        updated_tickets = []
        for ticket in tickets:
            if not ticket.sla_target_date and ticket.created_at:
                self._calculate_sla_target(ticket)
                updated_tickets.append(ticket)

        if updated_tickets:
            Support.objects.bulk_update(
                updated_tickets,
                ['sla_target_date', 'sla_status'],
                batch_size=100
            )

        return updated_tickets

    def _calculate_sla_target(self, ticket: Support) -> None:
        """
        Calculate SLA target date for a single ticket.
        Optimized with caching and business hours consideration.
        """
        sla_config = self._get_sla_config(ticket.priority)

        if self.calculation_type == SLACalculationType.BUSINESS_HOURS:
            target_date = self._add_business_hours(
                ticket.created_at,
                sla_config['hours']
            )
        else:
            target_date = ticket.created_at + timedelta(hours=sla_config['hours'])

        ticket.sla_target_date = target_date
        ticket.sla_status = Support.SLAStatus.WITHIN_SLA

    def _get_sla_config(self, priority: str) -> Dict:
        """
        Get SLA configuration with caching.
        """
        cache_key = f"{self.CACHE_KEY_SLA_RULES}_{priority}"
        config = cache.get(cache_key)

        if config is None:
            config = self.DEFAULT_SLA_TARGETS.get(
                priority,
                {'hours': 24, 'business_hours_only': True}
            )
            cache.set(cache_key, config, self.CACHE_TIMEOUT)

        return config

    def _add_business_hours(self, start_time: timezone.datetime, hours: int) -> timezone.datetime:
        """
        Add business hours to a datetime, skipping weekends and holidays.
        """
        # Business hours: 9 AM to 5 PM, Monday to Friday
        current = start_time
        hours_to_add = hours

        while hours_to_add > 0:
            # Skip weekends
            if current.weekday() >= 5:  # Saturday = 5, Sunday = 6
                current = current.replace(hour=9, minute=0, second=0, microsecond=0)
                current += timedelta(days=1)
                continue

            # Ensure we're in business hours
            if current.hour < 9:
                current = current.replace(hour=9, minute=0, second=0, microsecond=0)
            elif current.hour >= 17:
                current = current.replace(hour=9, minute=0, second=0, microsecond=0)
                current += timedelta(days=1)
                continue

            # Calculate hours until end of business day
            end_of_day = current.replace(hour=17, minute=0, second=0, microsecond=0)
            hours_until_eod = (end_of_day - current).total_seconds() / 3600

            if hours_to_add <= hours_until_eod:
                current += timedelta(hours=hours_to_add)
                hours_to_add = 0
            else:
                hours_to_add -= hours_until_eod
                current = current.replace(hour=9, minute=0, second=0, microsecond=0)
                current += timedelta(days=1)

        return current

    @transaction.atomic
    def bulk_update_sla_compliance(self, ticket_ids: Optional[List[int]] = None) -> Dict[str, int]:
        """
        Efficiently update SLA compliance for multiple tickets using bulk operations.
        """
        queryset = Support.objects.select_related().filter(
            sla_target_date__isnull=False,
            status__in=[
                Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS,
                Support.Status.PENDING_USER, Support.Status.PENDING_THIRD_PARTY,
                Support.Status.RESOLVED, Support.Status.CLOSED
            ]
        )

        if ticket_ids:
            queryset = queryset.filter(id__in=ticket_ids)

        current_time = timezone.now()

        # Use database-level updates for better performance
        updates = {
            'breached_count': 0,
            'resolved_within_sla_count': 0,
            'updated_count': 0
        }

        # Update breached tickets (open tickets past SLA target)
        breached_tickets = queryset.annotate(
            effective_target=F('sla_target_date') + F('sla_paused_duration')
        ).filter(
            effective_target__lt=current_time,
            resolved_at__isnull=True,
            sla_status__in=[Support.SLAStatus.WITHIN_SLA, Support.SLAStatus.PAUSED]
        )

        updates['breached_count'] = breached_tickets.update(
            sla_breach=True,
            sla_status=Support.SLAStatus.BREACHED
        )

        # Update resolved tickets within SLA
        resolved_within_sla = queryset.annotate(
            effective_target=F('sla_target_date') + F('sla_paused_duration')
        ).filter(
            resolved_at__isnull=False,
            resolved_at__lte=F('effective_target'),
            sla_breach=True
        )

        updates['resolved_within_sla_count'] = resolved_within_sla.update(
            sla_breach=False,
            sla_status=Support.SLAStatus.WITHIN_SLA
        )

        updates['updated_count'] = updates['breached_count'] + updates['resolved_within_sla_count']

        # Create activity logs for breached tickets if needed
        if updates['breached_count'] > 0:
            self._create_bulk_breach_activities(
                breached_tickets.values_list('id', flat=True)
            )

        logger.info(f"SLA compliance updated: {updates}")
        return updates

    def _create_bulk_breach_activities(self, ticket_ids: List[int]) -> None:
        """
        Create activity logs for breached tickets in bulk.
        """
        activities = [
            TicketActivity(
                ticket_id=ticket_id,
                action=TicketActivity.Action.SLA_BREACHED,
                details="SLA has been breached.",
                is_system_generated=True
            )
            for ticket_id in ticket_ids
        ]

        TicketActivity.objects.bulk_create(activities, batch_size=100)

    @transaction.atomic
    def bulk_pause_sla(self, ticket_ids: List[int], user=None) -> int:
        """
        Pause SLA for multiple tickets efficiently.
        """
        current_time = timezone.now()

        updated_count = Support.objects.filter(
            id__in=ticket_ids,
            sla_status__in=[Support.SLAStatus.WITHIN_SLA, Support.SLAStatus.BREACHED]
        ).update(
            sla_status=Support.SLAStatus.PAUSED,
            sla_paused_at=current_time
        )

        if updated_count > 0:
            # Create activity logs
            activities = [
                TicketActivity(
                    ticket_id=ticket_id,
                    action="SLA_PAUSED",
                    user=user,
                    details="SLA paused via bulk operation",
                    is_system_generated=not bool(user)
                )
                for ticket_id in Support.objects.filter(
                    id__in=ticket_ids,
                    sla_status=Support.SLAStatus.PAUSED
                ).values_list('id', flat=True)
            ]

            TicketActivity.objects.bulk_create(activities, batch_size=100)

        return updated_count

    @transaction.atomic
    def bulk_resume_sla(self, ticket_ids: List[int], user=None) -> int:
        """
        Resume SLA for multiple tickets efficiently.
        """
        current_time = timezone.now()

        # Get paused tickets with their pause times
        paused_tickets = Support.objects.filter(
            id__in=ticket_ids,
            sla_status=Support.SLAStatus.PAUSED,
            sla_paused_at__isnull=False
        ).values('id', 'sla_paused_at', 'sla_paused_duration')

        updates = []
        for ticket_data in paused_tickets:
            paused_duration = current_time - ticket_data['sla_paused_at']
            new_total_paused = ticket_data['sla_paused_duration'] + paused_duration

            updates.append(
                Support(
                    id=ticket_data['id'],
                    sla_paused_duration=new_total_paused,
                    sla_paused_at=None,
                    sla_status=Support.SLAStatus.WITHIN_SLA
                )
            )

        if updates:
            Support.objects.bulk_update(
                updates,
                ['sla_paused_duration', 'sla_paused_at', 'sla_status'],
                batch_size=100
            )

            # Create activity logs
            activities = [
                TicketActivity(
                    ticket_id=update.id,
                    action="SLA_RESUMED",
                    user=user,
                    details="SLA resumed via bulk operation",
                    is_system_generated=not bool(user)
                )
                for update in updates
            ]

            TicketActivity.objects.bulk_create(activities, batch_size=100)

        return len(updates)

    def get_sla_metrics(self, assigned_group: Optional[str] = None, days: int = 30) -> SLAMetrics:
        """
        Get SLA metrics with caching for performance.
        """
        cache_key = self.CACHE_KEY_SLA_METRICS.format(
            group=assigned_group or 'all',
            days=days
        )

        metrics = cache.get(cache_key)
        if metrics is not None:
            return metrics

        # Calculate date range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        # Build query
        queryset = Support.objects.filter(
            created_at__gte=start_date,
            created_at__lte=end_date
        )

        if assigned_group:
            queryset = queryset.filter(assigned_group=assigned_group)

        # Aggregate metrics
        total_tickets = queryset.count()

        if total_tickets == 0:
            metrics = SLAMetrics(
                total_tickets=0,
                within_sla=0,
                breached=0,
                paused=0,
                breach_percentage=0.0,
                avg_resolution_time=None
            )
        else:
            sla_counts = queryset.values('sla_status').annotate(
                count=models.Count('id')
            )

            within_sla = sum(
                item['count'] for item in sla_counts
                if item['sla_status'] == Support.SLAStatus.WITHIN_SLA
            )
            breached = sum(
                item['count'] for item in sla_counts
                if item['sla_status'] == Support.SLAStatus.BREACHED
            )
            paused = sum(
                item['count'] for item in sla_counts
                if item['sla_status'] == Support.SLAStatus.PAUSED
            )

            breach_percentage = (breached / total_tickets * 100) if total_tickets > 0 else 0.0

            # Calculate average resolution time
            resolved_tickets = queryset.filter(
                resolution_time__isnull=False
            ).aggregate(
                avg_time=models.Avg('resolution_time')
            )

            metrics = SLAMetrics(
                total_tickets=total_tickets,
                within_sla=within_sla,
                breached=breached,
                paused=paused,
                breach_percentage=breach_percentage,
                avg_resolution_time=resolved_tickets['avg_time']
            )

        # Cache the results
        cache.set(cache_key, metrics, self.CACHE_TIMEOUT)
        return metrics

    def get_tickets_approaching_breach(self, hours_threshold: int = 2) -> List[Support]:
        """
        Get tickets that are approaching SLA breach within the specified hours.
        Optimized query with proper indexing.
        """
        threshold_time = timezone.now() + timedelta(hours=hours_threshold)

        return list(Support.objects.select_related('user', 'assigned_to_user').annotate(
            effective_target=F('sla_target_date') + F('sla_paused_duration')
        ).filter(
            effective_target__lte=threshold_time,
            effective_target__gt=timezone.now(),
            status__in=[
                Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS,
                Support.Status.PENDING_USER, Support.Status.PENDING_THIRD_PARTY
            ],
            sla_status__in=[Support.SLAStatus.WITHIN_SLA, Support.SLAStatus.PAUSED]
        ).order_by('effective_target'))

    def calculate_sla_remaining_time_bulk(self, ticket_ids: List[int]) -> Dict[int, Optional[timedelta]]:
        """
        Calculate remaining SLA time for multiple tickets efficiently.
        """
        current_time = timezone.now()

        tickets = Support.objects.filter(
            id__in=ticket_ids
        ).annotate(
            effective_target=F('sla_target_date') + F('sla_paused_duration')
        ).values('id', 'effective_target', 'status', 'sla_status', 'resolved_at')

        results = {}
        for ticket in tickets:
            # Skip if resolved/closed or no SLA target
            if (ticket['status'] in [Support.Status.RESOLVED, Support.Status.CLOSED] or
                not ticket['effective_target'] or
                ticket['sla_status'] == Support.SLAStatus.PAUSED):
                results[ticket['id']] = None
            else:
                remaining = ticket['effective_target'] - current_time
                results[ticket['id']] = remaining

        return results

    def clear_sla_cache(self) -> None:
        """
        Clear all SLA-related cache entries.
        """
        cache.delete_many([
            key for key in cache._cache.keys()
            if key.startswith(self.CACHE_KEY_SLA_RULES) or
               key.startswith(self.CACHE_KEY_SLA_METRICS.split('_')[0])
        ])

    def auto_escalate_breached_tickets(self) -> int:
        """
        Auto-escalate tickets that have breached SLA and meet escalation criteria.
        """
        breached_tickets = Support.objects.filter(
            sla_status=Support.SLAStatus.BREACHED,
            escalation_level=0,
            status__in=[
                Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS
            ]
        ).select_for_update()

        escalated_count = 0
        with transaction.atomic():
            for ticket in breached_tickets:
                try:
                    ticket.escalate(reason="Auto-escalation due to SLA breach")
                    escalated_count += 1
                except Exception as e:
                    logger.error(f"Failed to escalate ticket {ticket.ticket_id}: {e}")

        return escalated_count
