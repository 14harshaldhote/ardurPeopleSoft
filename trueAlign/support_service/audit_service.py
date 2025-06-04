'''-------------------------------------------- AUDIT SERVICE ---------------------------------------'''
from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q, F, Count, Avg, Max, Min, Prefetch
from django.core.cache import cache
from django.utils import timezone
from typing import List, Optional, Dict, Any, Union
from uuid import UUID
import json
from datetime import datetime, timedelta


class AuditService:
    """
    Highly optimized service layer for retrieving and managing audit trail information
    for support tickets and related activities with caching and performance optimizations.
    """

    # Cache configuration
    CACHE_TIMEOUT = 300  # 5 minutes
    CACHE_PREFIX = 'audit_service'

    def __init__(self):
        self.cache_enabled = True

    def _get_cache_key(self, key_parts: List[str]) -> str:
        """Generate a cache key from parts"""
        return f"{self.CACHE_PREFIX}:{'_'.join(str(p) for p in key_parts)}"

    def _get_from_cache(self, cache_key: str) -> Optional[Any]:
        """Get data from cache if enabled"""
        if self.cache_enabled:
            return cache.get(cache_key)
        return None

    def _set_cache(self, cache_key: str, data: Any, timeout: Optional[int] = None) -> None:
        """Set data in cache if enabled"""
        if self.cache_enabled:
            cache.set(cache_key, data, timeout or self.CACHE_TIMEOUT)

    def get_ticket_activities(
        self,
        ticket: Support,
        action_type: Optional[str] = None,
        user: Optional[User] = None,
        limit: int = 50,
        include_system: bool = True
    ) -> List[TicketActivity]:
        """
        Retrieves activity logs for a specific ticket with optimized queries.
        """
        cache_key = self._get_cache_key([
            'activities', str(ticket.ticket_id), action_type or 'all',
            str(user.id) if user else 'all', str(limit), str(include_system)
        ])

        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result

        activities = (
            TicketActivity.objects
            .filter(ticket=ticket)
            .select_related('user')
            .only(
                'id', 'action', 'timestamp', 'details', 'is_system_generated',
                'user__username', 'user__first_name', 'user__last_name'
            )
        )

        if action_type:
            activities = activities.filter(action=action_type)
        if user:
            activities = activities.filter(user=user)
        if not include_system:
            activities = activities.filter(is_system_generated=False)

        result = list(activities.order_by('-timestamp')[:limit])
        self._set_cache(cache_key, result)
        return result

    def get_bulk_ticket_activities(
        self,
        ticket_ids: List[UUID],
        limit_per_ticket: int = 20
    ) -> Dict[UUID, List[TicketActivity]]:
        """
        Efficiently retrieve activities for multiple tickets at once.
        """
        activities = (
            TicketActivity.objects
            .filter(ticket__ticket_id__in=ticket_ids)
            .select_related('user', 'ticket')
            .only(
                'id', 'action', 'timestamp', 'details', 'is_system_generated',
                'user__username', 'ticket__ticket_id'
            )
            .order_by('ticket_id', '-timestamp')
        )

        # Group activities by ticket
        ticket_activities = {}
        for activity in activities:
            ticket_id = activity.ticket.ticket_id
            if ticket_id not in ticket_activities:
                ticket_activities[ticket_id] = []

            if len(ticket_activities[ticket_id]) < limit_per_ticket:
                ticket_activities[ticket_id].append(activity)

        return ticket_activities

    def get_user_activity_summary(
        self,
        user: User,
        days: int = 30,
        include_deleted: bool = False
    ) -> Dict[str, Any]:
        """
        Get comprehensive activity summary for a user with aggregated statistics.
        """
        cache_key = self._get_cache_key(['user_summary', str(user.id), str(days), str(include_deleted)])
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result

        since_date = timezone.now() - timedelta(days=days)

        # Base queryset
        ticket_manager = Support.all_objects if include_deleted else Support.objects

        # Activity statistics
        activity_stats = (
            TicketActivity.objects
            .filter(user=user, timestamp__gte=since_date)
            .values('action')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Ticket statistics
        created_tickets = ticket_manager.filter(user=user, created_at__gte=since_date).count()
        assigned_tickets = ticket_manager.filter(assigned_to_user=user, created_at__gte=since_date).count()

        # Recent activities with ticket info
        recent_activities = (
            TicketActivity.objects
            .filter(user=user, timestamp__gte=since_date)
            .select_related('ticket')
            .only(
                'action', 'timestamp', 'details',
                'ticket__ticket_id', 'ticket__subject', 'ticket__status'
            )
            .order_by('-timestamp')[:50]
        )

        # Comments count
        comments_count = (
            TicketComment.objects
            .filter(user=user, created_at__gte=since_date)
            .count()
        )

        result = {
            'user_id': user.id,
            'username': user.username,
            'period_days': days,
            'activity_breakdown': {item['action']: item['count'] for item in activity_stats},
            'tickets_created': created_tickets,
            'tickets_assigned': assigned_tickets,
            'comments_made': comments_count,
            'recent_activities': [
                {
                    'action': a.action,
                    'timestamp': a.timestamp,
                    'ticket_id': str(a.ticket.ticket_id),
                    'ticket_subject': a.ticket.subject,
                    'ticket_status': a.ticket.status,
                    'details': a.details
                } for a in recent_activities
            ]
        }

        self._set_cache(cache_key, result, timeout=600)  # Cache for 10 minutes
        return result

    def get_ticket_timeline(self, ticket: Support) -> List[Dict[str, Any]]:
        """
        Get a comprehensive timeline of all events for a ticket, optimized for display.
        """
        cache_key = self._get_cache_key(['timeline', str(ticket.ticket_id)])
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result

        timeline_events = []

        # Get activities
        activities = (
            TicketActivity.objects
            .filter(ticket=ticket)
            .select_related('user')
            .only('action', 'timestamp', 'details', 'user__username', 'is_system_generated')
        )

        for activity in activities:
            timeline_events.append({
                'type': 'activity',
                'action': activity.action,
                'timestamp': activity.timestamp,
                'user': activity.user.username if activity.user else 'System',
                'details': activity.details,
                'is_system': activity.is_system_generated
            })

        # Get status changes
        status_logs = (
            StatusLog.objects
            .filter(ticket=ticket)
            .select_related('changed_by')
            .only('old_status', 'new_status', 'changed_at', 'changed_by__username', 'duration_in_status')
        )

        for log in status_logs:
            timeline_events.append({
                'type': 'status_change',
                'action': 'STATUS_CHANGED',
                'timestamp': log.changed_at,
                'user': log.changed_by.username if log.changed_by else 'System',
                'details': f"Status changed from '{log.old_status}' to '{log.new_status}'",
                'old_status': log.old_status,
                'new_status': log.new_status,
                'duration_in_previous': str(log.duration_in_status) if log.duration_in_status else None
            })

        # Get field changes
        field_changes = (
            TicketFieldChange.objects
            .filter(ticket=ticket)
            .select_related('changed_by')
            .only('field_name', 'old_value', 'new_value', 'changed_at', 'changed_by__username')
        )

        for change in field_changes:
            timeline_events.append({
                'type': 'field_change',
                'action': 'FIELD_CHANGED',
                'timestamp': change.changed_at,
                'user': change.changed_by.username if change.changed_by else 'System',
                'details': f"Field '{change.field_name}' changed",
                'field_name': change.field_name,
                'old_value': change.old_value,
                'new_value': change.new_value
            })

        # Get comments
        comments = (
            TicketComment.objects
            .filter(ticket=ticket)
            .select_related('user')
            .only('created_at', 'user__username', 'is_internal', 'is_first_response')
        )

        for comment in comments:
            timeline_events.append({
                'type': 'comment',
                'action': 'COMMENT_ADDED',
                'timestamp': comment.created_at,
                'user': comment.user.username,
                'details': f"{'Internal' if comment.is_internal else 'Public'} comment added",
                'is_internal': comment.is_internal,
                'is_first_response': comment.is_first_response
            })

        # Sort all events by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])

        self._set_cache(cache_key, timeline_events)
        return timeline_events

    def get_system_audit_summary(self, days: int = 7) -> Dict[str, Any]:
        """
        Get system-wide audit summary with performance metrics.
        """
        cache_key = self._get_cache_key(['system_summary', str(days)])
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result

        since_date = timezone.now() - timedelta(days=days)

        # Total activities
        total_activities = TicketActivity.objects.filter(timestamp__gte=since_date).count()

        # Activity breakdown
        activity_breakdown = (
            TicketActivity.objects
            .filter(timestamp__gte=since_date)
            .values('action')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # User activity stats
        user_activity_stats = (
            TicketActivity.objects
            .filter(timestamp__gte=since_date)
            .exclude(user__isnull=True)
            .values('user__username')
            .annotate(activity_count=Count('id'))
            .order_by('-activity_count')[:10]
        )

        # Ticket stats
        tickets_created = Support.objects.filter(created_at__gte=since_date).count()
        tickets_resolved = Support.objects.filter(resolved_at__gte=since_date).count()
        tickets_reopened = Support.objects.filter(reopened_at__gte=since_date).count()

        # SLA breach stats
        sla_breached = Support.objects.filter(
            created_at__gte=since_date,
            sla_breach=True
        ).count()

        # Response time stats
        avg_response_time = (
            Support.objects
            .filter(
                created_at__gte=since_date,
                response_time__isnull=False
            )
            .aggregate(avg_response=Avg('response_time'))['avg_response']
        )

        result = {
            'period_days': days,
            'total_activities': total_activities,
            'activity_breakdown': {item['action']: item['count'] for item in activity_breakdown},
            'top_active_users': [
                {
                    'username': item['user__username'],
                    'activity_count': item['activity_count']
                } for item in user_activity_stats
            ],
            'ticket_statistics': {
                'created': tickets_created,
                'resolved': tickets_resolved,
                'reopened': tickets_reopened,
                'sla_breached': sla_breached
            },
            'performance_metrics': {
                'avg_response_time_seconds': avg_response_time.total_seconds() if avg_response_time else None,
                'avg_response_time_human': str(avg_response_time) if avg_response_time else None
            }
        }

        self._set_cache(cache_key, result, timeout=900)  # Cache for 15 minutes
        return result

    def get_audit_trail_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        action_types: Optional[List[str]] = None,
        users: Optional[List[User]] = None,
        limit: int = 1000
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get comprehensive audit trail for a date range with filtering.
        """
        # Activities
        activities_query = (
            TicketActivity.objects
            .filter(timestamp__range=(start_date, end_date))
            .select_related('user', 'ticket')
            .only(
                'action', 'timestamp', 'details', 'is_system_generated',
                'user__username', 'ticket__ticket_id', 'ticket__subject'
            )
        )

        if action_types:
            activities_query = activities_query.filter(action__in=action_types)
        if users:
            activities_query = activities_query.filter(user__in=users)

        activities = activities_query.order_by('-timestamp')[:limit]

        # Status changes
        status_changes = (
            StatusLog.objects
            .filter(changed_at__range=(start_date, end_date))
            .select_related('changed_by', 'ticket')
            .only(
                'old_status', 'new_status', 'changed_at', 'duration_in_status',
                'changed_by__username', 'ticket__ticket_id', 'ticket__subject'
            )
            .order_by('-changed_at')[:limit]
        )

        # Field changes
        field_changes = (
            TicketFieldChange.objects
            .filter(changed_at__range=(start_date, end_date))
            .select_related('changed_by', 'ticket')
            .only(
                'field_name', 'old_value', 'new_value', 'changed_at',
                'changed_by__username', 'ticket__ticket_id', 'ticket__subject'
            )
            .order_by('-changed_at')[:limit]
        )

        return {
            'activities': [
                {
                    'id': a.id,
                    'action': a.action,
                    'timestamp': a.timestamp,
                    'user': a.user.username if a.user else 'System',
                    'ticket_id': str(a.ticket.ticket_id),
                    'ticket_subject': a.ticket.subject,
                    'details': a.details,
                    'is_system': a.is_system_generated
                } for a in activities
            ],
            'status_changes': [
                {
                    'timestamp': sc.changed_at,
                    'user': sc.changed_by.username if sc.changed_by else 'System',
                    'ticket_id': str(sc.ticket.ticket_id),
                    'ticket_subject': sc.ticket.subject,
                    'old_status': sc.old_status,
                    'new_status': sc.new_status,
                    'duration_in_previous': str(sc.duration_in_status) if sc.duration_in_status else None
                } for sc in status_changes
            ],
            'field_changes': [
                {
                    'timestamp': fc.changed_at,
                    'user': fc.changed_by.username if fc.changed_by else 'System',
                    'ticket_id': str(fc.ticket.ticket_id),
                    'ticket_subject': fc.ticket.subject,
                    'field_name': fc.field_name,
                    'old_value': fc.old_value,
                    'new_value': fc.new_value
                } for fc in field_changes
            ]
        }

    def get_performance_metrics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get detailed performance metrics for audit and reporting.
        """
        cache_key = self._get_cache_key(['performance_metrics', str(days)])
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result

        since_date = timezone.now() - timedelta(days=days)

        # Response time metrics
        response_metrics = (
            Support.objects
            .filter(created_at__gte=since_date, response_time__isnull=False)
            .aggregate(
                avg_response=Avg('response_time'),
                min_response=Min('response_time'),
                max_response=Max('response_time')
            )
        )

        # Resolution time metrics
        resolution_metrics = (
            Support.objects
            .filter(resolved_at__gte=since_date, resolution_time__isnull=False)
            .aggregate(
                avg_resolution=Avg('resolution_time'),
                min_resolution=Min('resolution_time'),
                max_resolution=Max('resolution_time')
            )
        )

        # SLA metrics
        sla_metrics = (
            Support.objects
            .filter(created_at__gte=since_date)
            .aggregate(
                total_tickets=Count('id'),
                breached_sla=Count('id', filter=Q(sla_breach=True)),
                within_sla=Count('id', filter=Q(sla_breach=False))
            )
        )

        # Escalation metrics
        escalation_metrics = (
            Support.objects
            .filter(created_at__gte=since_date)
            .aggregate(
                total_escalations=Count('id', filter=Q(escalation_level__gt=0)),
                avg_escalation_level=Avg('escalation_level')
            )
        )

        # Reopen metrics
        reopen_metrics = (
            Support.objects
            .filter(created_at__gte=since_date)
            .aggregate(
                total_reopens=Count('id', filter=Q(reopen_count__gt=0)),
                avg_reopen_count=Avg('reopen_count')
            )
        )

        result = {
            'period_days': days,
            'response_times': {
                'average_seconds': response_metrics['avg_response'].total_seconds() if response_metrics['avg_response'] else None,
                'minimum_seconds': response_metrics['min_response'].total_seconds() if response_metrics['min_response'] else None,
                'maximum_seconds': response_metrics['max_response'].total_seconds() if response_metrics['max_response'] else None
            },
            'resolution_times': {
                'average_seconds': resolution_metrics['avg_resolution'].total_seconds() if resolution_metrics['avg_resolution'] else None,
                'minimum_seconds': resolution_metrics['min_resolution'].total_seconds() if resolution_metrics['min_resolution'] else None,
                'maximum_seconds': resolution_metrics['max_resolution'].total_seconds() if resolution_metrics['max_resolution'] else None
            },
            'sla_performance': {
                'total_tickets': sla_metrics['total_tickets'],
                'breached_count': sla_metrics['breached_sla'],
                'within_sla_count': sla_metrics['within_sla'],
                'breach_percentage': (sla_metrics['breached_sla'] / sla_metrics['total_tickets'] * 100) if sla_metrics['total_tickets'] > 0 else 0
            },
            'escalations': {
                'total_escalated': escalation_metrics['total_escalations'],
                'average_level': float(escalation_metrics['avg_escalation_level']) if escalation_metrics['avg_escalation_level'] else 0
            },
            'reopens': {
                'total_reopened': reopen_metrics['total_reopens'],
                'average_reopen_count': float(reopen_metrics['avg_reopen_count']) if reopen_metrics['avg_reopen_count'] else 0
            }
        }

        self._set_cache(cache_key, result, timeout=1800)  # Cache for 30 minutes
        return result

    def clear_cache(self, pattern: Optional[str] = None) -> None:
        """
        Clear audit service cache. If pattern is provided, clear only matching keys.
        """
        if pattern:
            # This would require a more sophisticated cache backend that supports pattern deletion
            # For now, we'll just clear the basic cache
            cache.clear()
        else:
            cache.clear()

    def export_audit_data(
        self,
        ticket_ids: Optional[List[UUID]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format_type: str = 'json'
    ) -> Union[str, Dict[str, Any]]:
        """
        Export audit data for compliance or backup purposes.
        """
        export_data = {
            'export_timestamp': timezone.now().isoformat(),
            'format': format_type,
            'tickets': []
        }

        # Build ticket queryset
        tickets_query = Support.all_objects.all()

        if ticket_ids:
            tickets_query = tickets_query.filter(ticket_id__in=ticket_ids)
        if start_date:
            tickets_query = tickets_query.filter(created_at__gte=start_date)
        if end_date:
            tickets_query = tickets_query.filter(created_at__lte=end_date)

        # Export data for each ticket
        for ticket in tickets_query.prefetch_related(
            Prefetch('activities', queryset=TicketActivity.objects.select_related('user')),
            Prefetch('status_logs', queryset=StatusLog.objects.select_related('changed_by')),
            Prefetch('field_changes', queryset=TicketFieldChange.objects.select_related('changed_by'))
        ):
            ticket_data = {
                'ticket_id': str(ticket.ticket_id),
                'subject': ticket.subject,
                'status': ticket.status,
                'created_at': ticket.created_at.isoformat(),
                'activities': [
                    {
                        'action': activity.action,
                        'timestamp': activity.timestamp.isoformat(),
                        'user': activity.user.username if activity.user else 'System',
                        'details': activity.details,
                        'is_system_generated': activity.is_system_generated
                    } for activity in ticket.activities.all()
                ],
                'status_changes': [
                    {
                        'old_status': log.old_status,
                        'new_status': log.new_status,
                        'changed_at': log.changed_at.isoformat(),
                        'changed_by': log.changed_by.username if log.changed_by else 'System'
                    } for log in ticket.status_logs.all()
                ],
                'field_changes': [
                    {
                        'field_name': change.field_name,
                        'old_value': change.old_value,
                        'new_value': change.new_value,
                        'changed_at': change.changed_at.isoformat(),
                        'changed_by': change.changed_by.username if change.changed_by else 'System'
                    } for change in ticket.field_changes.all()
                ]
            }
            export_data['tickets'].append(ticket_data)

        if format_type == 'json':
            return json.dumps(export_data, indent=2, default=str)
        else:
            return export_data
