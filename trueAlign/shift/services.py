"""
Enhanced Shift Management Services

This module provides comprehensive shift management functionality including:
- Dynamic conflict detection for any arbitrary shift times
- Midnight-crossing shift support
- Configurable conflict rules
- Employee availability integration
- Bulk assignment with intelligent conflict handling
- Audit logging and change tracking
- Performance-optimized queries

Author: TrueAlign Development Team
Version: 2.0.0
"""

import logging
from datetime import datetime, timedelta, time, date
from decimal import Decimal
from typing import List, Dict, Optional, Tuple, Set, Any, Union
from dataclasses import dataclass
from enum import Enum

from django.db import transaction, models
from django.db.models import Q, F, Count, Avg, Sum, Prefetch
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from .app_settings import (
    SHIFT_VALIDATION, CACHE_SETTINGS, CACHE_KEY_PREFIXES,
    PERFORMANCE_MONITORING, FEATURE_FLAGS
)

logger = logging.getLogger('trueAlign.shift.services')


class ConflictType(Enum):
    """Types of shift assignment conflicts."""
    TIME_OVERLAP = "time_overlap"
    LEAVE_CONFLICT = "leave_conflict"
    HOLIDAY_CONFLICT = "holiday_conflict"
    AVAILABILITY_CONFLICT = "availability_conflict"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    POLICY_VIOLATION = "policy_violation"


class AssignmentStatus(Enum):
    """Status of shift assignment operations."""
    SUCCESS = "success"
    CONFLICT = "conflict"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class ConflictDetail:
    """Detailed information about a shift assignment conflict."""
    conflict_type: ConflictType
    message: str
    conflicting_assignment: Optional['ShiftAssignment'] = None
    conflicting_shift: Optional['ShiftMaster'] = None
    overlap_start: Optional[datetime] = None
    overlap_end: Optional[datetime] = None
    severity: str = "high"  # low, medium, high, critical
    suggestion: Optional[str] = None


@dataclass
class AssignmentResult:
    """Result of a shift assignment operation."""
    status: AssignmentStatus
    assignment: Optional['ShiftAssignment'] = None
    conflicts: List[ConflictDetail] = None
    warnings: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.conflicts is None:
            self.conflicts = []
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class BulkAssignmentResult:
    """Result of bulk shift assignment operation."""
    total_attempted: int = 0
    successful: List[AssignmentResult] = None
    failed: List[AssignmentResult] = None
    skipped: List[AssignmentResult] = None
    summary: Dict[str, Any] = None

    def __post_init__(self):
        if self.successful is None:
            self.successful = []
        if self.failed is None:
            self.failed = []
        if self.skipped is None:
            self.skipped = []
        if self.summary is None:
            self.summary = {}


class TimeOverlapCalculator:
    """Utility class for calculating time overlaps, including midnight-crossing shifts."""

    @staticmethod
    def normalize_time_range(start_time: time, end_time: time, base_date: date) -> Tuple[datetime, datetime]:
        """
        Normalize a time range to datetime objects, handling midnight crossing.

        Args:
            start_time: Start time of the shift
            end_time: End time of the shift
            base_date: Base date for the shift

        Returns:
            Tuple of (start_datetime, end_datetime)
        """
        start_dt = timezone.make_aware(datetime.combine(base_date, start_time))

        # If end_time is before start_time, it crosses midnight
        if end_time <= start_time:
            end_dt = timezone.make_aware(datetime.combine(base_date + timedelta(days=1), end_time))
        else:
            end_dt = timezone.make_aware(datetime.combine(base_date, end_time))

        return start_dt, end_dt

    @staticmethod
    def times_overlap(start1: time, end1: time, start2: time, end2: time,
                     date1: date, date2: date = None) -> Tuple[bool, Optional[datetime], Optional[datetime]]:
        """
        Check if two time ranges overlap, handling midnight crossing.

        Args:
            start1, end1: First time range
            start2, end2: Second time range
            date1: Date for first range
            date2: Date for second range (defaults to date1)

        Returns:
            Tuple of (overlaps: bool, overlap_start: datetime, overlap_end: datetime)
        """
        if date2 is None:
            date2 = date1

        dt1_start, dt1_end = TimeOverlapCalculator.normalize_time_range(start1, end1, date1)
        dt2_start, dt2_end = TimeOverlapCalculator.normalize_time_range(start2, end2, date2)

        # Check for overlap
        overlap_start = max(dt1_start, dt2_start)
        overlap_end = min(dt1_end, dt2_end)

        overlaps = overlap_start < overlap_end

        return overlaps, overlap_start if overlaps else None, overlap_end if overlaps else None

    @staticmethod
    def calculate_overlap_duration(start1: time, end1: time, start2: time, end2: time,
                                 date1: date, date2: date = None) -> timedelta:
        """Calculate the duration of overlap between two time ranges."""
        overlaps, overlap_start, overlap_end = TimeOverlapCalculator.times_overlap(
            start1, end1, start2, end2, date1, date2
        )

        if overlaps and overlap_start and overlap_end:
            return overlap_end - overlap_start

        return timedelta(0)


class ConflictDetector:
    """Advanced conflict detection for shift assignments."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize conflict detector with configuration."""
        self.config = config or {}
        self.tolerance_minutes = self.config.get('tolerance_minutes', 0)
        self.check_holidays = self.config.get('check_holidays', True)
        self.check_leave = self.config.get('check_leave', True)
        self.strict_mode = self.config.get('strict_mode', True)

    def check_assignment_conflicts(self, user: User, shift: ShiftMaster,
                                 effective_from: date, effective_to: date = None) -> List[ConflictDetail]:
        """
        Check for conflicts when assigning a shift to a user.

        Args:
            user: User to assign shift to
            shift: Shift to assign
            effective_from: Start date of assignment
            effective_to: End date of assignment (None for ongoing)

        Returns:
            List of conflict details
        """
        conflicts = []

        # Validate inputs
        if not user or not shift or not effective_from:
            return conflicts

        # Get date range to check
        end_date = effective_to or (effective_from + timedelta(days=365))  # Check up to 1 year ahead
        check_dates = self._get_dates_to_check(effective_from, end_date, shift)

        for check_date in check_dates:
            # Check time conflicts
            time_conflicts = self._check_time_conflicts(user, shift, check_date)
            conflicts.extend(time_conflicts)

            # Check holiday conflicts
            if self.check_holidays:
                holiday_conflicts = self._check_holiday_conflicts(shift, check_date)
                conflicts.extend(holiday_conflicts)

            # Check leave conflicts (if leave system is available)
            if self.check_leave:
                leave_conflicts = self._check_leave_conflicts(user, check_date)
                conflicts.extend(leave_conflicts)

        return conflicts

    def _get_dates_to_check(self, start_date: date, end_date: date, shift: ShiftMaster) -> List[date]:
        """Get list of dates to check based on shift working days."""
        dates_to_check = []
        current_date = start_date

        while current_date <= end_date:
            if shift.is_working_day(current_date):
                dates_to_check.append(current_date)
            current_date += timedelta(days=1)

            # Limit to prevent excessive checking
            if len(dates_to_check) > 100:
                logger.warning(f"Limiting conflict check to 100 dates for performance")
                break

        return dates_to_check

    def _check_time_conflicts(self, user: User, shift: ShiftMaster, check_date: date) -> List[ConflictDetail]:
        """Check for time-based conflicts on a specific date."""
        conflicts = []

        # Get existing assignments for the user on this date
        existing_assignments = self._get_existing_assignments(user, check_date)

        for assignment in existing_assignments:
            existing_shift = assignment.shift

            # Check if shifts overlap
            overlaps, overlap_start, overlap_end = TimeOverlapCalculator.times_overlap(
                shift.start_time, shift.end_time,
                existing_shift.start_time, existing_shift.end_time,
                check_date
            )

            if overlaps:
                # Apply tolerance if configured
                if self.tolerance_minutes > 0:
                    overlap_duration = overlap_end - overlap_start
                    if overlap_duration.total_seconds() / 60 <= self.tolerance_minutes:
                        continue  # Within tolerance, no conflict

                conflict = ConflictDetail(
                    conflict_type=ConflictType.TIME_OVERLAP,
                    message=f"Shift '{shift.name}' overlaps with existing assignment '{existing_shift.name}' on {check_date}",
                    conflicting_assignment=assignment,
                    conflicting_shift=existing_shift,
                    overlap_start=overlap_start,
                    overlap_end=overlap_end,
                    severity="high",
                    suggestion=f"Consider adjusting shift times or selecting a different date"
                )
                conflicts.append(conflict)

        return conflicts

    def _get_existing_assignments(self, user: User, check_date: date) -> List[ShiftAssignment]:
        """Get existing shift assignments for a user on a specific date."""
        return list(ShiftAssignment.objects.filter(
            user=user,
            effective_from__lte=check_date
        ).filter(
            Q(effective_to__gte=check_date) | Q(effective_to__isnull=True)
        ).select_related('shift'))

    def _check_holiday_conflicts(self, shift: ShiftMaster, check_date: date) -> List[ConflictDetail]:
        """Check for holiday conflicts."""
        conflicts = []

        if Holiday.is_holiday(check_date):
            holiday = Holiday.objects.filter(
                Q(date=check_date) |
                Q(recurring_yearly=True, date__month=check_date.month, date__day=check_date.day)
            ).first()

            conflict = ConflictDetail(
                conflict_type=ConflictType.HOLIDAY_CONFLICT,
                message=f"Cannot assign shift on holiday: {holiday.name if holiday else 'Unknown Holiday'} ({check_date})",
                severity="medium",
                suggestion="Consider assigning shift on a different date"
            )
            conflicts.append(conflict)

        return conflicts

    def _check_leave_conflicts(self, user: User, check_date: date) -> List[ConflictDetail]:
        """Check for leave conflicts (placeholder for future integration)."""
        conflicts = []

        # TODO: Integrate with leave management system
        # This is a placeholder for future implementation
        try:
            # Check if user is on leave (requires leave models)
            # from ..models import LeaveRequest
            # leave_requests = LeaveRequest.objects.filter(
            #     user=user,
            #     start_date__lte=check_date,
            #     end_date__gte=check_date,
            #     status='approved'
            # )
            # if leave_requests.exists():
            #     conflict = ConflictDetail(
            #         conflict_type=ConflictType.LEAVE_CONFLICT,
            #         message=f"User is on approved leave on {check_date}",
            #         severity="high"
            #     )
            #     conflicts.append(conflict)
            pass
        except ImportError:
            pass  # Leave system not available

        return conflicts


class ShiftService:
    """
    Enhanced shift management service with comprehensive functionality.

    Provides methods for:
    - Creating and managing shifts
    - Dynamic conflict detection
    - Bulk assignment operations
    - Performance optimization
    - Audit logging
    """

    def __init__(self):
        """Initialize the shift service."""
        self.conflict_detector = ConflictDetector()
        self.cache_timeout = 300  # Default cache timeout
        self.performance_monitoring = True  # Enable performance monitoring

    # ============================
    # SHIFT MANAGEMENT
    # ============================

    def get_all_shifts(self, active_only: bool = True, include_stats: bool = False, page: int = None, per_page: int = 10) -> Dict[str, Any]:
        """
        Get all shifts with optional statistics and pagination.

        Args:
            active_only: If True, return only active shifts
            include_stats: If True, include assignment statistics
            page: Page number for pagination
            per_page: Number of items per page

        Returns:
            Dictionary with shifts list, pagination info, and metadata
        """
        cache_key = f"{CACHE_KEY_PREFIXES['shift_statistics']}all_shifts_{active_only}_{include_stats}"
        cached_result = cache.get(cache_key)

        if cached_result:
            logger.debug("Returning cached shift list")
            return cached_result

        start_time = timezone.now()

        queryset = ShiftMaster.objects.all()

        if active_only:
            queryset = queryset.filter(is_active=True)

        if include_stats:
            queryset = queryset.prefetch_related(
                Prefetch(
                    'assignments',
                    queryset=ShiftAssignment.objects.select_related('user')
                )
            ).annotate(
                total_assignments=Count('assignments'),
                active_assignments=Count(
                    'assignments',
                    filter=Q(assignments__is_current=True)
                )
            )

        shifts = []
        for shift in queryset:
            shift_data = {
                'id': shift.id,
                'name': shift.name,
                'start_time': shift.start_time,
                'end_time': shift.end_time,
                'shift_duration': shift.shift_duration,
                'break_duration': shift.break_duration,
                'grace_period': shift.grace_period,
                'work_days': shift.work_days,
                'custom_work_days': shift.custom_work_days,
                'is_active': shift.is_active,
                'crosses_midnight': shift.crosses_midnight,
                'is_night_shift': shift.is_night_shift(),
                'working_days_list': shift.working_days_list,
                'expected_hours': shift.expected_hours,
                'created_at': shift.created_at,
                'updated_at': shift.updated_at,
            }

            if include_stats:
                shift_data.update({
                    'total_assignments': getattr(shift, 'total_assignments', 0),
                    'active_assignments': getattr(shift, 'active_assignments', 0),
                    'assignment_history': list(shift.assignments.values(
                        'user__username', 'effective_from', 'effective_to', 'is_current'
                    ))
                })

            shifts.append(shift_data)

        # Cache the result
        cache.set(cache_key, shifts, self.cache_timeout)

        # Log performance
        if self.performance_monitoring:
            duration = (timezone.now() - start_time).total_seconds() * 1000
            logger.info(f"get_all_shifts completed in {duration:.2f}ms")

        # Handle pagination if requested
        total_count = len(shifts)
        if page is not None:
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_shifts = shifts[start_idx:end_idx]

            # Calculate pagination info
            total_pages = (total_count + per_page - 1) // per_page
            has_next = page < total_pages
            has_previous = page > 1

            return {
                'shifts': paginated_shifts,
                'pagination': {
                    'current_page': page,
                    'per_page': per_page,
                    'total_count': total_count,
                    'total_pages': total_pages,
                    'has_next': has_next,
                    'has_previous': has_previous,
                    'next_page': page + 1 if has_next else None,
                    'previous_page': page - 1 if has_previous else None,
                },
                'total_shifts': total_count,
            }

        return {
            'shifts': shifts,
            'total_shifts': total_count,
        }

    def get_shift_assignments(self, filters: Dict[str, Any] = None, page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """
        Get shift assignments with optional filtering and pagination.

        Args:
            filters: Dictionary of filters (shift_id, user_id, active_only, etc.)
            page: Page number for pagination
            per_page: Number of items per page

        Returns:
            Dictionary with assignments list, pagination info, and metadata
        """
        queryset = ShiftAssignment.objects.select_related('user', 'shift', 'created_by')

        # Apply filters
        if filters:
            if 'shift_id' in filters and filters['shift_id']:
                queryset = queryset.filter(shift_id=filters['shift_id'])

            if 'user_id' in filters and filters['user_id']:
                queryset = queryset.filter(user_id=filters['user_id'])

            if filters.get('active_only', True):
                queryset = queryset.filter(is_current=True)

            if 'effective_from' in filters and filters['effective_from']:
                queryset = queryset.filter(effective_from__gte=filters['effective_from'])

            if 'effective_to' in filters and filters['effective_to']:
                queryset = queryset.filter(effective_to__lte=filters['effective_to'])

        # Get total count for pagination
        total_count = queryset.count()

        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_queryset = queryset[start_idx:end_idx]

        assignments = []
        for assignment in paginated_queryset:
            # Get user's full name
            user_full_name = f"{assignment.user.first_name} {assignment.user.last_name}".strip()
            if not user_full_name:
                user_full_name = assignment.user.username

            assignment_data = {
                'id': assignment.id,
                'user': {
                    'id': assignment.user.id,
                    'username': assignment.user.username,
                    'first_name': assignment.user.first_name,
                    'last_name': assignment.user.last_name,
                    'email': assignment.user.email,
                    'full_name': user_full_name,
                },
                'shift': {
                    'id': assignment.shift.id,
                    'name': assignment.shift.name,
                    'start_time': assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    'shift_duration': float(assignment.shift.shift_duration),
                },
                'effective_from': assignment.effective_from.strftime('%Y-%m-%d'),
                'effective_to': assignment.effective_to.strftime('%Y-%m-%d') if assignment.effective_to else None,
                'is_current': assignment.is_current,
                'created_at': assignment.created_at.isoformat(),
                'updated_at': assignment.updated_at.isoformat(),
                'created_by': assignment.created_by.username if assignment.created_by else None,
                'notes': assignment.notes,
                'days_remaining': assignment.days_remaining(),
                'total_duration': assignment.total_duration(),
                'has_ended': assignment.has_ended(),
            }
            assignments.append(assignment_data)

        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page
        has_next = page < total_pages
        has_previous = page > 1

        return {
            'assignments': assignments,
            'pagination': {
                'current_page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_previous': has_previous,
                'next_page': page + 1 if has_next else None,
                'previous_page': page - 1 if has_previous else None,
            },
            'filters_applied': filters or {},
            'total_assignments': total_count,
        }

    def get_user_shift_calendar(self, user_or_id, month_or_start_date=None, year_or_end_date=None) -> Dict[str, Any]:
        """
        Get user's shift calendar data for a date range.
        Supports both (user_id, start_date, end_date) and (user, month, year) formats.

        Args:
            user_or_id: User object or User ID
            month_or_start_date: Month number or start date string
            year_or_end_date: Year number or end date string

        Returns:
            Dictionary with calendar data
        """
        # Handle different parameter formats
        if isinstance(user_or_id, User):
            user = user_or_id
        else:
            try:
                user = User.objects.get(id=user_or_id)
            except User.DoesNotExist:
                return {'error': 'User not found'}

        # Handle date parameters - check if they're month/year or date strings
        if isinstance(month_or_start_date, int) and isinstance(year_or_end_date, int):
            # Month/year format
            month = month_or_start_date
            year = year_or_end_date
            start_date = timezone.datetime(year, month, 1).date()
            # Last day of the month
            if month == 12:
                next_month = timezone.datetime(year + 1, 1, 1).date()
            else:
                next_month = timezone.datetime(year, month + 1, 1).date()
            end_date = next_month - timedelta(days=1)
        else:
            # Date string format
            if not month_or_start_date:
                start_date = timezone.now().date().replace(day=1)
            else:
                start_date = timezone.datetime.strptime(month_or_start_date, '%Y-%m-%d').date()

            if not year_or_end_date:
                # Last day of current month
                next_month = start_date.replace(month=start_date.month + 1) if start_date.month < 12 else start_date.replace(year=start_date.year + 1, month=1)
                end_date = next_month - timedelta(days=1)
            else:
                end_date = timezone.datetime.strptime(year_or_end_date, '%Y-%m-%d').date()

        # Get assignments for the date range
        assignments = ShiftAssignment.objects.filter(
            user=user,
            effective_from__lte=end_date
        ).filter(
            Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
        ).select_related('shift')

        # Get holidays for the date range
        holidays = Holiday.objects.filter(
            date__range=(start_date, end_date)
        )

        # Build calendar data
        calendar_events = []
        working_days_count = 0
        holidays_count = 0
        total_expected_hours = 0

        # Generate calendar events for each day
        current_date = start_date
        while current_date <= end_date:
            # Find assignment for this date
            day_assignment = None
            for assignment in assignments:
                if assignment.is_active_on(current_date):
                    day_assignment = assignment
                    break

            # Check if it's a holiday
            is_holiday = any(h.date == current_date for h in holidays)
            if is_holiday:
                holidays_count += 1

            # Determine if it's a working day
            is_working_day = False
            if day_assignment and day_assignment.shift.is_working_day(current_date) and not is_holiday:
                is_working_day = True
                working_days_count += 1
                total_expected_hours += float(day_assignment.shift.expected_hours)

            event = {
                'day': current_date.day,
                'date': current_date.strftime('%Y-%m-%d'),
                'weekday': current_date.strftime('%A'),
                'is_working_day': is_working_day,
                'is_weekend': current_date.weekday() >= 5,
                'is_holiday': is_holiday,
                'assignment': {
                    'id': day_assignment.id,
                    'shift_name': day_assignment.shift.name,
                    'start_time': day_assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': day_assignment.shift.end_time.strftime('%H:%M'),
                } if day_assignment else None,
            }

            calendar_events.append(event)
            current_date += timedelta(days=1)

        return {
            'user': {
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'calendar': calendar_events,
            'summary': {
                'total_days': len(calendar_events),
                'working_days': working_days_count,
                'holidays': holidays_count,
                'total_expected_hours': total_expected_hours,
            },
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
        }

    def get_shift_by_id(self, shift_id: int, include_assignments: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get a specific shift by ID.

        Args:
            shift_id: ID of the shift
            include_assignments: If True, include current assignments

        Returns:
            Shift dictionary or None if not found
        """
        cache_key = f"{CACHE_KEY_PREFIXES['user_current_shift']}shift_{shift_id}_{include_assignments}"
        cached_result = cache.get(cache_key)

        if cached_result:
            return cached_result

        try:
            queryset = ShiftMaster.objects

            if include_assignments:
                queryset = queryset.prefetch_related(
                    Prefetch(
                        'assignments',
                        queryset=ShiftAssignment.objects.filter(is_current=True).select_related('user')
                    )
                )

            shift = queryset.get(id=shift_id)

            shift_data = {
                'id': shift.id,
                'name': shift.name,
                'start_time': shift.start_time,
                'end_time': shift.end_time,
                'shift_duration': shift.shift_duration,
                'break_duration': shift.break_duration,
                'grace_period': shift.grace_period,
                'work_days': shift.work_days,
                'custom_work_days': shift.custom_work_days,
                'is_active': shift.is_active,
                'crosses_midnight': shift.crosses_midnight,
                'is_night_shift': shift.is_night_shift(),
                'working_days_list': shift.working_days_list,
                'expected_hours': shift.expected_hours,
                'created_at': shift.created_at,
                'updated_at': shift.updated_at,
            }

            if include_assignments:
                shift_data['current_assignments'] = [
                    {
                        'id': assignment.id,
                        'user_id': assignment.user.id,
                        'username': assignment.user.username,
                        'user_full_name': f"{assignment.user.first_name} {assignment.user.last_name}".strip(),
                        'effective_from': assignment.effective_from,
                        'effective_to': assignment.effective_to,
                        'notes': assignment.notes,
                    }
                    for assignment in shift.assignments.all()
                ]

            cache.set(cache_key, shift_data, self.cache_timeout)
            return shift_data

        except ShiftMaster.DoesNotExist:
            logger.warning(f"Shift with ID {shift_id} not found")
            return None

    def create_shift(self, shift_data: Dict[str, Any], created_by: User = None) -> AssignmentResult:
        """
        Create a new shift with validation.

        Args:
            shift_data: Dictionary containing shift information
            created_by: User creating the shift

        Returns:
            AssignmentResult with creation status
        """
        try:
            with transaction.atomic():
                # Validate required fields
                required_fields = ['name', 'start_time', 'end_time']
                for field in required_fields:
                    if field not in shift_data:
                        return AssignmentResult(
                            status=AssignmentStatus.ERROR,
                            conflicts=[ConflictDetail(
                                conflict_type=ConflictType.POLICY_VIOLATION,
                                message=f"Required field '{field}' is missing",
                                severity="critical"
                            )]
                        )

                # Check for duplicate shift names
                if ShiftMaster.objects.filter(name__iexact=shift_data['name']).exists():
                    return AssignmentResult(
                        status=AssignmentStatus.CONFLICT,
                        conflicts=[ConflictDetail(
                            conflict_type=ConflictType.POLICY_VIOLATION,
                            message=f"A shift with name '{shift_data['name']}' already exists",
                            severity="high"
                        )]
                    )

                # Create the shift
                shift = ShiftMaster.objects.create(**shift_data)

                # Clear related caches
                self._clear_shift_caches()

                # Log the creation
                logger.info(f"Shift '{shift.name}' created by {created_by}")

                return AssignmentResult(
                    status=AssignmentStatus.SUCCESS,
                    metadata={'shift_id': shift.id, 'shift_name': shift.name}
                )

        except ValidationError as e:
            logger.error(f"Validation error creating shift: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=str(e),
                    severity="high"
                )]
            )
        except Exception as e:
            logger.error(f"Error creating shift: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Failed to create shift: {str(e)}",
                    severity="critical"
                )]
            )

    def update_shift(self, shift_id: int, update_data: Dict[str, Any],
                    updated_by: User = None) -> AssignmentResult:
        """
        Update an existing shift.

        Args:
            shift_id: ID of shift to update
            update_data: Dictionary of fields to update
            updated_by: User making the update

        Returns:
            AssignmentResult with update status
        """
        try:
            with transaction.atomic():
                shift = ShiftMaster.objects.get(id=shift_id)
                original_data = {
                    'name': shift.name,
                    'start_time': shift.start_time,
                    'end_time': shift.end_time,
                }

                # Update fields
                for field, value in update_data.items():
                    if hasattr(shift, field):
                        setattr(shift, field, value)

                # Validate the updated shift
                shift.full_clean()
                shift.save()

                # Check impact on existing assignments
                warnings = self._check_update_impact(shift, original_data)

                # Clear related caches
                self._clear_shift_caches()

                logger.info(f"Shift '{shift.name}' updated by {updated_by}")

                return AssignmentResult(
                    status=AssignmentStatus.SUCCESS,
                    warnings=warnings,
                    metadata={'shift_id': shift.id, 'changes': update_data}
                )

        except ShiftMaster.DoesNotExist:
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Shift with ID {shift_id} not found",
                    severity="high"
                )]
            )
        except Exception as e:
            logger.error(f"Error updating shift {shift_id}: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Failed to update shift: {str(e)}",
                    severity="critical"
                )]
            )

    def delete_shift(self, shift_id: int, deleted_by: User = None,
                    force: bool = False) -> AssignmentResult:
        """
        Delete a shift with safety checks.

        Args:
            shift_id: ID of shift to delete
            deleted_by: User deleting the shift
            force: If True, delete even with active assignments

        Returns:
            AssignmentResult with deletion status
        """
        try:
            with transaction.atomic():
                shift = ShiftMaster.objects.get(id=shift_id)

                # Check for active assignments
                active_assignments = ShiftAssignment.objects.filter(
                    shift=shift,
                    is_current=True
                ).count()

                if active_assignments > 0 and not force:
                    return AssignmentResult(
                        status=AssignmentStatus.CONFLICT,
                        conflicts=[ConflictDetail(
                            conflict_type=ConflictType.POLICY_VIOLATION,
                            message=f"Cannot delete shift '{shift.name}' - {active_assignments} active assignments exist",
                            severity="high",
                            suggestion="End all assignments first or use force=True"
                        )]
                    )

                shift_name = shift.name
                shift.delete()

                # Clear related caches
                self._clear_shift_caches()

                logger.info(f"Shift '{shift_name}' deleted by {deleted_by}")

                return AssignmentResult(
                    status=AssignmentStatus.SUCCESS,
                    metadata={'deleted_shift': shift_name, 'active_assignments': active_assignments}
                )

        except ShiftMaster.DoesNotExist:
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Shift with ID {shift_id} not found",
                    severity="high"
                )]
            )
        except Exception as e:
            logger.error(f"Error deleting shift {shift_id}: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Failed to delete shift: {str(e)}",
                    severity="critical"
                )]
            )

    # ============================
    # ASSIGNMENT MANAGEMENT
    # ============================

    def assign_shift_to_user(self, user: User, shift: ShiftMaster,
                           effective_from: date, effective_to: date = None,
                           created_by: User = None, notes: str = "",
                           force: bool = False) -> AssignmentResult:
        """
        Assign a shift to a user with comprehensive conflict checking.

        Args:
            user: User to assign shift to
            shift: Shift to assign
            effective_from: Start date of assignment
            effective_to: End date of assignment (None for ongoing)
            created_by: User creating the assignment
            notes: Additional notes
            force: If True, skip conflict checking

        Returns:
            AssignmentResult with assignment status
        """
        try:
            with transaction.atomic():
                # Check conflicts unless forced
                if not force:
                    conflicts = self.conflict_detector.check_assignment_conflicts(
                        user, shift, effective_from, effective_to or (effective_from + timedelta(days=365))
                    )

                    if conflicts:
                        critical_conflicts = [c for c in conflicts if c.severity == "critical"]
                        if critical_conflicts:
                            return AssignmentResult(
                                status=AssignmentStatus.CONFLICT,
                                conflicts=conflicts
                            )

                # Create the assignment
                assignment = ShiftAssignment.objects.create(
                    user=user,
                    shift=shift,
                    effective_from=effective_from,
                    effective_to=effective_to,
                    created_by=created_by,
                    notes=notes,
                    is_current=True
                )

                # Clear related caches
                self._clear_user_shift_cache(user.id)

                logger.info(f"Shift '{shift.name}' assigned to {user.username} by {created_by}")

                return AssignmentResult(
                    status=AssignmentStatus.SUCCESS,
                    assignment=assignment,
                    conflicts=conflicts if not force else [],
                    metadata={
                        'assignment_id': assignment.id,
                        'user_id': user.id,
                        'shift_id': shift.id
                    }
                )

        except Exception as e:
            logger.error(f"Error assigning shift {shift.id} to user {user.id}: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Failed to assign shift: {str(e)}",
                    severity="critical"
                )]
            )

    def bulk_assign_shifts(self, assignments_data: List[Dict[str, Any]],
                          created_by: User = None,
                          auto_skip_conflicts: bool = True) -> BulkAssignmentResult:
        """
        Perform bulk shift assignments with intelligent conflict handling.

        Args:
            assignments_data: List of assignment dictionaries
            created_by: User creating the assignments
            auto_skip_conflicts: If True, automatically skip conflicting assignments

        Returns:
            BulkAssignmentResult with detailed results
        """
        result = BulkAssignmentResult(total_attempted=len(assignments_data))

        for assignment_data in assignments_data:
            try:
                user = User.objects.get(id=assignment_data['user_id'])
                shift = ShiftMaster.objects.get(id=assignment_data['shift_id'])
                effective_from = assignment_data['effective_from']
                effective_to = assignment_data.get('effective_to')
                notes = assignment_data.get('notes', '')

                assignment_result = self.assign_shift_to_user(
                    user=user,
                    shift=shift,
                    effective_from=effective_from,
                    effective_to=effective_to,
                    created_by=created_by,
                    notes=notes,
                    force=not auto_skip_conflicts
                )

                if assignment_result.status == AssignmentStatus.SUCCESS:
                    result.successful.append(assignment_result)
                elif assignment_result.status == AssignmentStatus.CONFLICT and auto_skip_conflicts:
                    result.skipped.append(assignment_result)
                else:
                    result.failed.append(assignment_result)

            except (User.DoesNotExist, ShiftMaster.DoesNotExist) as e:
                error_result = AssignmentResult(
                    status=AssignmentStatus.ERROR,
                    conflicts=[ConflictDetail(
                        conflict_type=ConflictType.POLICY_VIOLATION,
                        message=f"Invalid data: {str(e)}",
                        severity="high"
                    )],
                    metadata=assignment_data
                )
                result.failed.append(error_result)

        # Generate summary
        result.summary = {
            'total_attempted': result.total_attempted,
            'successful_count': len(result.successful),
            'failed_count': len(result.failed),
            'skipped_count': len(result.skipped),
            'success_rate': len(result.successful) / result.total_attempted if result.total_attempted > 0 else 0
        }

        logger.info(f"Bulk assignment completed: {len(result.successful)} successful, "
                   f"{len(result.failed)} failed, {len(result.skipped)} skipped")

        return result

    def end_shift_assignment(self, assignment_id: int, end_date: date = None,
                           ended_by: User = None) -> AssignmentResult:
        """
        End a shift assignment.

        Args:
            assignment_id: ID of assignment to end
            end_date: Date to end assignment (defaults to today)
            ended_by: User ending the assignment

        Returns:
            AssignmentResult with status
        """
        try:
            with transaction.atomic():
                assignment = ShiftAssignment.objects.get(id=assignment_id)

                if not end_date:
                    end_date = timezone.now().date()

                if assignment.effective_from > end_date:
                    return AssignmentResult(
                        status=AssignmentStatus.CONFLICT,
                        conflicts=[ConflictDetail(
                            conflict_type=ConflictType.POLICY_VIOLATION,
                            message="End date cannot be before assignment start date",
                            severity="high"
                        )]
                    )

                assignment.effective_to = end_date
                assignment.is_current = False
                assignment.save()

                # Clear related caches
                self._clear_user_shift_cache(assignment.user.id)

                logger.info(f"Assignment {assignment_id} ended by {ended_by}")

                return AssignmentResult(
                    status=AssignmentStatus.SUCCESS,
                    metadata={'assignment_id': assignment_id, 'end_date': end_date}
                )

        except ShiftAssignment.DoesNotExist:
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Assignment with ID {assignment_id} not found",
                    severity="high"
                )]
            )
        except Exception as e:
            logger.error(f"Error ending assignment {assignment_id}: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Failed to end assignment: {str(e)}",
                    severity="critical"
                )]
            )

    # ============================
    # USER SHIFT QUERIES
    # ============================

    def get_current_shift(self, user: User, check_date: date = None) -> Optional[ShiftMaster]:
        """
        Get user's current shift for a specific date.

        Args:
            user: User object
            check_date: Date to check (defaults to today)

        Returns:
            ShiftMaster object or None
        """
        if not check_date:
            check_date = timezone.now().date()

        cache_key = f"{CACHE_KEY_PREFIXES['user_current_shift']}{user.id}_{check_date}"
        cached_shift = cache.get(cache_key)

        if cached_shift:
            return cached_shift

        shift = ShiftAssignment.get_user_current_shift(user, check_date)
        cache.set(cache_key, shift, self.cache_timeout)

        return shift

    def is_working_day_for_user(self, user: User, check_date: date) -> bool:
        """
        Check if a date is a working day for the user.

        Args:
            user: User object
            check_date: Date to check

        Returns:
            True if it's a working day
        """
        # Check holidays first
        if Holiday.is_holiday(check_date):
            return False

        # Get user's shift
        shift = self.get_current_shift(user, check_date)
        if not shift:
            return False

        return shift.is_working_day(check_date)

    def get_user_shift_status(self, user: User) -> Dict[str, Any]:
        """
        Get comprehensive shift status for a user.

        Args:
            user: User object

        Returns:
            Dictionary with shift status information
        """
        now = timezone.now()
        today = now.date()
        current_time = now.time()

        shift = self.get_current_shift(user, today)
        if not shift:
            return {
                'on_shift': False,
                'status': 'no_shift',
                'message': 'No shift assigned',
                'shift': None,
                'next_shift_date': None
            }

        # Check if today is a working day
        if not self.is_working_day_for_user(user, today):
            return {
                'on_shift': False,
                'status': 'non_working_day',
                'message': 'Not a working day' if not Holiday.is_holiday(today) else 'Holiday',
                'shift': {
                    'name': shift.name,
                    'start_time': shift.start_time,
                    'end_time': shift.end_time
                },
                'next_shift_date': self._get_next_working_day(user, today)
            }

        # Check if within shift hours
        is_within_hours = shift.is_within_shift_hours(now, today)

        # Check grace period
        grace_start_dt = timezone.make_aware(
            datetime.combine(today, shift.start_time)
        ) - shift.grace_period

        end_date = today if not shift.crosses_midnight else today + timedelta(days=1)
        grace_end_dt = timezone.make_aware(
            datetime.combine(end_date, shift.end_time)
        ) + shift.grace_period

        within_grace = grace_start_dt <= now <= grace_end_dt

        return {
            'on_shift': is_within_hours,
            'within_grace_period': within_grace,
            'status': 'on_shift' if is_within_hours else 'off_shift',
            'shift': {
                'name': shift.name,
                'start_time': shift.start_time,
                'end_time': shift.end_time,
                'crosses_midnight': shift.crosses_midnight,
                'expected_hours': shift.expected_hours
            },
            'current_time': current_time,
            'message': 'Currently on shift' if is_within_hours else 'Currently off shift'
        }

    def _get_next_working_day(self, user: User, from_date: date) -> Optional[date]:
        """Get the next working day for a user."""
        shift = self.get_current_shift(user, from_date)
        if not shift:
            return None

        check_date = from_date + timedelta(days=1)
        for _ in range(14):  # Check up to 2 weeks ahead
            if self.is_working_day_for_user(user, check_date):
                return check_date
            check_date += timedelta(days=1)

        return None

    # ============================
    # HOLIDAY MANAGEMENT
    # ============================

    def get_holidays(self, year: int = None) -> List[Dict[str, Any]]:
        """
        Get holidays for a specific year.

        Args:
            year: Year to filter by (defaults to current year)

        Returns:
            List of holiday dictionaries
        """
        if not year:
            year = timezone.now().year

        cache_key = f"{CACHE_KEY_PREFIXES['holidays']}{year}"
        cached_holidays = cache.get(cache_key)

        if cached_holidays:
            return cached_holidays

        holidays = []
        holiday_objects = Holiday.objects.filter(date__year=year).order_by('date')

        for holiday in holiday_objects:
            holidays.append({
                'id': holiday.id,
                'name': holiday.name,
                'date': holiday.date,
                'recurring_yearly': holiday.recurring_yearly,
                'created_at': holiday.created_at
            })

        cache.set(cache_key, holidays, CACHE_SETTINGS.get('holidays_timeout', 3600))
        return holidays

    def create_holiday(self, holiday_data: Dict[str, Any], created_by: User = None) -> AssignmentResult:
        """
        Create a new holiday.

        Args:
            holiday_data: Holiday information
            created_by: User creating the holiday

        Returns:
            AssignmentResult with creation status
        """
        try:
            with transaction.atomic():
                # Validate required fields
                if not holiday_data.get('name') or not holiday_data.get('date'):
                    return AssignmentResult(
                        status=AssignmentStatus.ERROR,
                        conflicts=[ConflictDetail(
                            conflict_type=ConflictType.POLICY_VIOLATION,
                            message="Holiday name and date are required",
                            severity="high"
                        )]
                    )

                # Check for duplicates
                existing = Holiday.objects.filter(
                    name__iexact=holiday_data['name'],
                    date=holiday_data['date']
                ).exists()

                if existing:
                    return AssignmentResult(
                        status=AssignmentStatus.CONFLICT,
                        conflicts=[ConflictDetail(
                            conflict_type=ConflictType.POLICY_VIOLATION,
                            message=f"Holiday '{holiday_data['name']}' already exists on {holiday_data['date']}",
                            severity="medium"
                        )]
                    )

                # Create holiday
                holiday = Holiday.objects.create(**holiday_data)

                # Clear holiday cache
                self._clear_holiday_caches()

                logger.info(f"Holiday '{holiday.name}' created by {created_by}")

                return AssignmentResult(
                    status=AssignmentStatus.SUCCESS,
                    metadata={'holiday_id': holiday.id, 'holiday_name': holiday.name}
                )

        except Exception as e:
            logger.error(f"Error creating holiday: {e}")
            return AssignmentResult(
                status=AssignmentStatus.ERROR,
                conflicts=[ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Failed to create holiday: {str(e)}",
                    severity="critical"
                )]
            )

    # ============================
    # STATISTICS AND REPORTING
    # ============================

    def get_shift_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive shift management statistics.

        Returns:
            Dictionary with various statistics
        """
        cache_key = f"{CACHE_KEY_PREFIXES['shift_statistics']}overview"
        cached_stats = cache.get(cache_key)

        if cached_stats:
            return cached_stats

        start_time = timezone.now()

        try:
            today = timezone.now().date()

            # Basic counts with single queries
            shifts_stats = ShiftMaster.objects.aggregate(
                total_shifts=Count('id'),
                active_shifts=Count('id', filter=Q(is_active=True))
            )

            assignment_stats = ShiftAssignment.objects.aggregate(
                total_assignments=Count('id'),
                current_assignments=Count('id', filter=Q(is_current=True))
            )

            # User statistics
            user_stats = User.objects.aggregate(
                total_users=Count('id'),
                users_with_shifts=Count('id', filter=Q(shift_assignments__is_current=True))
            )

            # Shift distribution
            shift_distribution = list(ShiftMaster.objects.filter(is_active=True).annotate(
                assignment_count=Count('assignments', filter=Q(assignments__is_current=True))
            ).values('name', 'assignment_count'))

            # Recent activity
            thirty_days_ago = today - timedelta(days=30)
            recent_assignments = ShiftAssignment.objects.filter(
                created_at__date__gte=thirty_days_ago
            ).count()

            # Upcoming changes
            upcoming_changes = ShiftAssignment.objects.filter(
                effective_to__range=(today, today + timedelta(days=7))
            ).count()

            # Holiday statistics
            holiday_stats = Holiday.objects.aggregate(
                total_holidays=Count('id')
            )

            stats = {
                'overview': {
                    'total_shifts': shifts_stats['total_shifts'],
                    'active_shifts': shifts_stats['active_shifts'],
                    'inactive_shifts': shifts_stats['total_shifts'] - shifts_stats['active_shifts'],
                    'total_assignments': assignment_stats['total_assignments'],
                    'current_assignments': assignment_stats['current_assignments']
                },
                'users': {
                    'total_users': user_stats['total_users'],
                    'users_with_shifts': user_stats['users_with_shifts'],
                    'users_without_shifts': user_stats['total_users'] - user_stats['users_with_shifts'],
                    'coverage_percentage': round(
                        (user_stats['users_with_shifts'] / user_stats['total_users'] * 100)
                        if user_stats['total_users'] > 0 else 0, 2
                    )
                },
                'shift_distribution': shift_distribution,
                'activity': {
                    'recent_assignments': recent_assignments,
                    'upcoming_changes': upcoming_changes
                },
                'holidays': {
                    'total_holidays': holiday_stats['total_holidays']
                },
                'updated_at': timezone.now()
            }

            # Cache the results
            cache.set(cache_key, stats, CACHE_SETTINGS.get('statistics_timeout', 1800))

            # Log performance
            if self.performance_monitoring:
                duration = (timezone.now() - start_time).total_seconds() * 1000
                logger.info(f"get_shift_statistics completed in {duration:.2f}ms")

            return stats

        except Exception as e:
            logger.error(f"Error getting shift statistics: {e}")
            raise

    def get_shift_schedule_for_date(self, check_date: date) -> Dict[str, Any]:
        """
        Get shift schedule for a specific date.

        Args:
            check_date: Date to get schedule for

        Returns:
            Dictionary with schedule information
        """
        cache_key = f"{CACHE_KEY_PREFIXES['schedule']}{check_date}"
        cached_schedule = cache.get(cache_key)

        if cached_schedule:
            return cached_schedule

        try:
            # Get active assignments for the date
            assignments = ShiftAssignment.objects.filter(
                effective_from__lte=check_date
            ).filter(
                Q(effective_to__gte=check_date) | Q(effective_to__isnull=True)
            ).select_related('user', 'shift')

            schedule = {}
            total_scheduled = 0
            is_holiday = Holiday.is_holiday(check_date)

            for assignment in assignments:
                shift = assignment.shift
                user = assignment.user

                # Check if user should work on this date
                if shift.is_working_day(check_date) and not is_holiday:
                    if shift.name not in schedule:
                        schedule[shift.name] = {
                            'shift_info': {
                                'id': shift.id,
                                'name': shift.name,
                                'start_time': shift.start_time,
                                'end_time': shift.end_time,
                                'duration': shift.shift_duration,
                                'crosses_midnight': shift.crosses_midnight
                            },
                            'users': []
                        }

                    schedule[shift.name]['users'].append({
                        'id': user.id,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'email': user.email,
                        'assignment_id': assignment.id
                    })
                    total_scheduled += 1

            result = {
                'date': check_date,
                'schedule': schedule,
                'total_scheduled': total_scheduled,
                'is_holiday': is_holiday,
                'day_name': check_date.strftime('%A')
            }

            # Cache the result
            cache.set(cache_key, result, self.cache_timeout)
            return result

        except Exception as e:
            logger.error(f"Error getting schedule for {check_date}: {e}")
            return {
                'date': check_date,
                'schedule': {},
                'total_scheduled': 0,
                'is_holiday': False,
                'error': str(e)
            }

            # Get holiday information
            holiday_info = None
            if is_holiday:
                holiday = Holiday.objects.filter(
                    Q(date=check_date) |
                    Q(recurring_yearly=True, date__month=check_date.month, date__day=check_date.day)
                ).first()
                if holiday:
                    holiday_info = {
                        'name': holiday.name,
                        'date': holiday.date,
                        'recurring': holiday.recurring_yearly
                    }

            result = {
                'date': check_date,
                'weekday': check_date.strftime('%A'),
                'is_holiday': is_holiday,
                'holiday_info': holiday_info,
                'total_scheduled': total_scheduled,
                'shifts': schedule,
                'summary': {
                    'total_shifts': len(schedule),
                    'total_users': total_scheduled
                }
            }

            # Cache the result
            cache.set(cache_key, result, self.cache_timeout)
            return result

        except Exception as e:
            logger.error(f"Error getting schedule for {check_date}: {e}")
            return {
                'date': check_date,
                'schedule': {},
                'total_scheduled': 0,
                'is_holiday': False,
                'error': str(e)
            }

    # ============================
    # UTILITY AND CACHE METHODS
    # ============================

    def _clear_shift_caches(self):
        """Clear all shift-related caches."""
        cache_patterns = [
            f"{CACHE_KEY_PREFIXES['shift_statistics']}*",
            f"{CACHE_KEY_PREFIXES['user_current_shift']}*",
            f"{CACHE_KEY_PREFIXES['schedule']}*"
        ]
        for pattern in cache_patterns:
            try:
                cache.delete_many(cache.keys(pattern))
            except Exception:
                pass  # Cache backend may not support pattern deletion

    def _clear_user_shift_cache(self, user_id: int):
        """Clear shift cache for a specific user."""
        cache_pattern = f"{CACHE_KEY_PREFIXES['user_current_shift']}{user_id}_*"
        try:
            cache.delete_many(cache.keys(cache_pattern))
        except Exception:
            pass

    def _clear_holiday_caches(self):
        """Clear holiday-related caches."""
        cache_pattern = f"{CACHE_KEY_PREFIXES['holidays']}*"
        try:
            cache.delete_many(cache.keys(cache_pattern))
        except Exception:
            pass

    def _check_update_impact(self, shift: ShiftMaster, original_data: Dict[str, Any]) -> List[str]:
        """Check impact of shift updates on existing assignments."""
        warnings = []

        # Check if timing changed
        if (original_data['start_time'] != shift.start_time or
            original_data['end_time'] != shift.end_time):

            active_assignments = ShiftAssignment.objects.filter(
                shift=shift,
                is_current=True
            ).count()

            if active_assignments > 0:
                warnings.append(
                    f"Shift timing changed - this affects {active_assignments} active assignments"
                )

        # Check if name changed
        if original_data['name'] != shift.name:
            warnings.append("Shift name changed - update any external references")

        return warnings

    def validate_assignment_data(self, assignment_data: Dict[str, Any]) -> List[ConflictDetail]:
        """
        Validate assignment data before processing.

        Args:
            assignment_data: Assignment data to validate

        Returns:
            List of validation conflicts
        """
        conflicts = []

        # Required fields validation
        required_fields = ['user_id', 'shift_id', 'effective_from']
        for field in required_fields:
            if field not in assignment_data:
                conflicts.append(ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message=f"Required field '{field}' is missing",
                    severity="critical"
                ))

        # Date validation
        if 'effective_from' in assignment_data:
            try:
                effective_from = assignment_data['effective_from']
                if isinstance(effective_from, str):
                    effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()

                if effective_from < timezone.now().date() - timedelta(days=7):
                    conflicts.append(ConflictDetail(
                        conflict_type=ConflictType.POLICY_VIOLATION,
                        message="Assignment cannot be more than 7 days in the past",
                        severity="medium"
                    ))
            except (ValueError, TypeError):
                conflicts.append(ConflictDetail(
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    message="Invalid effective_from date format",
                    severity="high"
                ))

        return conflicts

    def get_assignment_recommendations(self, user: User, shift: ShiftMaster) -> List[str]:
        """
        Get recommendations for a shift assignment.

        Args:
            user: User to assign shift to
            shift: Shift to assign

        Returns:
            List of recommendation strings
        """
        recommendations = []

        # Check user's shift history
        recent_assignments = ShiftAssignment.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count()

        if recent_assignments >= 3:
            recommendations.append(
                "User has had multiple shift changes recently - consider stability"
            )

        # Check shift compatibility
        current_shift = self.get_current_shift(user)
        if current_shift:
            if current_shift.is_night_shift() and not shift.is_night_shift():
                recommendations.append(
                    "Transitioning from night to day shift - consider adjustment period"
                )
            elif not current_shift.is_night_shift() and shift.is_night_shift():
                recommendations.append(
                    "Transitioning from day to night shift - consider adjustment period"
                )

        # Check optimal timing
        if shift.grace_period.total_seconds() < 600:  # Less than 10 minutes
            recommendations.append(
                "Consider increasing grace period for better attendance flexibility"
            )

        return recommendations

    def get_user_availability_status(self, user_id: int, date: date = None) -> Dict[str, Any]:
        """
        Get user's availability status for a specific date.

        Args:
            user_id: User ID to check
            date: Date to check (defaults to today)

        Returns:
            Dictionary with availability status
        """
        if date is None:
            date = timezone.now().date()

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return {'error': 'User not found'}

        # Check current assignment
        current_assignment = ShiftAssignment.current_assignment_for_user(user)

        # Check if on leave
        from ..models import LeaveRequest
        on_leave = LeaveRequest.objects.filter(
            user=user,
            start_date__lte=date,
            end_date__gte=date,
            status='Approved'
        ).exists()

        # Check if holiday
        is_holiday = Holiday.is_holiday(date)

        return {
            'user_id': user_id,
            'date': date.strftime('%Y-%m-%d'),
            'available': bool(current_assignment and not on_leave and not is_holiday),
            'current_assignment': {
                'id': current_assignment.id,
                'shift_name': current_assignment.shift.name,
                'shift_times': f"{current_assignment.shift.start_time} - {current_assignment.shift.end_time}"
            } if current_assignment else None,
            'on_leave': on_leave,
            'is_holiday': is_holiday,
            'status': 'Available' if current_assignment and not on_leave and not is_holiday else
                     'On Leave' if on_leave else
                     'Holiday' if is_holiday else
                     'No Assignment'
        }

    def get_shift_coverage_report(self, start_date: date, end_date: date) -> Dict[str, Any]:
        """
        Generate shift coverage report for a date range.

        Args:
            start_date: Start date for the report
            end_date: End date for the report

        Returns:
            Dictionary with coverage statistics
        """
        assignments = ShiftAssignment.objects.filter(
            effective_from__lte=end_date
        ).filter(
            Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
        ).select_related('user', 'shift')

        coverage_data = {}
        current_date = start_date

        while current_date <= end_date:
            day_coverage = {}
            day_total = 0

            for assignment in assignments:
                if assignment.is_active_on(current_date) and assignment.shift.is_working_day(current_date):
                    shift_name = assignment.shift.name
                    if shift_name not in day_coverage:
                        day_coverage[shift_name] = 0
                    day_coverage[shift_name] += 1
                    day_total += 1

            coverage_data[current_date.strftime('%Y-%m-%d')] = {
                'date': current_date,
                'day_name': current_date.strftime('%A'),
                'is_weekend': current_date.weekday() >= 5,
                'is_holiday': Holiday.is_holiday(current_date),
                'shift_coverage': day_coverage,
                'total_coverage': day_total
            }

            current_date += timedelta(days=1)

        return {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'coverage_data': coverage_data,
            'total_days': (end_date - start_date).days + 1
        }
