"""
Advanced Conflict Resolution Service for TrueAlign Shift Management

This module provides sophisticated conflict detection and resolution capabilities
for shift assignments, including:

- Multi-dimensional conflict analysis
- Intelligent resolution suggestions
- Automatic conflict resolution strategies
- Performance-optimized conflict detection
- Detailed conflict reporting and audit trails
- Configurable resolution policies

Author: TrueAlign Development Team
Version: 2.0.0
"""

import logging
from datetime import datetime, timedelta, time, date
from typing import List, Dict, Optional, Tuple, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import itertools

from django.db import transaction, models
from django.db.models import Q, F, Count, Prefetch
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from .services import ConflictType, ConflictDetail, AssignmentResult, AssignmentStatus
from .app_settings import SHIFT_VALIDATION, CACHE_SETTINGS, PERFORMANCE_MONITORING

logger = logging.getLogger('trueAlign.shift.conflict_resolver')


class ResolutionStrategy(Enum):
    """Available conflict resolution strategies."""
    MANUAL_REVIEW = "manual_review"
    AUTO_SKIP = "auto_skip"
    AUTO_ADJUST_DATES = "auto_adjust_dates"
    AUTO_SPLIT_ASSIGNMENT = "auto_split_assignment"
    SUGGEST_ALTERNATIVE_SHIFT = "suggest_alternative_shift"
    SUGGEST_ALTERNATIVE_DATES = "suggest_alternative_dates"
    PRIORITY_BASED = "priority_based"


class ConflictSeverity(Enum):
    """Conflict severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ResolutionOption:
    """A potential resolution for a conflict."""
    strategy: ResolutionStrategy
    description: str
    impact_score: float  # 0.0 to 1.0, lower is better
    feasibility_score: float  # 0.0 to 1.0, higher is better
    automated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    side_effects: List[str] = field(default_factory=list)
    required_approvals: List[str] = field(default_factory=list)


@dataclass
class ConflictAnalysis:
    """Comprehensive analysis of a conflict."""
    conflict_id: str
    conflict_type: ConflictType
    severity: ConflictSeverity
    affected_users: List[User]
    affected_shifts: List[ShiftMaster]
    affected_assignments: List[ShiftAssignment]
    time_overlap: Optional[Tuple[datetime, datetime]] = None
    business_impact: str = ""
    resolution_options: List[ResolutionOption] = field(default_factory=list)
    recommended_action: Optional[ResolutionOption] = None
    auto_resolvable: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResolutionResult:
    """Result of a conflict resolution attempt."""
    success: bool
    resolution_applied: Optional[ResolutionOption] = None
    conflicts_resolved: List[str] = field(default_factory=list)
    new_conflicts_created: List[ConflictAnalysis] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConflictDetectionEngine:
    """Advanced conflict detection engine with multi-dimensional analysis."""

    def __init__(self):
        """Initialize the conflict detection engine."""
        self.cache_timeout = CACHE_SETTINGS.get('default_timeout', 300)
        self.performance_monitoring = PERFORMANCE_MONITORING.get('enabled', True)

    def detect_all_conflicts(self, start_date: date, end_date: date,
                           user_ids: List[int] = None) -> List[ConflictAnalysis]:
        """
        Detect all conflicts in the specified date range.

        Args:
            start_date: Start date for conflict detection
            end_date: End date for conflict detection
            user_ids: Optional list of user IDs to check (None for all users)

        Returns:
            List of conflict analyses
        """
        start_time = timezone.now()
        conflicts = []

        try:
            # Get all relevant assignments
            assignments = self._get_assignments_in_range(start_date, end_date, user_ids)

            # Group assignments by user for efficient processing
            user_assignments = defaultdict(list)
            for assignment in assignments:
                user_assignments[assignment.user.id].append(assignment)

            # Detect time-based conflicts
            for user_id, user_assigns in user_assignments.items():
                user_conflicts = self._detect_user_time_conflicts(user_assigns)
                conflicts.extend(user_conflicts)

            # Detect business rule violations
            business_conflicts = self._detect_business_rule_conflicts(assignments)
            conflicts.extend(business_conflicts)

            # Detect capacity and resource conflicts
            capacity_conflicts = self._detect_capacity_conflicts(assignments, start_date, end_date)
            conflicts.extend(capacity_conflicts)

            # Detect policy violations
            policy_conflicts = self._detect_policy_violations(assignments)
            conflicts.extend(policy_conflicts)

            # Generate resolution options for each conflict
            for conflict in conflicts:
                conflict.resolution_options = self._generate_resolution_options(conflict)
                conflict.recommended_action = self._select_recommended_action(conflict)
                conflict.auto_resolvable = self._is_auto_resolvable(conflict)

            # Log performance
            if self.performance_monitoring:
                duration = (timezone.now() - start_time).total_seconds() * 1000
                logger.info(f"Conflict detection completed in {duration:.2f}ms - "
                           f"found {len(conflicts)} conflicts")

            return conflicts

        except Exception as e:
            logger.error(f"Error in conflict detection: {e}")
            raise

    def _get_assignments_in_range(self, start_date: date, end_date: date,
                                user_ids: List[int] = None) -> List[ShiftAssignment]:
        """Get all assignments that overlap with the specified date range."""
        query = ShiftAssignment.objects.filter(
            effective_from__lte=end_date
        ).filter(
            Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
        ).select_related('user', 'shift')

        if user_ids:
            query = query.filter(user_id__in=user_ids)

        return list(query.order_by('user', 'effective_from'))

    def _detect_user_time_conflicts(self, assignments: List[ShiftAssignment]) -> List[ConflictAnalysis]:
        """Detect time-based conflicts for a single user's assignments."""
        conflicts = []

        # Sort assignments by start date
        sorted_assignments = sorted(assignments, key=lambda x: x.effective_from)

        # Check each pair of assignments for overlaps
        for i, assign1 in enumerate(sorted_assignments):
            for assign2 in sorted_assignments[i+1:]:
                overlap_analysis = self._analyze_assignment_overlap(assign1, assign2)
                if overlap_analysis:
                    conflicts.append(overlap_analysis)

        return conflicts

    def _analyze_assignment_overlap(self, assign1: ShiftAssignment,
                                  assign2: ShiftAssignment) -> Optional[ConflictAnalysis]:
        """Analyze potential overlap between two assignments."""
        # Check date range overlap
        assign1_end = assign1.effective_to or date(2099, 12, 31)
        assign2_end = assign2.effective_to or date(2099, 12, 31)

        if not (assign1.effective_from <= assign2_end and assign2.effective_from <= assign1_end):
            return None  # No date overlap

        # Find overlapping dates
        overlap_start = max(assign1.effective_from, assign2.effective_from)
        overlap_end = min(assign1_end, assign2_end)

        # Check for time conflicts on overlapping dates
        time_conflicts = []
        current_date = overlap_start

        while current_date <= overlap_end:
            if self._shifts_conflict_on_date(assign1.shift, assign2.shift, current_date):
                shift1_start, shift1_end = self._get_shift_datetime_range(assign1.shift, current_date)
                shift2_start, shift2_end = self._get_shift_datetime_range(assign2.shift, current_date)

                time_overlap_start = max(shift1_start, shift2_start)
                time_overlap_end = min(shift1_end, shift2_end)

                if time_overlap_start < time_overlap_end:
                    time_conflicts.append((current_date, time_overlap_start, time_overlap_end))

            current_date += timedelta(days=1)

        if not time_conflicts:
            return None

        # Calculate severity based on overlap duration and frequency
        total_overlap_minutes = sum(
            (end - start).total_seconds() / 60
            for _, start, end in time_conflicts
        )

        severity = self._calculate_conflict_severity(total_overlap_minutes, len(time_conflicts))

        # Create conflict analysis
        conflict_id = f"time_overlap_{assign1.id}_{assign2.id}"

        return ConflictAnalysis(
            conflict_id=conflict_id,
            conflict_type=ConflictType.TIME_OVERLAP,
            severity=severity,
            affected_users=[assign1.user],
            affected_shifts=[assign1.shift, assign2.shift],
            affected_assignments=[assign1, assign2],
            time_overlap=(time_conflicts[0][1], time_conflicts[-1][2]) if time_conflicts else None,
            business_impact=self._assess_business_impact(assign1, assign2, time_conflicts),
            metadata={
                'total_overlap_minutes': total_overlap_minutes,
                'conflict_days': len(time_conflicts),
                'time_conflicts': time_conflicts
            }
        )

    def _shifts_conflict_on_date(self, shift1: ShiftMaster, shift2: ShiftMaster, check_date: date) -> bool:
        """Check if two shifts conflict on a specific date."""
        # Both shifts must be working days
        if not (shift1.is_working_day(check_date) and shift2.is_working_day(check_date)):
            return False

        # Check if it's a holiday
        if Holiday.is_holiday(check_date):
            return False

        # Get time ranges for both shifts
        start1, end1 = self._get_shift_datetime_range(shift1, check_date)
        start2, end2 = self._get_shift_datetime_range(shift2, check_date)

        # Check for time overlap
        return start1 < end2 and start2 < end1

    def _get_shift_datetime_range(self, shift: ShiftMaster, base_date: date) -> Tuple[datetime, datetime]:
        """Get datetime range for a shift on a specific date."""
        start_dt = timezone.make_aware(datetime.combine(base_date, shift.start_time))

        if shift.crosses_midnight:
            end_dt = timezone.make_aware(datetime.combine(base_date + timedelta(days=1), shift.end_time))
        else:
            end_dt = timezone.make_aware(datetime.combine(base_date, shift.end_time))

        return start_dt, end_dt

    def _calculate_conflict_severity(self, overlap_minutes: float, conflict_days: int) -> ConflictSeverity:
        """Calculate conflict severity based on overlap duration and frequency."""
        if overlap_minutes >= 480 or conflict_days >= 5:  # 8+ hours or 5+ days
            return ConflictSeverity.CRITICAL
        elif overlap_minutes >= 240 or conflict_days >= 3:  # 4+ hours or 3+ days
            return ConflictSeverity.HIGH
        elif overlap_minutes >= 60 or conflict_days >= 2:  # 1+ hours or 2+ days
            return ConflictSeverity.MEDIUM
        else:
            return ConflictSeverity.LOW

    def _assess_business_impact(self, assign1: ShiftAssignment, assign2: ShiftAssignment,
                              time_conflicts: List[Tuple]) -> str:
        """Assess the business impact of a conflict."""
        impact_factors = []

        # Check if shifts are critical operations
        if any('critical' in shift.name.lower() or 'emergency' in shift.name.lower()
               for shift in [assign1.shift, assign2.shift]):
            impact_factors.append("Critical operations affected")

        # Check overlap during business hours
        business_hours_overlap = any(
            9 <= start.hour <= 17 for _, start, _ in time_conflicts
        )
        if business_hours_overlap:
            impact_factors.append("Business hours affected")

        # Check weekend/holiday impact
        weekend_conflicts = any(
            conflict_date.weekday() >= 5 for conflict_date, _, _ in time_conflicts
        )
        if weekend_conflicts:
            impact_factors.append("Weekend coverage affected")

        return "; ".join(impact_factors) if impact_factors else "Minimal business impact"

    def _detect_business_rule_conflicts(self, assignments: List[ShiftAssignment]) -> List[ConflictAnalysis]:
        """Detect business rule violations."""
        conflicts = []

        # Group assignments by user
        user_assignments = defaultdict(list)
        for assignment in assignments:
            user_assignments[assignment.user.id].append(assignment)

        for user_id, user_assigns in user_assignments.items():
            # Check for excessive assignment changes
            recent_changes = len([a for a in user_assigns
                                if a.created_at >= timezone.now() - timedelta(days=30)])

            if recent_changes >= 5:
                conflicts.append(ConflictAnalysis(
                    conflict_id=f"excessive_changes_{user_id}",
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    severity=ConflictSeverity.MEDIUM,
                    affected_users=[user_assigns[0].user],
                    affected_shifts=[a.shift for a in user_assigns],
                    affected_assignments=user_assigns,
                    business_impact="Potential user fatigue and adjustment issues",
                    metadata={'recent_changes': recent_changes}
                ))

            # Check for rapid consecutive assignments without buffer time
            sorted_assigns = sorted(user_assigns, key=lambda x: x.effective_from)
            for i in range(len(sorted_assigns) - 1):
                current = sorted_assigns[i]
                next_assign = sorted_assigns[i + 1]

                if current.effective_to:
                    gap = (next_assign.effective_from - current.effective_to).days
                    if gap < 1:
                        conflicts.append(ConflictAnalysis(
                            conflict_id=f"no_buffer_time_{current.id}_{next_assign.id}",
                            conflict_type=ConflictType.POLICY_VIOLATION,
                            severity=ConflictSeverity.HIGH,
                            affected_users=[current.user],
                            affected_shifts=[current.shift, next_assign.shift],
                            affected_assignments=[current, next_assign],
                            business_impact="No adjustment time between different shifts",
                            metadata={'gap_days': gap}
                        ))

        return conflicts

    def _detect_capacity_conflicts(self, assignments: List[ShiftAssignment],
                                 start_date: date, end_date: date) -> List[ConflictAnalysis]:
        """Detect capacity and resource conflicts."""
        conflicts = []

        # Group assignments by shift and date
        shift_coverage = defaultdict(lambda: defaultdict(list))

        current_date = start_date
        while current_date <= end_date:
            for assignment in assignments:
                if assignment.is_active_on(current_date):
                    shift = assignment.shift
                    if shift.is_working_day(current_date) and not Holiday.is_holiday(current_date):
                        shift_coverage[shift.id][current_date].append(assignment)
            current_date += timedelta(days=1)

        # Check for under/over-staffing
        for shift_id, date_assignments in shift_coverage.items():
            for check_date, day_assignments in date_assignments.items():
                # This is a placeholder for capacity rules - would need business requirements
                if len(day_assignments) > 10:  # Example: max 10 people per shift
                    conflicts.append(ConflictAnalysis(
                        conflict_id=f"overstaffed_{shift_id}_{check_date}",
                        conflict_type=ConflictType.CAPACITY_EXCEEDED,
                        severity=ConflictSeverity.MEDIUM,
                        affected_users=[a.user for a in day_assignments],
                        affected_shifts=[day_assignments[0].shift],
                        affected_assignments=day_assignments,
                        business_impact="Potential resource waste and coordination issues",
                        metadata={
                            'date': check_date,
                            'assigned_count': len(day_assignments),
                            'max_capacity': 10
                        }
                    ))

        return conflicts

    def _detect_policy_violations(self, assignments: List[ShiftAssignment]) -> List[ConflictAnalysis]:
        """Detect policy violations in assignments."""
        conflicts = []

        for assignment in assignments:
            # Check assignment duration limits
            if assignment.effective_to:
                duration = (assignment.effective_to - assignment.effective_from).days
                if duration > 365:  # Max 1 year assignments
                    conflicts.append(ConflictAnalysis(
                        conflict_id=f"excessive_duration_{assignment.id}",
                        conflict_type=ConflictType.POLICY_VIOLATION,
                        severity=ConflictSeverity.HIGH,
                        affected_users=[assignment.user],
                        affected_shifts=[assignment.shift],
                        affected_assignments=[assignment],
                        business_impact="Long-term assignments may need review",
                        metadata={'duration_days': duration}
                    ))

            # Check for inactive shift assignments
            if not assignment.shift.is_active:
                conflicts.append(ConflictAnalysis(
                    conflict_id=f"inactive_shift_{assignment.id}",
                    conflict_type=ConflictType.POLICY_VIOLATION,
                    severity=ConflictSeverity.CRITICAL,
                    affected_users=[assignment.user],
                    affected_shifts=[assignment.shift],
                    affected_assignments=[assignment],
                    business_impact="User assigned to inactive shift",
                    metadata={'shift_active': assignment.shift.is_active}
                ))

        return conflicts

    def _generate_resolution_options(self, conflict: ConflictAnalysis) -> List[ResolutionOption]:
        """Generate resolution options for a conflict."""
        options = []

        if conflict.conflict_type == ConflictType.TIME_OVERLAP:
            options.extend(self._generate_time_overlap_resolutions(conflict))
        elif conflict.conflict_type == ConflictType.POLICY_VIOLATION:
            options.extend(self._generate_policy_violation_resolutions(conflict))
        elif conflict.conflict_type == ConflictType.CAPACITY_EXCEEDED:
            options.extend(self._generate_capacity_resolutions(conflict))

        # Always add manual review option
        options.append(ResolutionOption(
            strategy=ResolutionStrategy.MANUAL_REVIEW,
            description="Flag for manual review by administrator",
            impact_score=0.1,
            feasibility_score=1.0,
            automated=False,
            required_approvals=["manager", "hr"]
        ))

        return options

    def _generate_time_overlap_resolutions(self, conflict: ConflictAnalysis) -> List[ResolutionOption]:
        """Generate resolution options for time overlap conflicts."""
        options = []

        if len(conflict.affected_assignments) == 2:
            assign1, assign2 = conflict.affected_assignments

            # Option 1: End first assignment before second starts
            options.append(ResolutionOption(
                strategy=ResolutionStrategy.AUTO_ADJUST_DATES,
                description=f"End '{assign1.shift.name}' assignment one day before '{assign2.shift.name}' starts",
                impact_score=0.3,
                feasibility_score=0.8,
                automated=True,
                metadata={
                    'action': 'adjust_end_date',
                    'assignment_id': assign1.id,
                    'new_end_date': assign2.effective_from - timedelta(days=1)
                }
            ))

            # Option 2: Delay second assignment
            options.append(ResolutionOption(
                strategy=ResolutionStrategy.AUTO_ADJUST_DATES,
                description=f"Delay '{assign2.shift.name}' assignment until after '{assign1.shift.name}' ends",
                impact_score=0.4,
                feasibility_score=0.7,
                automated=True,
                metadata={
                    'action': 'adjust_start_date',
                    'assignment_id': assign2.id,
                    'new_start_date': (assign1.effective_to or assign1.effective_from + timedelta(days=30)) + timedelta(days=1)
                }
            ))

            # Option 3: Suggest alternative shifts
            options.append(ResolutionOption(
                strategy=ResolutionStrategy.SUGGEST_ALTERNATIVE_SHIFT,
                description="Suggest alternative shifts that don't conflict",
                impact_score=0.2,
                feasibility_score=0.6,
                automated=False,
                metadata={'require_alternative_analysis': True}
            ))

        return options

    def _generate_policy_violation_resolutions(self, conflict: ConflictAnalysis) -> List[ResolutionOption]:
        """Generate resolution options for policy violations."""
        options = []

        if 'inactive_shift' in conflict.conflict_id:
            options.append(ResolutionOption(
                strategy=ResolutionStrategy.SUGGEST_ALTERNATIVE_SHIFT,
                description="Replace with active shift assignment",
                impact_score=0.2,
                feasibility_score=0.9,
                automated=False,
                required_approvals=["manager"]
            ))

        if 'excessive_duration' in conflict.conflict_id:
            options.append(ResolutionOption(
                strategy=ResolutionStrategy.AUTO_SPLIT_ASSIGNMENT,
                description="Split long assignment into smaller periods with reviews",
                impact_score=0.3,
                feasibility_score=0.7,
                automated=True,
                metadata={'split_duration_days': 90}
            ))

        return options

    def _generate_capacity_resolutions(self, conflict: ConflictAnalysis) -> List[ResolutionOption]:
        """Generate resolution options for capacity conflicts."""
        options = []

        if 'overstaffed' in conflict.conflict_id:
            options.append(ResolutionOption(
                strategy=ResolutionStrategy.SUGGEST_ALTERNATIVE_DATES,
                description="Redistribute assignments across different dates",
                impact_score=0.4,
                feasibility_score=0.6,
                automated=False,
                required_approvals=["manager"]
            ))

        return options

    def _select_recommended_action(self, conflict: ConflictAnalysis) -> Optional[ResolutionOption]:
        """Select the recommended resolution action."""
        if not conflict.resolution_options:
            return None

        # Score options based on impact, feasibility, and automation capability
        scored_options = []
        for option in conflict.resolution_options:
            score = (option.feasibility_score * 0.6) - (option.impact_score * 0.4)
            if option.automated and conflict.severity in [ConflictSeverity.LOW, ConflictSeverity.MEDIUM]:
                score += 0.2
            scored_options.append((score, option))

        # Return highest scoring option
        scored_options.sort(key=lambda x: x[0], reverse=True)
        return scored_options[0][1]

    def _is_auto_resolvable(self, conflict: ConflictAnalysis) -> bool:
        """Determine if conflict can be automatically resolved."""
        if not conflict.recommended_action:
            return False

        # Only auto-resolve low to medium severity conflicts
        if conflict.severity in [ConflictSeverity.HIGH, ConflictSeverity.CRITICAL]:
            return False

        # Only auto-resolve if recommended action is automated
        return conflict.recommended_action.automated and not conflict.recommended_action.required_approvals


class ConflictResolver:
    """Advanced conflict resolution service."""

    def __init__(self):
        """Initialize the conflict resolver."""
        self.detection_engine = ConflictDetectionEngine()
        self.resolution_history = []

    def resolve_conflict(self, conflict: ConflictAnalysis,
                        resolution: ResolutionOption = None,
                        user: User = None) -> ResolutionResult:
        """
        Resolve a specific conflict.

        Args:
            conflict: Conflict to resolve
            resolution: Specific resolution to apply (None for recommended)
            user: User performing the resolution

        Returns:
            ResolutionResult with details of the resolution
        """
        try:
            if not resolution:
                resolution = conflict.recommended_action

            if not resolution:
                return ResolutionResult(
                    success=False,
                    warnings=["No resolution strategy available for this conflict"]
                )

            # Execute the resolution strategy
            with transaction.atomic():
                result = self._execute_resolution(conflict, resolution, user)

                # Log the resolution
                self._log_resolution(conflict, resolution, result, user)

                return result

        except Exception as e:
            logger.error(f"Error resolving conflict {conflict.conflict_id}: {e}")
            return ResolutionResult(
                success=False,
                warnings=[f"Failed to resolve conflict: {str(e)}"]
            )

    def auto_resolve_conflicts(self, conflicts: List[ConflictAnalysis],
                             user: User = None) -> Dict[str, Any]:
        """
        Automatically resolve all auto-resolvable conflicts.

        Args:
            conflicts: List of conflicts to process
            user: User performing the resolution (system if None)

        Returns:
            Summary of resolution results
        """
        auto_resolvable = [c for c in conflicts if c.auto_resolvable]
        results = {
            'total_conflicts': len(conflicts),
            'auto_resolvable': len(auto_resolvable),
            'resolved': 0,
            'failed': 0,
            'resolution_details': []
        }

        for conflict in auto_resolvable:
            try:
                result = self.resolve_conflict(conflict, user=user)
                if result.success:
                    results['resolved'] += 1
                else:
                    results['failed'] += 1
                results['resolution_details'].append({
                    'conflict_id': conflict.conflict_id,
                    'success': result.success,
                    'strategy': result.resolution_applied.strategy.value if result.resolution_applied else None
                })
            except Exception as e:
                results['failed'] += 1
                logger.error(f"Auto-resolution failed for {conflict.conflict_id}: {e}")

        logger.info(f"Auto-resolution completed: {results['resolved']} resolved, {results['failed']} failed")
        return results

    def _execute_resolution(self, conflict: ConflictAnalysis,
                          resolution: ResolutionOption, user: User) -> ResolutionResult:
        """Execute a specific resolution strategy."""
        strategy = resolution.strategy

        if strategy == ResolutionStrategy.AUTO_ADJUST_DATES:
            return self._execute_date_adjustment(conflict, resolution, user)
        elif strategy == ResolutionStrategy.AUTO_SPLIT_ASSIGNMENT:
            return self._execute_assignment_split(conflict, resolution, user)
        elif strategy == ResolutionStrategy.AUTO_SKIP:
            return self._execute_auto_skip(conflict, resolution, user)
        else:
            return ResolutionResult(
                success=False,
                warnings=[f"Resolution strategy {strategy.value} not implemented"]
            )

    def _execute_date_adjustment(self, conflict: ConflictAnalysis,
                               resolution: ResolutionOption, user: User) -> ResolutionResult:
        """Execute date adjustment resolution."""
        metadata = resolution.metadata
        action = metadata.get('action')
        assignment_id = metadata.get('assignment_id')

        try:
            assignment = ShiftAssignment.objects.get(id=assignment_id)

            if action == 'adjust_end_date':
                new_end_date = metadata.get('new_end_date')
                assignment.effective_to = new_end_date
                assignment.save()

                return ResolutionResult(
                    success=True,
                    resolution_applied=resolution,
                    conflicts_resolved=[conflict.conflict_id],
                    metadata={
                        'assignment_id': assignment_id,
                        'new_end_date': new_end_date,
                        'action': action
                    }
                )

            elif action == 'adjust_start_date':
                new_start_date = metadata.get('new_start_date')
                assignment.effective_from = new_start_date
                assignment.save()

                return ResolutionResult(
                    success=True,
                    resolution_applied=resolution,
                    conflicts_resolved=[conflict.conflict_id],
                    metadata={
                        'assignment_id': assignment_id,
                        'new_start_date': new_start_date,
                        'action': action
                    }
                )

        except ShiftAssignment.DoesNotExist:
            return ResolutionResult(
                success=False,
                warnings=[f"Assignment {assignment_id} not found"]
            )

    def _execute_assignment_split(self, conflict: ConflictAnalysis,
                                resolution: ResolutionOption, user: User) -> ResolutionResult:
        """Execute assignment split resolution."""
        # Implementation for splitting long assignments
        # This would create multiple smaller assignments
        return ResolutionResult(
            success=False,
            warnings=["Assignment split not yet implemented"]
        )

    def _execute_auto_skip(self, conflict: ConflictAnalysis,
                         resolution: ResolutionOption, user: User) -> ResolutionResult:
        """Execute auto-skip resolution."""
        # Mark conflict as skipped for manual review
        return ResolutionResult(
            success=True,
            resolution_applied=resolution,
            conflicts_resolved=[conflict.conflict_id],
            warnings=["Conflict marked for manual review"]
        )

    def _log_resolution(self, conflict: ConflictAnalysis, resolution: ResolutionOption,
                       result: ResolutionResult, user: User):
        """Log conflict resolution for audit purposes."""
        log_entry = {
            'timestamp': timezone.now(),
            'conflict_id': conflict.conflict_id,
            'conflict_type': conflict.conflict_type.value,
            'severity': conflict.severity.value,
            'resolution_strategy': resolution.strategy.value,
            'success': result.success,
            'user': user.username if user else 'system',
            'metadata': result.metadata
        }

        self.resolution_history.append(log_entry)

        # Also log to Django logger
        logger.info(f"Conflict {conflict.conflict_id} resolved using {resolution.strategy.value} "
                   f"by {user.username if user else 'system'}")

    def get_resolution_history(self, conflict_id: str = None, user: User = None,
                             start_date: date = None, end_date: date = None) -> List[Dict[str, Any]]:
        """
        Get resolution history with optional filtering.

        Args:
            conflict_id: Filter by specific conflict ID
            user: Filter by user who performed resolution
            start_date: Filter by start date
            end_date: Filter by end date

        Returns:
            List of resolution history entries
        """
        filtered_history = self.resolution_history

        if conflict_id:
            filtered_history = [h for h in filtered_history if h['conflict_id'] == conflict_id]

        if user:
            filtered_history = [h for h in filtered_history if h['user'] == user.username]

        if start_date:
            filtered_history = [h for h in filtered_history if h['timestamp'].date() >= start_date]

        if end_date:
            filtered_history = [h for h in filtered_history if h['timestamp'].date() <= end_date]

        return filtered_history

    def generate_conflict_report(self, conflicts: List[ConflictAnalysis]) -> Dict[str, Any]:
        """
        Generate comprehensive conflict report.

        Args:
            conflicts: List of conflicts to report on

        Returns:
            Dictionary with conflict report data
        """
        if not conflicts:
            return {
                'summary': {'total_conflicts': 0},
                'details': [],
                'recommendations': ['No conflicts detected']
            }

        # Categorize conflicts
        by_type = defaultdict(list)
        by_severity = defaultdict(list)
        auto_resolvable = []
        manual_review_required = []

        for conflict in conflicts:
            by_type[conflict.conflict_type.value].append(conflict)
            by_severity[conflict.severity.value].append(conflict)

            if conflict.auto_resolvable:
                auto_resolvable.append(conflict)
            else:
                manual_review_required.append(conflict)

        # Calculate impact metrics
        total_users_affected = len(set(
            user.id for conflict in conflicts
            for user in conflict.affected_users
        ))

        total_assignments_affected = len(set(
            assignment.id for conflict in conflicts
            for assignment in conflict.affected_assignments
        ))

        # Generate recommendations
        recommendations = []
        if auto_resolvable:
            recommendations.append(f"Consider auto-resolving {len(auto_resolvable)} conflicts")

        if by_severity.get('critical'):
            recommendations.append(f"Immediate attention required for {len(by_severity['critical'])} critical conflicts")

        if by_type.get('time_overlap'):
            recommendations.append("Review shift scheduling policies to prevent time overlaps")

        return {
            'summary': {
                'total_conflicts': len(conflicts),
                'by_type': {k: len(v) for k, v in by_type.items()},
                'by_severity': {k: len(v) for k, v in by_severity.items()},
                'auto_resolvable': len(auto_resolvable),
                'manual_review_required': len(manual_review_required),
                'users_affected': total_users_affected,
                'assignments_affected': total_assignments_affected
            },
            'details': [
                {
                    'conflict_id': c.conflict_id,
                    'type': c.conflict_type.value,
                    'severity': c.severity.value,
                    'affected_users': [u.username for u in c.affected_users],
                    'affected_shifts': [s.name for s in c.affected_shifts],
                    'business_impact': c.business_impact,
                    'auto_resolvable': c.auto_resolvable,
                    'recommended_action': c.recommended_action.description if c.recommended_action else None
                }
                for c in conflicts
            ],
            'recommendations': recommendations,
            'generated_at': timezone.now()
        }


class SmartConflictPreventionService:
    """
    Proactive conflict prevention service that suggests optimal assignments.
    """

    def __init__(self):
        """Initialize the prevention service."""
        self.conflict_detector = ConflictDetectionEngine()

    def suggest_optimal_assignment(self, user: User, shift: ShiftMaster,
                                 preferred_start_date: date,
                                 duration_days: int = None) -> Dict[str, Any]:
        """
        Suggest optimal assignment parameters to minimize conflicts.

        Args:
            user: User to assign shift to
            shift: Shift to assign
            preferred_start_date: Preferred start date
            duration_days: Preferred duration in days

        Returns:
            Dictionary with optimization suggestions
        """
        suggestions = {
            'original_request': {
                'user': user.username,
                'shift': shift.name,
                'preferred_start_date': preferred_start_date,
                'duration_days': duration_days
            },
            'optimized_options': [],
            'conflict_warnings': [],
            'recommendations': []
        }

        # Check original request for conflicts
        end_date = preferred_start_date + timedelta(days=duration_days) if duration_days else None
        original_conflicts = self.conflict_detector.detect_all_conflicts(
            preferred_start_date,
            end_date or preferred_start_date + timedelta(days=90),
            [user.id]
        )

        if original_conflicts:
            suggestions['conflict_warnings'] = [
                f"{c.conflict_type.value}: {c.business_impact}"
                for c in original_conflicts
            ]

        # Generate alternative options
        alternative_dates = self._generate_alternative_dates(
            user, shift, preferred_start_date, duration_days
        )

        for alt_date, score, reason in alternative_dates:
            alt_end_date = alt_date + timedelta(days=duration_days) if duration_days else None
            alt_conflicts = self.conflict_detector.detect_all_conflicts(
                alt_date,
                alt_end_date or alt_date + timedelta(days=90),
                [user.id]
            )

            suggestions['optimized_options'].append({
                'start_date': alt_date,
                'end_date': alt_end_date,
                'optimization_score': score,
                'reason': reason,
                'conflict_count': len(alt_conflicts),
                'conflicts': [c.conflict_type.value for c in alt_conflicts]
            })

        # Generate general recommendations
        suggestions['recommendations'] = self._generate_assignment_recommendations(
            user, shift, preferred_start_date
        )

        return suggestions

    def _generate_alternative_dates(self, user: User, shift: ShiftMaster,
                                  preferred_date: date, duration_days: int) -> List[Tuple[date, float, str]]:
        """Generate alternative start dates with optimization scores."""
        alternatives = []

        # Check dates within 2 weeks of preferred date
        for days_offset in range(-14, 15):
            if days_offset == 0:
                continue  # Skip original date

            alt_date = preferred_date + timedelta(days=days_offset)

            # Skip past dates
            if alt_date < timezone.now().date():
                continue

            score, reason = self._calculate_date_score(user, shift, alt_date, duration_days)
            alternatives.append((alt_date, score, reason))

        # Sort by score (higher is better)
        alternatives.sort(key=lambda x: x[1], reverse=True)
        return alternatives[:5]  # Return top 5 alternatives

    def _calculate_date_score(self, user: User, shift: ShiftMaster,
                            start_date: date, duration_days: int) -> Tuple[float, str]:
        """Calculate optimization score for a specific date."""
        score = 1.0
        reasons = []

        # Check if it's a Monday (better for starting new assignments)
        if start_date.weekday() == 0:
            score += 0.2
            reasons.append("Monday start")

        # Check for holidays
        if Holiday.is_holiday(start_date):
            score -= 0.5
            reasons.append("Holiday start")

        # Check user's recent assignment history
        recent_assignments = ShiftAssignment.objects.filter(
            user=user,
            effective_from__gte=start_date - timedelta(days=30),
            effective_from__lte=start_date
        ).count()

        if recent_assignments == 0:
            score += 0.3
            reasons.append("No recent changes")
        elif recent_assignments >= 3:
            score -= 0.3
            reasons.append("Many recent changes")

        # Check shift working days alignment
        if shift.is_working_day(start_date):
            score += 0.1
            reasons.append("Working day alignment")

        return score, "; ".join(reasons)

    def _generate_assignment_recommendations(self, user: User, shift: ShiftMaster,
                                          start_date: date) -> List[str]:
        """Generate general assignment recommendations."""
        recommendations = []

        # Check user's current shift
        current_shift = ShiftAssignment.get_user_current_shift(user, start_date)
        if current_shift and current_shift.id != shift.id:
            if current_shift.is_night_shift() != shift.is_night_shift():
                recommendations.append(
                    "Consider providing adjustment period when switching between day/night shifts"
                )

        # Check shift complexity
        if shift.crosses_midnight:
            recommendations.append(
                "Midnight-crossing shift requires special attention for attendance tracking"
            )

        # Check grace period adequacy
        if shift.grace_period.total_seconds() < 600:  # Less than 10 minutes
            recommendations.append(
                "Consider increasing grace period for better attendance flexibility"
            )

        return recommendations


# Utility functions for external use
def detect_conflicts_for_date_range(start_date: date, end_date: date,
                                  user_ids: List[int] = None) -> List[ConflictAnalysis]:
    """
    Convenience function to detect conflicts for a date range.

    Args:
        start_date: Start date for conflict detection
        end_date: End date for conflict detection
        user_ids: Optional list of user IDs to check

    Returns:
        List of conflict analyses
    """
    engine = ConflictDetectionEngine()
    return engine.detect_all_conflicts(start_date, end_date, user_ids)


def auto_resolve_all_conflicts(start_date: date, end_date: date,
                             user_ids: List[int] = None,
                             resolver_user: User = None) -> Dict[str, Any]:
    """
    Convenience function to detect and auto-resolve conflicts.

    Args:
        start_date: Start date for conflict detection
        end_date: End date for conflict detection
        user_ids: Optional list of user IDs to check
        resolver_user: User performing the resolution

    Returns:
        Resolution summary
    """
    conflicts = detect_conflicts_for_date_range(start_date, end_date, user_ids)

    if not conflicts:
        return {
            'total_conflicts': 0,
            'auto_resolvable': 0,
            'resolved': 0,
            'failed': 0,
            'message': 'No conflicts detected'
        }

    resolver = ConflictResolver()
    return resolver.auto_resolve_conflicts(conflicts, resolver_user)


def generate_optimization_suggestions(user: User, shift: ShiftMaster,
                                    preferred_start_date: date,
                                    duration_days: int = None) -> Dict[str, Any]:
    """
    Convenience function to get assignment optimization suggestions.

    Args:
        user: User to assign shift to
        shift: Shift to assign
        preferred_start_date: Preferred start date
        duration_days: Preferred duration in days

    Returns:
        Optimization suggestions
    """
    prevention_service = SmartConflictPreventionService()
    return prevention_service.suggest_optimal_assignment(
        user, shift, preferred_start_date, duration_days
    )
