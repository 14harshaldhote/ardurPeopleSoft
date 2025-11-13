"""
Comprehensive Validation Utilities for TrueAlign Shift Management

This module provides advanced validation capabilities for shift management
operations, including:

- Multi-layered shift validation
- Assignment conflict validation
- Business rule compliance checking
- Performance-optimized validation pipelines
- Custom validation rules and policies
- Integration with conflict detection system
- Detailed validation reporting

Author: TrueAlign Development Team
Version: 2.0.0
"""

import logging
from datetime import datetime, timedelta, time, date
from decimal import Decimal
from typing import List, Dict, Optional, Tuple, Set, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import re
from functools import wraps
import asyncio

from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.db.models import Q, Count
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from .services import ConflictType, ConflictDetail, TimeOverlapCalculator
from .app_settings import SHIFT_VALIDATION, CACHE_SETTINGS, PERFORMANCE_MONITORING

logger = logging.getLogger('trueAlign.shift.validators')


class ValidationLevel(Enum):
    """Validation strictness levels."""
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    COMPREHENSIVE = "comprehensive"


class ValidationContext(Enum):
    """Validation context types."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    BULK_OPERATION = "bulk_operation"
    IMPORT = "import"
    API = "api"


@dataclass
class ValidationRule:
    """Represents a single validation rule."""
    name: str
    description: str
    validator_func: Callable
    severity: str = "error"  # error, warning, info
    context: List[ValidationContext] = field(default_factory=list)
    enabled: bool = True
    priority: int = 100  # Lower numbers = higher priority
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of validation operation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)
    field_errors: Dict[str, List[str]] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, message: str, field: str = None):
        """Add an error to the validation result."""
        self.is_valid = False
        self.errors.append(message)
        if field:
            if field not in self.field_errors:
                self.field_errors[field] = []
            self.field_errors[field].append(message)

    def add_warning(self, message: str):
        """Add a warning to the validation result."""
        self.warnings.append(message)

    def add_info(self, message: str):
        """Add an info message to the validation result."""
        self.info.append(message)

    def add_suggestion(self, message: str):
        """Add a suggestion to the validation result."""
        self.suggestions.append(message)

    def merge(self, other: 'ValidationResult'):
        """Merge another validation result into this one."""
        if not other.is_valid:
            self.is_valid = False

        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        self.info.extend(other.info)
        self.suggestions.extend(other.suggestions)

        for field, field_errors in other.field_errors.items():
            if field not in self.field_errors:
                self.field_errors[field] = []
            self.field_errors[field].extend(field_errors)

        self.metadata.update(other.metadata)


class BaseValidator:
    """Base class for all validators."""

    def __init__(self, level: ValidationLevel = ValidationLevel.STANDARD,
                 context: ValidationContext = ValidationContext.CREATE):
        """
        Initialize the validator.

        Args:
            level: Validation strictness level
            context: Validation context
        """
        self.level = level
        self.context = context
        self.rules = []
        self.cache_timeout = CACHE_SETTINGS.get('default_timeout', 300)
        self._register_rules()

    def _register_rules(self):
        """Register validation rules. Override in subclasses."""
        pass

    def validate(self, data: Any) -> ValidationResult:
        """
        Validate the provided data.

        Args:
            data: Data to validate

        Returns:
            ValidationResult with validation outcome
        """
        result = ValidationResult(is_valid=True)

        # Filter rules by context and enabled status
        applicable_rules = [
            rule for rule in self.rules
            if rule.enabled and (not rule.context or self.context in rule.context)
        ]

        # Sort rules by priority
        applicable_rules.sort(key=lambda x: x.priority)

        # Execute validation rules
        for rule in applicable_rules:
            try:
                rule_result = rule.validator_func(data, self.level, self.context)
                if rule_result:
                    result.merge(rule_result)

                    # Stop on critical errors in strict mode
                    if (self.level == ValidationLevel.STRICT and
                        not result.is_valid and rule.severity == "error"):
                        break

            except Exception as e:
                logger.error(f"Error in validation rule {rule.name}: {e}")
                result.add_error(f"Validation rule {rule.name} failed: {str(e)}")

        return result

    def add_rule(self, rule: ValidationRule):
        """Add a custom validation rule."""
        self.rules.append(rule)

    def remove_rule(self, rule_name: str):
        """Remove a validation rule by name."""
        self.rules = [rule for rule in self.rules if rule.name != rule_name]

    def enable_rule(self, rule_name: str):
        """Enable a validation rule."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True

    def disable_rule(self, rule_name: str):
        """Disable a validation rule."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False


class ShiftValidator(BaseValidator):
    """Comprehensive validator for shift operations."""

    def _register_rules(self):
        """Register shift validation rules."""
        self.rules = [
            ValidationRule(
                name="required_fields",
                description="Validate required fields are present",
                validator_func=self._validate_required_fields,
                priority=10
            ),
            ValidationRule(
                name="name_validation",
                description="Validate shift name format and uniqueness",
                validator_func=self._validate_shift_name,
                priority=20
            ),
            ValidationRule(
                name="time_validation",
                description="Validate shift times are logical",
                validator_func=self._validate_shift_times,
                priority=30
            ),
            ValidationRule(
                name="duration_validation",
                description="Validate shift duration constraints",
                validator_func=self._validate_duration,
                priority=40
            ),
            ValidationRule(
                name="work_days_validation",
                description="Validate work days configuration",
                validator_func=self._validate_work_days,
                priority=50
            ),
            ValidationRule(
                name="business_rules",
                description="Validate business rule compliance",
                validator_func=self._validate_business_rules,
                priority=60
            ),
            ValidationRule(
                name="overlap_detection",
                description="Detect potential shift overlaps",
                validator_func=self._validate_shift_overlaps,
                priority=70,
                context=[ValidationContext.CREATE, ValidationContext.UPDATE]
            ),
            ValidationRule(
                name="performance_validation",
                description="Validate performance implications",
                validator_func=self._validate_performance_impact,
                priority=80,
                severity="warning"
            )
        ]

    def _validate_required_fields(self, data: Dict[str, Any],
                                level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate required fields are present."""
        result = ValidationResult(is_valid=True)
        required_fields = ['name', 'start_time', 'end_time']

        for field in required_fields:
            if field not in data or not data[field]:
                result.add_error(f"Field '{field}' is required", field)

        return result if result.errors else None

    def _validate_shift_name(self, data: Dict[str, Any],
                           level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate shift name format and uniqueness."""
        result = ValidationResult(is_valid=True)
        name = data.get('name', '').strip()

        if not name:
            return None

        # Length validation
        if len(name) > 50:
            result.add_error("Shift name cannot exceed 50 characters", "name")

        if len(name) < 2:
            result.add_error("Shift name must be at least 2 characters", "name")

        # Format validation
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', name):
            result.add_error("Shift name can only contain letters, numbers, spaces, hyphens, and underscores", "name")

        # Uniqueness validation
        existing_query = ShiftMaster.objects.filter(name__iexact=name)

        # Exclude current shift if updating
        if context == ValidationContext.UPDATE and 'id' in data:
            existing_query = existing_query.exclude(id=data['id'])

        if existing_query.exists():
            result.add_error(f"A shift with name '{name}' already exists", "name")

        # Reserved name validation
        reserved_names = ['default', 'system', 'admin', 'all', 'none']
        if name.lower() in reserved_names:
            result.add_error(f"'{name}' is a reserved name and cannot be used", "name")

        return result if result.errors else None

    def _validate_shift_times(self, data: Dict[str, Any],
                            level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate shift times are logical."""
        result = ValidationResult(is_valid=True)

        start_time = data.get('start_time')
        end_time = data.get('end_time')

        if not (start_time and end_time):
            return None

        # Convert string times to time objects if needed
        if isinstance(start_time, str):
            try:
                start_time = datetime.strptime(start_time, '%H:%M').time()
            except ValueError:
                result.add_error("Invalid start time format. Use HH:MM", "start_time")
                return result

        if isinstance(end_time, str):
            try:
                end_time = datetime.strptime(end_time, '%H:%M').time()
            except ValueError:
                result.add_error("Invalid end time format. Use HH:MM", "end_time")
                return result

        # Check for same start and end time
        if start_time == end_time:
            result.add_error("Start time and end time cannot be the same", "end_time")

        # Validate time ranges
        crosses_midnight = end_time < start_time

        if crosses_midnight:
            result.add_info("This shift crosses midnight")

            # In strict mode, warn about midnight crossing complexity
            if level == ValidationLevel.STRICT:
                result.add_warning("Midnight-crossing shifts require careful attendance tracking")

        # Check for unrealistic shift lengths
        if crosses_midnight:
            # Calculate duration for midnight crossing
            hours_before = 24 - start_time.hour - start_time.minute/60
            hours_after = end_time.hour + end_time.minute/60
            total_hours = hours_before + hours_after
        else:
            total_hours = (end_time.hour - start_time.hour) + (end_time.minute - start_time.minute)/60

        if total_hours > 16:
            result.add_warning(f"Shift duration of {total_hours:.1f} hours is very long")
        elif total_hours < 0.5:
            result.add_error("Shift duration must be at least 30 minutes")

        return result if (result.errors or result.warnings or result.info) else None

    def _validate_duration(self, data: Dict[str, Any],
                         level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate shift duration constraints."""
        result = ValidationResult(is_valid=True)

        shift_duration = data.get('shift_duration')
        break_duration = data.get('break_duration')
        grace_period = data.get('grace_period')

        # Validate shift duration
        if shift_duration is not None:
            try:
                duration = Decimal(str(shift_duration))

                min_duration = Decimal(str(SHIFT_VALIDATION.get('min_duration', 0.5)))
                max_duration = Decimal(str(SHIFT_VALIDATION.get('max_duration', 24.0)))

                if duration < min_duration:
                    result.add_error(f"Shift duration must be at least {min_duration} hours", "shift_duration")
                elif duration > max_duration:
                    result.add_error(f"Shift duration cannot exceed {max_duration} hours", "shift_duration")

            except (ValueError, TypeError):
                result.add_error("Invalid shift duration format", "shift_duration")

        # Validate break duration
        if break_duration is not None:
            if isinstance(break_duration, timedelta):
                break_hours = break_duration.total_seconds() / 3600
            elif isinstance(break_duration, (int, float)):
                break_hours = float(break_duration) / 60  # Assuming minutes
            else:
                result.add_error("Invalid break duration format", "break_duration")
                break_hours = 0

            max_break_hours = SHIFT_VALIDATION.get('max_break_duration', 8)
            if break_hours > max_break_hours:
                result.add_error(f"Break duration cannot exceed {max_break_hours} hours", "break_duration")

            # Check break duration vs shift duration
            if shift_duration and break_hours >= float(shift_duration):
                result.add_error("Break duration must be less than shift duration", "break_duration")

        # Validate grace period
        if grace_period is not None:
            if isinstance(grace_period, timedelta):
                grace_minutes = grace_period.total_seconds() / 60
            elif isinstance(grace_period, (int, float)):
                grace_minutes = float(grace_period)
            else:
                result.add_error("Invalid grace period format", "grace_period")
                grace_minutes = 0

            max_grace_minutes = SHIFT_VALIDATION.get('max_grace_period', 120) * 60
            if grace_minutes > max_grace_minutes:
                result.add_error(f"Grace period cannot exceed {max_grace_minutes} minutes", "grace_period")

        return result if result.errors else None

    def _validate_work_days(self, data: Dict[str, Any],
                          level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate work days configuration."""
        result = ValidationResult(is_valid=True)

        work_days = data.get('work_days', 'Weekdays')
        custom_work_days = data.get('custom_work_days', '')

        valid_work_day_choices = ['Weekdays', 'All Days', 'Custom']

        if work_days not in valid_work_day_choices:
            result.add_error(f"Work days must be one of: {', '.join(valid_work_day_choices)}", "work_days")

        # Validate custom work days if specified
        if work_days == 'Custom':
            if not custom_work_days:
                result.add_error("Custom work days must be specified when 'Custom' is selected", "custom_work_days")
            else:
                valid_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                day_names = [day.strip() for day in custom_work_days.split(',') if day.strip()]

                if not day_names:
                    result.add_error("At least one work day must be specified", "custom_work_days")

                invalid_days = [day for day in day_names if day not in valid_days]
                if invalid_days:
                    result.add_error(f"Invalid day names: {', '.join(invalid_days)}", "custom_work_days")

                if len(day_names) != len(set(day_names)):
                    result.add_error("Duplicate day names found", "custom_work_days")

        elif custom_work_days and work_days != 'Custom':
            result.add_warning("Custom work days specified but work days is not set to 'Custom'")

        return result if (result.errors or result.warnings) else None

    def _validate_business_rules(self, data: Dict[str, Any],
                               level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate business rule compliance."""
        result = ValidationResult(is_valid=True)

        # Check if creating too many shifts
        if context == ValidationContext.CREATE:
            total_shifts = ShiftMaster.objects.count()
            if total_shifts >= 50:  # Example limit
                result.add_warning("High number of shifts may impact performance")

        # Check for potential issues with shift design
        start_time = data.get('start_time')
        end_time = data.get('end_time')

        if start_time and end_time:
            # Convert to time objects if needed
            if isinstance(start_time, str):
                start_time = datetime.strptime(start_time, '%H:%M').time()
            if isinstance(end_time, str):
                end_time = datetime.strptime(end_time, '%H:%M').time()

            # Check for common shift timing patterns
            if start_time.hour == 9 and end_time.hour == 17:
                result.add_info("Standard business hours detected")
            elif start_time.hour >= 22 or end_time.hour <= 6:
                result.add_info("Night shift detected - consider additional policies")

        return result if (result.warnings or result.info) else None

    def _validate_shift_overlaps(self, data: Dict[str, Any],
                               level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Detect potential shift overlaps with existing shifts."""
        result = ValidationResult(is_valid=True)

        start_time = data.get('start_time')
        end_time = data.get('end_time')
        work_days = data.get('work_days', 'Weekdays')

        if not (start_time and end_time):
            return None

        # Convert to time objects if needed
        if isinstance(start_time, str):
            start_time = datetime.strptime(start_time, '%H:%M').time()
        if isinstance(end_time, str):
            end_time = datetime.strptime(end_time, '%H:%M').time()

        # Get existing shifts with similar work patterns
        existing_shifts = ShiftMaster.objects.filter(is_active=True)

        # Exclude current shift if updating
        if context == ValidationContext.UPDATE and 'id' in data:
            existing_shifts = existing_shifts.exclude(id=data['id'])

        overlapping_shifts = []

        for shift in existing_shifts:
            # Check if work days overlap
            if self._work_days_overlap(work_days, shift.work_days, data.get('custom_work_days'), shift.custom_work_days):
                # Check if times overlap
                if self._times_overlap(start_time, end_time, shift.start_time, shift.end_time):
                    overlapping_shifts.append(shift)

        if overlapping_shifts:
            if level in [ValidationLevel.STRICT, ValidationLevel.COMPREHENSIVE]:
                overlap_names = [shift.name for shift in overlapping_shifts]
                result.add_error(f"Shift times overlap with existing shifts: {', '.join(overlap_names)}")
            else:
                result.add_warning(f"Shift times overlap with {len(overlapping_shifts)} existing shifts")
                result.add_suggestion("Consider adjusting shift times to avoid conflicts during assignment")

        return result if (result.errors or result.warnings) else None

    def _validate_performance_impact(self, data: Dict[str, Any],
                                   level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate performance implications of the shift."""
        result = ValidationResult(is_valid=True)

        # Check if this might be a frequently used shift
        name = data.get('name', '').lower()
        high_usage_indicators = ['default', 'standard', 'regular', 'main', 'primary']

        if any(indicator in name for indicator in high_usage_indicators):
            result.add_info("This appears to be a frequently used shift - ensure optimal configuration")

        # Check complexity factors
        complexity_score = 0

        if data.get('work_days') == 'Custom':
            complexity_score += 1

        start_time = data.get('start_time')
        end_time = data.get('end_time')
        if start_time and end_time:
            if isinstance(start_time, str):
                start_time = datetime.strptime(start_time, '%H:%M').time()
            if isinstance(end_time, str):
                end_time = datetime.strptime(end_time, '%H:%M').time()

            if end_time < start_time:  # Crosses midnight
                complexity_score += 1

        if complexity_score >= 2:
            result.add_warning("High complexity shift may impact performance during assignment operations")

        return result if (result.warnings or result.info) else None

    def _work_days_overlap(self, work_days1: str, work_days2: str,
                          custom1: str, custom2: str) -> bool:
        """Check if two work day configurations overlap."""
        days1 = self._get_work_days_list(work_days1, custom1)
        days2 = self._get_work_days_list(work_days2, custom2)
        return bool(set(days1) & set(days2))

    def _get_work_days_list(self, work_days: str, custom_work_days: str) -> List[int]:
        """Get list of work day indices (0=Monday, 6=Sunday)."""
        if work_days == 'Weekdays':
            return [0, 1, 2, 3, 4]
        elif work_days == 'All Days':
            return [0, 1, 2, 3, 4, 5]
        elif work_days == 'Custom' and custom_work_days:
            day_map = {
                'Monday': 0, 'Tuesday': 1, 'Wednesday': 2, 'Thursday': 3,
                'Friday': 4, 'Saturday': 5, 'Sunday': 6
            }
            day_names = [day.strip() for day in custom_work_days.split(',')]
            return [day_map.get(day, -1) for day in day_names if day in day_map]
        return []

    def _times_overlap(self, start1: time, end1: time, start2: time, end2: time) -> bool:
        """Check if two time ranges overlap."""
        # Convert to minutes from midnight for easier comparison
        def time_to_minutes(t):
            return t.hour * 60 + t.minute

        # Handle midnight crossing
        start1_min = time_to_minutes(start1)
        end1_min = time_to_minutes(end1)
        if end1_min <= start1_min:  # Crosses midnight
            end1_min += 24 * 60

        start2_min = time_to_minutes(start2)
        end2_min = time_to_minutes(end2)
        if end2_min <= start2_min:  # Crosses midnight
            end2_min += 24 * 60

        # Check for overlap
        return start1_min < end2_min and start2_min < end1_min


class AssignmentValidator(BaseValidator):
    """Comprehensive validator for shift assignments."""

    def _register_rules(self):
        """Register assignment validation rules."""
        self.rules = [
            ValidationRule(
                name="required_fields",
                description="Validate required fields are present",
                validator_func=self._validate_required_fields,
                priority=10
            ),
            ValidationRule(
                name="user_validation",
                description="Validate user exists and is active",
                validator_func=self._validate_user,
                priority=20
            ),
            ValidationRule(
                name="shift_validation",
                description="Validate shift exists and is active",
                validator_func=self._validate_shift,
                priority=30
            ),
            ValidationRule(
                name="date_validation",
                description="Validate assignment dates are logical",
                validator_func=self._validate_dates,
                priority=40
            ),
            ValidationRule(
                name="conflict_detection",
                description="Detect assignment conflicts",
                validator_func=self._validate_conflicts,
                priority=50
            ),
            ValidationRule(
                name="business_rules",
                description="Validate business rule compliance",
                validator_func=self._validate_assignment_business_rules,
                priority=60
            ),
            ValidationRule(
                name="capacity_validation",
                description="Validate capacity constraints",
                validator_func=self._validate_capacity,
                priority=70,
                severity="warning"
            ),
            ValidationRule(
                name="optimization_suggestions",
                description="Provide optimization suggestions",
                validator_func=self._validate_optimization,
                priority=80,
                severity="info"
            )
        ]

    def _validate_required_fields(self, data: Dict[str, Any],
                                level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate required fields are present."""
        result = ValidationResult(is_valid=True)

        required_fields = ['user_id', 'shift_id', 'effective_from']

        for field in required_fields:
            if field not in data or data[field] is None:
                result.add_error(f"Field '{field}' is required", field)

        return result if result.errors else None

    def _validate_user(self, data: Dict[str, Any],
                      level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate user exists and is active."""
        result = ValidationResult(is_valid=True)

        user_id = data.get('user_id')
        if not user_id:
            return None

        try:
            user = User.objects.get(id=user_id)
            if not user.is_active:
                result.add_error(f"User {user.username} is not active", "user_id")
        except User.DoesNotExist:
            result.add_error(f"User with ID {user_id} does not exist", "user_id")

        return result if result.errors else None

    def _validate_shift(self, data: Dict[str, Any],
                       level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate shift exists and is active."""
        result = ValidationResult(is_valid=True)

        shift_id = data.get('shift_id')
        if not shift_id:
            return None

        try:
            shift = ShiftMaster.objects.get(id=shift_id)
            if not shift.is_active:
                result.add_error(f"Shift '{shift.name}' is not active", "shift_id")
        except ShiftMaster.DoesNotExist:
            result.add_error(f"Shift with ID {shift_id} does not exist", "shift_id")

        return result if result.errors else None

    def _validate_dates(self, data: Dict[str, Any],
                       level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate assignment dates are logical."""
        result = ValidationResult(is_valid=True)

        effective_from = data.get('effective_from')
        effective_to = data.get('effective_to')

        if not effective_from:
            return None

        # Convert string dates if needed
        if isinstance(effective_from, str):
            try:
                effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()
            except ValueError:
                result.add_error("Invalid effective_from date format. Use YYYY-MM-DD", "effective_from")
                return result

        if effective_to and isinstance(effective_to, str):
            try:
                effective_to = datetime.strptime(effective_to, '%Y-%m-%d').date()
            except ValueError:
                result.add_error("Invalid effective_to date format. Use YYYY-MM-DD", "effective_to")
                return result

        # Validate date logic
        today = timezone.now().date()

        # Check if assignment is too far in the past
        if effective_from < today - timedelta(days=7):
            if level == ValidationLevel.STRICT:
                result.add_error("Assignment cannot be more than 7 days in the past", "effective_from")
            else:
                result.add_warning("Assignment is in the past")

        # Check end date logic
        if effective_to:
            if effective_to <= effective_from:
                result.add_error("End date must be after start date", "effective_to")

            # Check for excessively long assignments
            duration = (effective_to - effective_from).days
            max_duration = SHIFT_VALIDATION.get('max_assignment_days', 365)

            if duration > max_duration:
                result.add_error(f"Assignment duration cannot exceed {max_duration} days", "effective_to")
            elif duration > 180:  # 6 months
                result.add_warning("Long-term assignment may need periodic review")

        return result if (result.errors or result.warnings) else None

    def _validate_conflicts(self, data: Dict[str, Any],
                          level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Detect assignment conflicts."""
        result = ValidationResult(is_valid=True)

        user_id = data.get('user_id')
        shift_id = data.get('shift_id')
        effective_from = data.get('effective_from')
        effective_to = data.get('effective_to')

        if not (user_id and shift_id and effective_from):
            return None

        # Convert string dates if needed
        if isinstance(effective_from, str):
            try:
                effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()
            except ValueError:
                return None

        if effective_to and isinstance(effective_to, str):
            try:
                effective_to = datetime.strptime(effective_to, '%Y-%m-%d').date()
            except ValueError:
                return None

        # Find overlapping assignments
        overlapping_query = ShiftAssignment.objects.filter(
            user_id=user_id,
            effective_from__lte=effective_to or date(2099, 12, 31)
        ).filter(
            Q(effective_to__gte=effective_from) | Q(effective_to__isnull=True)
        )

        # Exclude current assignment if updating
        if context == ValidationContext.UPDATE and 'id' in data:
            overlapping_query = overlapping_query.exclude(id=data['id'])

        overlapping_assignments = list(overlapping_query.select_related('shift'))

        if overlapping_assignments:
            # Check for time-based conflicts
            try:
                current_shift = ShiftMaster.objects.get(id=shift_id)

                for assignment in overlapping_assignments:
                    existing_shift = assignment.shift

                    # Check if shifts have overlapping times on working days
                    overlap_detected = self._check_time_overlap_on_dates(
                        current_shift, existing_shift, effective_from, effective_to, assignment
                    )

                    if overlap_detected:
                        if level == ValidationLevel.STRICT:
                            result.add_error(
                                f"Time conflict with existing assignment '{existing_shift.name}' "
                                f"from {assignment.effective_from} to {assignment.effective_to or 'ongoing'}"
                            )
                        else:
                            result.add_warning(
                                f"Potential time conflict with '{existing_shift.name}' assignment"
                            )
                            result.add_suggestion("Review assignment dates and times to avoid conflicts")

            except ShiftMaster.DoesNotExist:
                pass

        return result if (result.errors or result.warnings) else None

    def _check_time_overlap_on_dates(self, shift1: ShiftMaster, shift2: ShiftMaster,
                                   start_date: date, end_date: Optional[date],
                                   existing_assignment: ShiftAssignment) -> bool:
        """Check if two shifts have time overlaps on their working dates."""
        # Determine the overlap period
        assignment_start = max(start_date, existing_assignment.effective_from)
        assignment_end = min(
            end_date or date(2099, 12, 31),
            existing_assignment.effective_to or date(2099, 12, 31)
        )

        # Check each day in the overlap period
        current_date = assignment_start
        while current_date <= assignment_end and current_date <= assignment_start + timedelta(days=30):
            # Both shifts must be working days
            if (shift1.is_working_day(current_date) and
                shift2.is_working_day(current_date) and
                not Holiday.is_holiday(current_date)):

                # Check if times overlap using TimeOverlapCalculator
                overlaps, _, _ = TimeOverlapCalculator.times_overlap(
                    shift1.start_time, shift1.end_time,
                    shift2.start_time, shift2.end_time,
                    current_date
                )

                if overlaps:
                    return True

            current_date += timedelta(days=1)

        return False

    def _validate_assignment_business_rules(self, data: Dict[str, Any],
                                          level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate business rule compliance for assignments."""
        result = ValidationResult(is_valid=True)

        user_id = data.get('user_id')
        effective_from = data.get('effective_from')

        if not (user_id and effective_from):
            return None

        # Convert string date if needed
        if isinstance(effective_from, str):
            try:
                effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()
            except ValueError:
                return None

        # Check for excessive assignment changes
        thirty_days_ago = effective_from - timedelta(days=30)
        recent_assignments = ShiftAssignment.objects.filter(
            user_id=user_id,
            created_at__date__gte=thirty_days_ago
        ).count()

        if recent_assignments >= 5:
            result.add_warning(
                f"User has {recent_assignments} assignment changes in the last 30 days"
            )
            result.add_suggestion("Consider assignment stability for user adjustment")

        # Check for weekend/holiday start dates
        if effective_from.weekday() >= 5:  # Saturday or Sunday
            result.add_info(f"Assignment starts on {effective_from.strftime('%A')}")

        # Check for immediate start (today or tomorrow)
        today = timezone.now().date()
        if effective_from <= today + timedelta(days=1):
            result.add_info("Assignment starts very soon - ensure user notification")

        return result if (result.warnings or result.info) else None

    def _validate_capacity(self, data: Dict[str, Any],
                         level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Validate capacity constraints."""
        result = ValidationResult(is_valid=True)

        shift_id = data.get('shift_id')
        effective_from = data.get('effective_from')

        if not (shift_id and effective_from):
            return None

        # Convert string date if needed
        if isinstance(effective_from, str):
            try:
                effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()
            except ValueError:
                return None

        # Check current assignments for this shift
        current_assignments = ShiftAssignment.objects.filter(
            shift_id=shift_id,
            effective_from__lte=effective_from,
            is_current=True
        ).filter(
            Q(effective_to__gte=effective_from) | Q(effective_to__isnull=True)
        ).count()

        # Example capacity limits (would be configurable in real implementation)
        if current_assignments > 20:
            result.add_warning(f"High assignment count ({current_assignments}) for this shift")
        elif current_assignments > 50:
            result.add_error("Maximum capacity exceeded for this shift")

        return result if (result.errors or result.warnings) else None

    def _validate_optimization(self, data: Dict[str, Any],
                             level: ValidationLevel, context: ValidationContext) -> Optional[ValidationResult]:
        """Provide optimization suggestions."""
        result = ValidationResult(is_valid=True)

        user_id = data.get('user_id')
        shift_id = data.get('shift_id')
        effective_from = data.get('effective_from')

        if not (user_id and shift_id and effective_from):
            return None

        # Convert string date if needed
        if isinstance(effective_from, str):
            try:
                effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()
            except ValueError:
                return None

        try:
            # Get user's current shift for comparison
            user = User.objects.get(id=user_id)
            current_shift = ShiftAssignment.get_user_current_shift(user, effective_from)
            new_shift = ShiftMaster.objects.get(id=shift_id)

            if current_shift and current_shift.id != new_shift.id:
                # Suggest optimal transition timing
                if current_shift.is_night_shift() != new_shift.is_night_shift():
                    result.add_suggestion(
                        "Consider providing adjustment period when switching between day/night shifts"
                    )

                # Check for start date optimization
                if effective_from.weekday() == 0:  # Monday
                    result.add_info("Good choice: Monday start allows full week adjustment")
                elif effective_from.weekday() >= 5:  # Weekend
                    result.add_suggestion("Consider starting on Monday for better adjustment")

            # Check shift characteristics
            if new_shift.crosses_midnight:
                result.add_info("Midnight-crossing shift requires careful attendance tracking")

            if new_shift.grace_period.total_seconds() < 600:  # Less than 10 minutes
                result.add_suggestion("Consider increasing grace period for better flexibility")

        except (User.DoesNotExist, ShiftMaster.DoesNotExist):
            pass

        return result if (result.suggestions or result.info) else None


# Factory functions for easy validator creation
def create_shift_validator(level: ValidationLevel = ValidationLevel.STANDARD,
                         context: ValidationContext = ValidationContext.CREATE) -> ShiftValidator:
    """Create a shift validator with specified level and context."""
    return ShiftValidator(level, context)


def create_assignment_validator(level: ValidationLevel = ValidationLevel.STANDARD,
                              context: ValidationContext = ValidationContext.CREATE) -> AssignmentValidator:
    """Create an assignment validator with specified level and context."""
    return AssignmentValidator(level, context)


# Convenience functions for common validation scenarios
def validate_shift_data(data: Dict[str, Any],
                       level: ValidationLevel = ValidationLevel.STANDARD,
                       context: ValidationContext = ValidationContext.CREATE) -> ValidationResult:
    """
    Validate shift data with specified parameters.

    Args:
        data: Shift data to validate
        level: Validation strictness level
        context: Validation context

    Returns:
        ValidationResult with validation outcome
    """
    validator = create_shift_validator(level, context)
    return validator.validate(data)


def validate_assignment_data(data: Dict[str, Any],
                           level: ValidationLevel = ValidationLevel.STANDARD,
                           context: ValidationContext = ValidationContext.CREATE) -> ValidationResult:
    """
    Validate assignment data with specified parameters.

    Args:
        data: Assignment data to validate
        level: Validation strictness level
        context: Validation context

    Returns:
        ValidationResult with validation outcome
    """
    validator = create_assignment_validator(level, context)
    return validator.validate(data)


def validate_bulk_assignment_data(assignments_data: List[Dict[str, Any]],
                                level: ValidationLevel = ValidationLevel.STANDARD) -> Dict[str, Any]:
    """
    Validate multiple assignment data entries.

    Args:
        assignments_data: List of assignment data dictionaries
        level: Validation strictness level

    Returns:
        Dictionary with validation summary and individual results
    """
    validator = create_assignment_validator(level, ValidationContext.BULK_OPERATION)

    results = {
        'total_assignments': len(assignments_data),
        'valid_assignments': 0,
        'invalid_assignments': 0,
        'warnings_count': 0,
        'individual_results': [],
        'summary_errors': [],
        'summary_warnings': []
    }

    for i, assignment_data in enumerate(assignments_data):
        result = validator.validate(assignment_data)

        result_summary = {
            'index': i,
            'is_valid': result.is_valid,
            'errors': result.errors,
            'warnings': result.warnings,
            'field_errors': result.field_errors
        }

        results['individual_results'].append(result_summary)

        if result.is_valid:
            results['valid_assignments'] += 1
        else:
            results['invalid_assignments'] += 1

        results['warnings_count'] += len(result.warnings)

    # Generate summary insights
    if results['invalid_assignments'] > 0:
        results['summary_errors'].append(
            f"{results['invalid_assignments']} of {results['total_assignments']} assignments have validation errors"
        )

    if results['warnings_count'] > 0:
        results['summary_warnings'].append(
            f"Total of {results['warnings_count']} warnings across all assignments"
        )

    return results


# Performance validation utilities
def validate_with_performance_monitoring(validator: BaseValidator, data: Any) -> Tuple[ValidationResult, Dict[str, float]]:
    """
    Validate data with performance monitoring.

    Args:
        validator: Validator instance to use
        data: Data to validate

    Returns:
        Tuple of (ValidationResult, performance_metrics)
    """
    start_time = timezone.now()

    result = validator.validate(data)

    end_time = timezone.now()
    duration_ms = (end_time - start_time).total_seconds() * 1000

    performance_metrics = {
        'validation_duration_ms': duration_ms,
        'rules_executed': len([r for r in validator.rules if r.enabled]),
        'errors_found': len(result.errors),
        'warnings_found': len(result.warnings)
    }

    if PERFORMANCE_MONITORING.get('enabled', True) and duration_ms > 100:
        logger.warning(f"Slow validation detected: {duration_ms:.2f}ms")

    return result, performance_metrics


# Caching utilities for validation
def get_cached_validation_result(cache_key: str) -> Optional[ValidationResult]:
    """Get cached validation result."""
    return cache.get(cache_key)


def cache_validation_result(cache_key: str, result: ValidationResult, timeout: int = None) -> None:
    """Cache validation result."""
    if timeout is None:
        timeout = CACHE_SETTINGS.get('default_timeout', 300)
    cache.set(cache_key, result, timeout)
