"""
Simplified Shift Management Services

This module provides essential shift management functionality:
- Basic conflict detection
- Shift assignment operations
- Simple validation
- Core business logic

Optimized for maintainability and performance.
"""

import logging
from datetime import datetime, timedelta, time, date
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum

from django.db import transaction
from django.db.models import Q, Count
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday

logger = logging.getLogger('trueAlign.shift.services')


class ConflictType(Enum):
    """Types of shift assignment conflicts."""
    TIME_OVERLAP = "time_overlap"
    HOLIDAY_CONFLICT = "holiday_conflict"
    USER_CONFLICT = "user_conflict"


@dataclass
class ConflictDetail:
    """Information about a shift assignment conflict."""
    conflict_type: ConflictType
    message: str
    conflicting_assignment: Optional['ShiftAssignment'] = None


@dataclass
class AssignmentResult:
    """Result of a shift assignment operation."""
    success: bool
    assignment: Optional['ShiftAssignment'] = None
    conflicts: List[ConflictDetail] = None
    errors: List[str] = None

    def __post_init__(self):
        if self.conflicts is None:
            self.conflicts = []
        if self.errors is None:
            self.errors = []


class ConflictDetector:
    """Simple conflict detection for shift assignments."""

    def check_assignment_conflicts(self, user: User, shift: ShiftMaster, 
                                 effective_from: date, effective_to: date = None) -> List[ConflictDetail]:
        """Check for conflicts in shift assignment."""
        conflicts = []
        
        try:
            # Check for user conflicts (overlapping assignments)
            user_conflicts = self._check_user_conflicts(user, effective_from, effective_to)
            conflicts.extend(user_conflicts)
            
            # Check for holiday conflicts
            holiday_conflicts = self._check_holiday_conflicts(effective_from, effective_to)
            conflicts.extend(holiday_conflicts)
            
        except Exception as e:
            logger.error(f"Error checking conflicts: {e}")
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.USER_CONFLICT,
                message=f"Error checking conflicts: {str(e)}"
            ))
        
        return conflicts

    def _check_user_conflicts(self, user: User, effective_from: date, 
                            effective_to: date = None) -> List[ConflictDetail]:
        """Check for user assignment conflicts."""
        conflicts = []
        
        # Get existing assignments for the user
        existing_assignments = ShiftAssignment.objects.filter(
            user=user,
            is_current=True
        )
        
        # Filter by date range
        if effective_to:
            existing_assignments = existing_assignments.filter(
                effective_from__lte=effective_to,
                effective_to__gte=effective_from
            )
        else:
            existing_assignments = existing_assignments.filter(
                effective_from__lte=effective_from
            )
        
        for assignment in existing_assignments:
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.USER_CONFLICT,
                message=f"User already assigned to {assignment.shift.name} during this period",
                conflicting_assignment=assignment
            ))
        
        return conflicts

    def _check_holiday_conflicts(self, effective_from: date, 
                               effective_to: date = None) -> List[ConflictDetail]:
        """Check for holiday conflicts."""
        conflicts = []
        
        # Check if assignment dates conflict with holidays
        if effective_to:
            holidays = Holiday.objects.filter(
                date__gte=effective_from,
                date__lte=effective_to
            )
        else:
            holidays = Holiday.objects.filter(date=effective_from)
        
        for holiday in holidays:
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.HOLIDAY_CONFLICT,
                message=f"Assignment conflicts with holiday: {holiday.name} on {holiday.date}"
            ))
        
        return conflicts


class ShiftService:
    """Essential shift management service."""

    def __init__(self):
        self.conflict_detector = ConflictDetector()

    def assign_shift_to_user(self, user_id: int, shift_id: int, 
                           effective_from: date, effective_to: date = None,
                           assigned_by: User = None) -> AssignmentResult:
        """Assign a shift to a user with conflict checking."""
        try:
            # Get user and shift
            user = User.objects.get(id=user_id)
            shift = ShiftMaster.objects.get(id=shift_id)
            
            # Validate dates
            if effective_from < date.today():
                return AssignmentResult(
                    success=False,
                    errors=["Effective from date cannot be in the past"]
                )
            
            if effective_to and effective_to < effective_from:
                return AssignmentResult(
                    success=False,
                    errors=["Effective to date cannot be before effective from date"]
                )
            
            # Check for conflicts
            conflicts = self.conflict_detector.check_assignment_conflicts(
                user, shift, effective_from, effective_to
            )
            
            if conflicts:
                return AssignmentResult(
                    success=False,
                    conflicts=conflicts
                )
            
            # Create assignment
            with transaction.atomic():
                assignment = ShiftAssignment.objects.create(
                    user=user,
                    shift=shift,
                    effective_from=effective_from,
                    effective_to=effective_to,
                    is_current=True,
                    assigned_by=assigned_by
                )
            
            logger.info(f"Successfully assigned {user.username} to {shift.name}")
            
            return AssignmentResult(
                success=True,
                assignment=assignment
            )
            
        except User.DoesNotExist:
            return AssignmentResult(
                success=False,
                errors=["User not found"]
            )
        except ShiftMaster.DoesNotExist:
            return AssignmentResult(
                success=False,
                errors=["Shift not found"]
            )
        except Exception as e:
            logger.error(f"Error assigning shift: {e}")
            return AssignmentResult(
                success=False,
                errors=[f"Assignment failed: {str(e)}"]
            )

    def end_assignment(self, assignment_id: int, end_date: date = None) -> AssignmentResult:
        """End a shift assignment."""
        try:
            assignment = ShiftAssignment.objects.get(id=assignment_id)
            
            if end_date is None:
                end_date = date.today()
            
            assignment.effective_to = end_date
            assignment.is_current = False
            assignment.save()
            
            logger.info(f"Successfully ended assignment {assignment_id}")
            
            return AssignmentResult(
                success=True,
                assignment=assignment
            )
            
        except ShiftAssignment.DoesNotExist:
            return AssignmentResult(
                success=False,
                errors=["Assignment not found"]
            )
        except Exception as e:
            logger.error(f"Error ending assignment: {e}")
            return AssignmentResult(
                success=False,
                errors=[f"Failed to end assignment: {str(e)}"]
            )

    def get_shift_statistics(self) -> Dict[str, Any]:
        """Get basic shift statistics."""
        try:
            stats = {
                'total_shifts': ShiftMaster.objects.filter(is_active=True).count(),
                'total_assignments': ShiftAssignment.objects.filter(is_current=True).count(),
                'total_users': User.objects.filter(is_active=True).count(),
                'users_with_shifts': ShiftAssignment.objects.filter(
                    is_current=True
                ).values('user').distinct().count(),
                'upcoming_holidays': Holiday.objects.filter(
                    date__gte=date.today(),
                    date__lte=date.today() + timedelta(days=30)
                ).count()
            }
            
            # Calculate utilization rate
            if stats['total_users'] > 0:
                stats['utilization_rate'] = round(
                    (stats['users_with_shifts'] / stats['total_users']) * 100, 1
                )
            else:
                stats['utilization_rate'] = 0
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def validate_shift_data(self, data: Dict[str, Any]) -> List[str]:
        """Basic shift data validation."""
        errors = []
        
        # Required fields
        if not data.get('name'):
            errors.append("Shift name is required")
        
        if not data.get('start_time'):
            errors.append("Start time is required")
        
        if not data.get('end_time'):
            errors.append("End time is required")
        
        # Check for duplicate shift names
        if data.get('name'):
            existing_shift = ShiftMaster.objects.filter(
                name=data['name'],
                is_active=True
            ).first()
            
            if existing_shift and str(existing_shift.id) != str(data.get('id', '')):
                errors.append(f"Shift name '{data['name']}' already exists")
        
        return errors


# Convenience functions
def create_shift_service() -> ShiftService:
    """Create a shift service instance."""
    return ShiftService()


def get_user_current_assignment(user: User) -> Optional[ShiftAssignment]:
    """Get user's current shift assignment."""
    return ShiftAssignment.objects.filter(
        user=user,
        is_current=True
    ).select_related('shift').first()


def get_shift_assignments(shift: ShiftMaster, active_only: bool = True) -> List[ShiftAssignment]:
    """Get assignments for a shift."""
    queryset = ShiftAssignment.objects.filter(shift=shift).select_related('user')
    
    if active_only:
        queryset = queryset.filter(is_current=True)
    
    return list(queryset)
