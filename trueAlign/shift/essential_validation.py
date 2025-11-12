"""
Essential Validation Functions - Simplified
Extracted from validators.py and system_validator.py for merging into services.py
"""

from datetime import datetime, timedelta, time, date
from typing import List, Dict, Optional, Any
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday


def validate_shift_times(start_time: time, end_time: time) -> List[str]:
    """Basic shift time validation"""
    errors = []
    
    if not start_time or not end_time:
        errors.append("Start time and end time are required")
        return errors
    
    # Convert to minutes for comparison
    start_minutes = start_time.hour * 60 + start_time.minute
    end_minutes = end_time.hour * 60 + end_time.minute
    
    # Handle midnight crossing
    if end_minutes <= start_minutes:
        # This is a midnight-crossing shift, which is valid
        pass
    
    return errors


def validate_assignment_dates(effective_from: date, effective_to: date = None) -> List[str]:
    """Basic assignment date validation"""
    errors = []
    
    if not effective_from:
        errors.append("Effective from date is required")
        return errors
    
    if effective_from < date.today():
        errors.append("Effective from date cannot be in the past")
    
    if effective_to and effective_to < effective_from:
        errors.append("Effective to date cannot be before effective from date")
    
    return errors


def validate_user_assignment_conflict(user: User, shift: ShiftMaster, 
                                    effective_from: date, effective_to: date = None) -> List[str]:
    """Basic conflict validation for user assignments"""
    errors = []
    
    # Check for overlapping assignments
    existing_assignments = ShiftAssignment.objects.filter(
        user=user,
        is_current=True
    )
    
    if effective_to:
        existing_assignments = existing_assignments.filter(
            effective_from__lte=effective_to,
            effective_to__gte=effective_from
        )
    else:
        existing_assignments = existing_assignments.filter(
            effective_from__lte=effective_from
        )
    
    if existing_assignments.exists():
        errors.append(f"User already has an assignment during this period")
    
    return errors


def validate_holiday_conflict(assignment_date: date) -> List[str]:
    """Check if assignment conflicts with holidays"""
    errors = []
    
    holiday = Holiday.objects.filter(date=assignment_date).first()
    if holiday:
        errors.append(f"Assignment date conflicts with holiday: {holiday.name}")
    
    return errors


# Essential validation functions that can be merged into services.py
ESSENTIAL_VALIDATORS = {
    'validate_shift_times': validate_shift_times,
    'validate_assignment_dates': validate_assignment_dates,
    'validate_user_assignment_conflict': validate_user_assignment_conflict,
    'validate_holiday_conflict': validate_holiday_conflict,
}
