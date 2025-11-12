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
                           created_by: User = None) -> AssignmentResult:
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
                    created_by=assigned_by
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

    def bulk_assign_shifts(self, assignments_data: List[Dict[str, Any]], 
                          created_by: User = None, 
                          auto_skip_conflicts: bool = True) -> BulkAssignmentResult:
        """
        Perform bulk shift assignments with intelligent conflict handling.

        Args:
            assignments_data: List of assignment dictionaries with keys:
                - user_id: ID of the user
                - shift_id: ID of the shift
                - effective_from: Start date
                - effective_to: End date (optional)
                - notes: Assignment notes (optional)
            created_by: User creating the assignments
            auto_skip_conflicts: If True, automatically skip conflicting assignments

        Returns:
            BulkAssignmentResult with detailed results
        """
        result = BulkAssignmentResult(total_attempted=len(assignments_data))

        for assignment_data in assignments_data:
            try:
                user_id = assignment_data['user_id']
                shift_id = assignment_data['shift_id']
                effective_from = assignment_data['effective_from']
                effective_to = assignment_data.get('effective_to')
                
                # Use the existing assign_shift_to_user method
                assignment_result = self.assign_shift_to_user(
                    user_id=user_id,
                    shift_id=shift_id,
                    effective_from=effective_from,
                    effective_to=effective_to,
                    created_by=created_by
                )

                if assignment_result.success:
                    result.successful.append(assignment_result)
                elif assignment_result.conflicts and auto_skip_conflicts:
                    # Skip assignments with conflicts if auto_skip_conflicts is True
                    result.skipped.append(assignment_result)
                else:
                    # Failed assignments (errors or conflicts when not skipping)
                    result.failed.append(assignment_result)

            except Exception as e:
                logger.error(f"Error in bulk assignment for data {assignment_data}: {e}")
                error_result = AssignmentResult(
                    success=False,
                    errors=[f"Invalid data: {str(e)}"]
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

    def process_csv_bulk_assignment(self, csv_file, created_by: User) -> Dict[str, Any]:
        """
        Process CSV file for bulk shift assignments.
        
        Expected CSV format:
        username,shift_name,effective_from,effective_to,notes
        
        Args:
            csv_file: Uploaded CSV file
            created_by: User processing the CSV
            
        Returns:
            Dictionary with processing results
        """
        try:
            import csv
            import io
            
            # Read CSV content
            csv_content = csv_file.read().decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            
            assignments_data = []
            errors = []
            
            for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 (header is row 1)
                try:
                    # Validate required fields
                    username = row.get('username', '').strip()
                    shift_name = row.get('shift_name', '').strip()
                    effective_from_str = row.get('effective_from', '').strip()
                    
                    if not all([username, shift_name, effective_from_str]):
                        errors.append(f"Row {row_num}: Missing required fields (username, shift_name, effective_from)")
                        continue
                    
                    # Find user by username
                    try:
                        user = User.objects.get(username=username, is_active=True)
                    except User.DoesNotExist:
                        errors.append(f"Row {row_num}: User '{username}' not found")
                        continue
                    
                    # Find shift by name
                    try:
                        shift = ShiftMaster.objects.get(name=shift_name, is_active=True)
                    except ShiftMaster.DoesNotExist:
                        errors.append(f"Row {row_num}: Shift '{shift_name}' not found")
                        continue
                    
                    # Parse dates
                    try:
                        from datetime import datetime
                        effective_from = datetime.strptime(effective_from_str, '%Y-%m-%d').date()
                    except ValueError:
                        errors.append(f"Row {row_num}: Invalid effective_from date format. Use YYYY-MM-DD")
                        continue
                    
                    effective_to = None
                    effective_to_str = row.get('effective_to', '').strip()
                    if effective_to_str:
                        try:
                            effective_to = datetime.strptime(effective_to_str, '%Y-%m-%d').date()
                        except ValueError:
                            errors.append(f"Row {row_num}: Invalid effective_to date format. Use YYYY-MM-DD")
                            continue
                    
                    # Prepare assignment data
                    assignments_data.append({
                        'user_id': user.id,
                        'shift_id': shift.id,
                        'effective_from': effective_from,
                        'effective_to': effective_to,
                        'notes': row.get('notes', '').strip() or f'CSV import by {created_by.get_full_name() or created_by.username}'
                    })
                    
                except Exception as e:
                    errors.append(f"Row {row_num}: Error processing row - {str(e)}")
            
            if errors and not assignments_data:
                return {
                    'success': False,
                    'message': 'No valid assignments found in CSV',
                    'errors': errors
                }
            
            # Process bulk assignments
            if assignments_data:
                result = self.bulk_assign_shifts(assignments_data, created_by=created_by)
                
                return {
                    'success': True,
                    'assigned_count': len(result.successful),
                    'failed_count': len(result.failed),
                    'skipped_count': len(result.skipped),
                    'csv_errors': errors,
                    'total_processed': len(assignments_data)
                }
            else:
                return {
                    'success': False,
                    'message': 'No valid assignments to process',
                    'errors': errors
                }
                
        except Exception as e:
            logger.error(f"Error processing CSV bulk assignment: {e}")
            return {
                'success': False,
                'message': f'Error processing CSV file: {str(e)}',
                'errors': []
            }

    def end_shift_assignment(self, assignment_id: int, end_date: date = None, ended_by: User = None) -> bool:
        """End a shift assignment."""
        try:
            assignment = ShiftAssignment.objects.get(id=assignment_id)
            
            if end_date is None:
                end_date = date.today()
            
            assignment.effective_to = end_date
            assignment.is_current = False
            assignment.save()
            
            logger.info(f"Successfully ended assignment {assignment_id}")
            return True
            
        except ShiftAssignment.DoesNotExist:
            logger.error(f"Assignment {assignment_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error ending assignment {assignment_id}: {e}")
            return False

    def is_working_day_for_user(self, user: User, check_date: date) -> bool:
        """Check if a date is a working day for a user based on their shift."""
        try:
            assignment = ShiftAssignment.objects.filter(
                user=user,
                is_current=True,
                effective_from__lte=check_date
            ).filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=check_date)
            ).first()
            
            if not assignment:
                return False
            
            # Simple check - assume all days are working days for now
            # This can be enhanced based on shift work_days configuration
            return True
            
        except Exception as e:
            logger.error(f"Error checking working day for user {user.username}: {e}")
            return False

    def get_shift_schedule_for_date(self, start_date: date, end_date: date = None) -> Dict[str, Any]:
        """Get shift schedule data for a date range."""
        try:
            if end_date is None:
                end_date = start_date
            
            assignments = ShiftAssignment.objects.filter(
                is_current=True,
                effective_from__lte=end_date
            ).filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=start_date)
            ).select_related('user', 'shift').order_by('shift__start_time')
            
            schedule_data = {}
            for assignment in assignments:
                date_key = start_date.strftime('%Y-%m-%d')
                if date_key not in schedule_data:
                    schedule_data[date_key] = []
                
                schedule_data[date_key].append({
                    'user': assignment.user.get_full_name() or assignment.user.username,
                    'shift': assignment.shift.name,
                    'start_time': assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    'assignment_id': assignment.id
                })
            
            return schedule_data
            
        except Exception as e:
            logger.error(f"Error getting schedule data: {e}")
            return {}

    def get_current_shift(self, user: User) -> Optional[ShiftMaster]:
        """Get user's current shift."""
        try:
            assignment = ShiftAssignment.objects.filter(
                user=user,
                is_current=True,
                effective_from__lte=date.today()
            ).filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=date.today())
            ).select_related('shift').first()
            
            return assignment.shift if assignment else None
            
        except Exception as e:
            logger.error(f"Error getting current shift for user {user.username}: {e}")
            return None

    def get_user_shift_status(self, user: User) -> Dict[str, Any]:
        """Get comprehensive shift status for a user."""
        try:
            current_assignment = ShiftAssignment.objects.filter(
                user=user,
                is_current=True,
                effective_from__lte=date.today()
            ).filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=date.today())
            ).select_related('shift').first()
            
            if current_assignment:
                return {
                    'has_shift': True,
                    'shift_name': current_assignment.shift.name,
                    'start_time': current_assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': current_assignment.shift.end_time.strftime('%H:%M'),
                    'effective_from': current_assignment.effective_from.strftime('%Y-%m-%d'),
                    'effective_to': current_assignment.effective_to.strftime('%Y-%m-%d') if current_assignment.effective_to else None,
                    'assignment_id': current_assignment.id
                }
            else:
                return {
                    'has_shift': False,
                    'shift_name': None,
                    'start_time': None,
                    'end_time': None,
                    'effective_from': None,
                    'effective_to': None,
                    'assignment_id': None
                }
                
        except Exception as e:
            logger.error(f"Error getting shift status for user {user.username}: {e}")
            return {
                'has_shift': False,
                'error': str(e)
            }


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
