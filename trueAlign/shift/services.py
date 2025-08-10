import logging
import csv
import io
from datetime import datetime, date, time, timedelta
from decimal import Decimal
from typing import List, Dict, Optional, Tuple, Any, Union
from django.contrib.auth.models import User, Group
from django.db import transaction, models
from django.db.models import Q, Count, Avg, Sum
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.core.files.uploadedfile import InMemoryUploadedFile
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday

logger = logging.getLogger('trueAlign.shift')

class ShiftService:
    """
    Comprehensive service class for shift management operations.
    Handles all business logic for shifts, assignments, holidays, and reporting.
    """

    def __init__(self):
        self.logger = logger
        self.timezone = timezone.get_current_timezone()

    # ============================
    # SHIFT MANAGEMENT METHODS
    # ============================

    def get_all_shifts(self, active_only: bool = True, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
        """
        Get paginated list of all shifts with filtering options.

        Args:
            active_only: Only return active shifts
            page: Page number for pagination
            per_page: Items per page

        Returns:
            Dict containing shifts, pagination info, and metadata
        """
        try:
            query = ShiftMaster.objects.all()

            if active_only:
                query = query.filter(is_active=True)

            # Add annotation for assignment count
            query = query.annotate(
                assignment_count=Count('assignments'),
                active_assignment_count=Count(
                    'assignments',
                    filter=Q(assignments__is_current=True)
                )
            ).order_by('name')

            paginator = Paginator(query, per_page)
            page_obj = paginator.get_page(page)

            shifts_data = []
            for shift in page_obj:
                shifts_data.append({
                    'id': shift.id,
                    'name': shift.name,
                    'start_time': shift.start_time.strftime('%H:%M'),
                    'end_time': shift.end_time.strftime('%H:%M'),
                    'duration': float(shift.shift_duration),
                    'work_days': shift.work_days,
                    'custom_work_days': shift.custom_work_days,
                    'is_active': shift.is_active,
                    'crosses_midnight': shift.crosses_midnight,
                    'assignment_count': shift.assignment_count,
                    'active_assignment_count': shift.active_assignment_count,
                    'expected_hours': shift.expected_hours,
                    'break_minutes': shift.break_duration.total_seconds() // 60,
                    'grace_minutes': shift.grace_period.total_seconds() // 60,
                    'created_at': shift.created_at,
                    'updated_at': shift.updated_at
                })

            return {
                'shifts': shifts_data,
                'pagination': {
                    'current_page': page_obj.number,
                    'total_pages': paginator.num_pages,
                    'total_count': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                    'per_page': per_page
                },
                'summary': {
                    'total_shifts': paginator.count,
                    'active_shifts': query.filter(is_active=True).count(),
                    'inactive_shifts': query.filter(is_active=False).count()
                }
            }

        except Exception as e:
            self.logger.error(f"Error getting all shifts: {str(e)}")
            raise

    def get_shift_by_id(self, shift_id: int) -> Dict[str, Any]:
        """
        Get a single shift by ID.

        Args:
            shift_id: The ID of the shift to retrieve

        Returns:
            Dict containing shift data or None if not found
        """
        try:
            shift = ShiftMaster.objects.get(id=shift_id)

            return {
                'id': shift.id,
                'name': shift.name,
                'description': getattr(shift, 'description', ''),
                'start_time': shift.start_time.strftime('%H:%M'),
                'end_time': shift.end_time.strftime('%H:%M'),
                'duration': float(shift.shift_duration),
                'work_days': shift.work_days,
                'custom_work_days': shift.custom_work_days,
                'is_active': shift.is_active,
                'crosses_midnight': shift.crosses_midnight,
                'break_minutes': shift.break_duration.total_seconds() // 60,
                'grace_minutes': shift.grace_period.total_seconds() // 60,
                'created_at': shift.created_at,
                'updated_at': shift.updated_at
            }

        except ShiftMaster.DoesNotExist:
            self.logger.warning(f"Shift with ID {shift_id} not found")
            return None
        except Exception as e:
            self.logger.error(f"Error getting shift by ID {shift_id}: {str(e)}")
            return None


    def get_shift_by_name(self, name: str) -> Optional[ShiftMaster]:
        """Get shift by name with error handling."""
        try:
            return ShiftMaster.objects.get(name=name, is_active=True)
        except ShiftMaster.DoesNotExist:
            self.logger.warning(f"Active shift with name '{name}' not found")
            return None
        except Exception as e:
            self.logger.error(f"Error getting shift by name '{name}': {str(e)}")
            raise

    def create_shift(self, shift_data: Dict[str, Any]) -> Tuple[bool, Union[ShiftMaster, str]]:
        """
        Create a new shift with validation.

        Args:
            shift_data: Dictionary containing shift information

        Returns:
            Tuple of (success: bool, result: ShiftMaster or error_message)
        """
        try:
            # Validate required fields
            required_fields = ['name', 'start_time', 'end_time', 'shift_duration']
            for field in required_fields:
                if field not in shift_data or not shift_data[field]:
                    return False, f"Field '{field}' is required"

            # Check for duplicate name
            if ShiftMaster.objects.filter(name=shift_data['name']).exists():
                return False, f"Shift with name '{shift_data['name']}' already exists"

            # Validate time format and values
            try:
                if isinstance(shift_data['start_time'], str):
                    shift_data['start_time'] = datetime.strptime(shift_data['start_time'], '%H:%M').time()
                if isinstance(shift_data['end_time'], str):
                    shift_data['end_time'] = datetime.strptime(shift_data['end_time'], '%H:%M').time()
            except ValueError as e:
                return False, f"Invalid time format: {str(e)}"

            # Validate shift duration
            duration = Decimal(str(shift_data['shift_duration']))
            if duration <= 0 or duration > 24:
                return False, "Shift duration must be between 0 and 24 hours"

            # Set defaults for optional fields
            shift_data.setdefault('break_duration', timedelta(minutes=30))
            shift_data.setdefault('grace_period', timedelta(minutes=15))
            shift_data.setdefault('work_days', 'Weekdays')
            shift_data.setdefault('is_active', True)

            # Convert string durations to timedelta if needed
            if isinstance(shift_data.get('break_duration'), (int, str)):
                minutes = int(shift_data['break_duration'])
                shift_data['break_duration'] = timedelta(minutes=minutes)

            if isinstance(shift_data.get('grace_period'), (int, str)):
                minutes = int(shift_data['grace_period'])
                shift_data['grace_period'] = timedelta(minutes=minutes)

            # Create the shift
            with transaction.atomic():
                shift = ShiftMaster.objects.create(**shift_data)
                self.logger.info(f"Created new shift: {shift.name} (ID: {shift.id})")
                return True, shift

        except Exception as e:
            self.logger.error(f"Error creating shift: {str(e)}")
            return False, f"Error creating shift: {str(e)}"

    def update_shift(self, shift_id: int, update_data: Dict[str, Any]) -> Tuple[bool, Union[ShiftMaster, str]]:
        """
        Update an existing shift with validation.

        Args:
            shift_id: ID of shift to update
            update_data: Dictionary containing fields to update

        Returns:
            Tuple of (success: bool, result: ShiftMaster or error_message)
        """
        try:
            shift = self.get_shift_by_id(shift_id)
            if not shift:
                return False, f"Shift with ID {shift_id} not found"

            # Check if name is being changed and if it conflicts
            if 'name' in update_data and update_data['name'] != shift.name:
                if ShiftMaster.objects.filter(name=update_data['name']).exclude(id=shift_id).exists():
                    return False, f"Shift with name '{update_data['name']}' already exists"

            # Validate time formats
            for time_field in ['start_time', 'end_time']:
                if time_field in update_data and isinstance(update_data[time_field], str):
                    try:
                        update_data[time_field] = datetime.strptime(update_data[time_field], '%H:%M').time()
                    except ValueError:
                        return False, f"Invalid time format for {time_field}"

            # Validate duration
            if 'shift_duration' in update_data:
                duration = Decimal(str(update_data['shift_duration']))
                if duration <= 0 or duration > 24:
                    return False, "Shift duration must be between 0 and 24 hours"

            # Convert duration fields
            for duration_field in ['break_duration', 'grace_period']:
                if duration_field in update_data and isinstance(update_data[duration_field], (int, str)):
                    minutes = int(update_data[duration_field])
                    update_data[duration_field] = timedelta(minutes=minutes)

            # Update the shift
            with transaction.atomic():
                for field, value in update_data.items():
                    if hasattr(shift, field):
                        setattr(shift, field, value)

                shift.save()
                self.logger.info(f"Updated shift: {shift.name} (ID: {shift.id})")
                return True, shift

        except Exception as e:
            self.logger.error(f"Error updating shift {shift_id}: {str(e)}")
            return False, f"Error updating shift: {str(e)}"

    def delete_shift(self, shift_id: int, force: bool = False) -> Tuple[bool, str]:
        """
        Delete a shift with safety checks.

        Args:
            shift_id: ID of shift to delete
            force: If True, delete even with active assignments

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            shift = self.get_shift_by_id(shift_id)
            if not shift:
                return False, f"Shift with ID {shift_id} not found"

            # Check for active assignments
            active_assignments = ShiftAssignment.objects.filter(
                shift=shift,
                is_current=True
            ).count()

            if active_assignments > 0 and not force:
                return False, f"Cannot delete shift. {active_assignments} active assignments exist. Use force=True to override."

            with transaction.atomic():
                # If forcing deletion, deactivate assignments
                if force and active_assignments > 0:
                    ShiftAssignment.objects.filter(
                        shift=shift,
                        is_current=True
                    ).update(
                        is_current=False,
                        effective_to=timezone.now().date()
                    )

                shift_name = shift.name
                shift.delete()
                self.logger.info(f"Deleted shift: {shift_name} (ID: {shift_id})")
                return True, f"Shift '{shift_name}' deleted successfully"

        except Exception as e:
            self.logger.error(f"Error deleting shift {shift_id}: {str(e)}")
            return False, f"Error deleting shift: {str(e)}"

    # ============================
    # SHIFT ASSIGNMENT METHODS
    # ============================

    def assign_shift_to_user(self, user_id: int, shift_id: int, effective_from: date,
                           effective_to: Optional[date] = None) -> Tuple[bool, Union[ShiftAssignment, str]]:
        """
        Assign a shift to a user with overlap handling.

        Args:
            user_id: ID of user to assign shift to
            shift_id: ID of shift to assign
            effective_from: Start date of assignment
            effective_to: End date of assignment (optional)

        Returns:
            Tuple of (success: bool, result: ShiftAssignment or error_message)
        """
        try:
            # Validate user and shift exist
            try:
                user = User.objects.get(id=user_id)
                shift = ShiftMaster.objects.get(id=shift_id)
            except (User.DoesNotExist, ShiftMaster.DoesNotExist) as e:
                return False, f"User or Shift not found: {str(e)}"

            # Validate dates
            if effective_from < timezone.now().date():
                return False, "Effective from date cannot be in the past"

            if effective_to and effective_to <= effective_from:
                return False, "Effective to date must be after effective from date"

            # Check for overlapping assignments
            is_valid, error_message = self.validate_shift_assignment(user_id, shift_id, effective_from, effective_to)
            if not is_valid:
                return False, error_message

            with transaction.atomic():
                # Create new assignment
                assignment = ShiftAssignment.objects.create(
                    user=user,
                    shift=shift,
                    effective_from=effective_from,
                    effective_to=effective_to,
                    is_current=True
                )

                self.logger.info(f"Assigned shift '{shift.name}' to user '{user.username}' from {effective_from}")
                return True, assignment

        except Exception as e:
            self.logger.error(f"Error assigning shift: {str(e)}")
            return False, f"Error assigning shift: {str(e)}"

    def assign_shifts_to_users(self, user_ids: List[int], shift_id: int, effective_from: date,
                             effective_to: Optional[date] = None) -> Tuple[int, int, List[str]]:
        """
        Bulk assign shift to multiple users.

        Args:
            user_ids: List of user IDs
            shift_id: ID of shift to assign
            effective_from: Start date of assignment
            effective_to: End date of assignment (optional)

        Returns:
            Tuple of (success_count: int, error_count: int, errors: List[str])
        """
        success_count = 0
        error_count = 0
        errors = []

        try:
            shift = ShiftMaster.objects.get(id=shift_id)
        except ShiftMaster.DoesNotExist:
            return 0, len(user_ids), [f"Shift with ID {shift_id} not found"]

        for user_id in user_ids:
            try:
                success, result = self.assign_shift_to_user(user_id, shift_id, effective_from, effective_to)
                if success:
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"User {user_id}: {result}")
            except Exception as e:
                error_count += 1
                errors.append(f"User {user_id}: {str(e)}")

        self.logger.info(f"Bulk assignment completed: {success_count} successful, {error_count} failed")
        return success_count, error_count, errors

    def validate_shift_assignment(self, user_id: int, shift_id: int, effective_from: date,
                                effective_to: Optional[date] = None, assignment_id: Optional[int] = None,
                                override_conflicts: bool = False) -> Tuple[bool, str, dict]:
        """
        Enhanced validation for shift assignments with comprehensive business rules.

        Args:
            user_id: ID of user
            shift_id: ID of shift
            effective_from: Start date
            effective_to: End date (optional)
            assignment_id: ID of assignment being edited (optional)
            override_conflicts: Allow admin to override conflicts

        Returns:
            Tuple of (is_valid: bool, message: str, validation_details: dict)
        """
        validation_details = {
            'conflicts': [],
            'warnings': [],
            'business_rules': [],
            'recommendations': []
        }

        try:
            # Check if user and shift exist and are active
            try:
                user = User.objects.get(id=user_id, is_active=True)
                shift = ShiftMaster.objects.get(id=shift_id, is_active=True)
            except User.DoesNotExist:
                return False, "User not found or inactive", validation_details
            except ShiftMaster.DoesNotExist:
                return False, "Shift not found or inactive", validation_details

            # Validate date ranges
            today = timezone.now().date()
            if effective_from < today and not assignment_id:
                validation_details['business_rules'].append("Cannot create assignments with past effective dates")
                return False, "Effective date cannot be in the past for new assignments", validation_details

            if effective_to and effective_to <= effective_from:
                return False, "End date must be after start date", validation_details

            # Check maximum assignment duration (1 year)
            if effective_to:
                duration = (effective_to - effective_from).days
                if duration > 365:
                    validation_details['business_rules'].append("Assignment duration exceeds 1 year limit")
                    if not override_conflicts:
                        return False, "Assignment duration cannot exceed 1 year", validation_details

            # Check for overlapping assignments
            overlapping_assignments = self._find_overlapping_assignments(
                user_id, effective_from, effective_to, assignment_id
            )

            if overlapping_assignments:
                conflict_msgs = []
                for assignment in overlapping_assignments:
                    end_str = assignment.effective_to.strftime('%Y-%m-%d') if assignment.effective_to else 'ongoing'
                    conflict_msg = f"{assignment.shift.name} ({assignment.effective_from.strftime('%Y-%m-%d')} to {end_str})"
                    conflict_msgs.append(conflict_msg)
                    validation_details['conflicts'].append({
                        'type': 'overlapping_assignment',
                        'assignment_id': assignment.id,
                        'shift_name': assignment.shift.name,
                        'effective_from': assignment.effective_from,
                        'effective_to': assignment.effective_to
                    })

                if not override_conflicts:
                    return False, f"Overlapping assignments found: {', '.join(conflict_msgs)}", validation_details

            # Check for exact same shift assignment
            exact_conflicts = self._find_exact_shift_conflicts(
                user_id, shift_id, effective_from, effective_to, assignment_id
            )

            if exact_conflicts and not override_conflicts:
                validation_details['conflicts'].append({
                    'type': 'exact_shift_conflict',
                    'message': 'User already assigned to this shift in overlapping period'
                })
                return False, "User is already assigned to this shift during the specified period", validation_details

            # Business rule validations
            business_rule_issues = self._validate_business_rules(user, shift, effective_from, effective_to)
            validation_details['business_rules'].extend(business_rule_issues)

            # Check working days alignment
            working_days_warning = self._check_working_days_alignment(shift, effective_from, effective_to)
            if working_days_warning:
                validation_details['warnings'].append(working_days_warning)

            # Check for shift pattern recommendations
            recommendations = self._get_shift_recommendations(user, shift, effective_from)
            validation_details['recommendations'].extend(recommendations)

            # Final validation
            has_critical_issues = any(
                conflict['type'] in ['overlapping_assignment', 'exact_shift_conflict']
                for conflict in validation_details['conflicts']
            )

            if has_critical_issues and not override_conflicts:
                return False, "Critical conflicts found - admin override required", validation_details

            return True, "Assignment is valid", validation_details

        except Exception as e:
            self.logger.error(f"Error validating assignment: {str(e)}")
            return False, f"Validation error: {str(e)}", validation_details

    def _find_overlapping_assignments(self, user_id: int, effective_from: date,
                                    effective_to: Optional[date], assignment_id: Optional[int]) -> List[ShiftAssignment]:
        """Find assignments that overlap with the given date range."""
        query = ShiftAssignment.objects.filter(user_id=user_id)

        if assignment_id:
            query = query.exclude(id=assignment_id)

        # Complex overlap detection
        if effective_to:
            # Assignment has end date
            query = query.filter(
                Q(effective_from__lte=effective_to) &
                (Q(effective_to__gte=effective_from) | Q(effective_to__isnull=True))
            )
        else:
            # Assignment is ongoing
            query = query.filter(
                Q(effective_to__gte=effective_from) | Q(effective_to__isnull=True)
            )

        return list(query.select_related('shift'))

    def _find_exact_shift_conflicts(self, user_id: int, shift_id: int, effective_from: date,
                                   effective_to: Optional[date], assignment_id: Optional[int]) -> List[ShiftAssignment]:
        """Find assignments to the exact same shift in overlapping period."""
        query = ShiftAssignment.objects.filter(user_id=user_id, shift_id=shift_id)

        if assignment_id:
            query = query.exclude(id=assignment_id)

        if effective_to:
            query = query.filter(
                Q(effective_from__lte=effective_to) &
                (Q(effective_to__gte=effective_from) | Q(effective_to__isnull=True))
            )
        else:
            query = query.filter(
                Q(effective_to__gte=effective_from) | Q(effective_to__isnull=True)
            )

        return list(query.select_related('shift'))

    def _validate_business_rules(self, user, shift: ShiftMaster, effective_from: date,
                               effective_to: Optional[date]) -> List[str]:
        """Validate business rules for shift assignments."""
        issues = []

        # Rule 1: Check if user has too many shift changes in short period
        recent_assignments = ShiftAssignment.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count()

        if recent_assignments >= 5:
            issues.append(f"User has {recent_assignments} shift changes in the last 30 days - may indicate instability")

        # Rule 2: Check for rapid consecutive assignments
        last_assignment = ShiftAssignment.objects.filter(
            user=user,
            effective_from__lt=effective_from
        ).order_by('-effective_from').first()

        if last_assignment and last_assignment.effective_to:
            gap = (effective_from - last_assignment.effective_to).days
            if gap < 1:
                issues.append("Assignment starts immediately after previous assignment ends - no buffer time")
            elif gap == 1:
                issues.append("Assignment starts next day after previous assignment - minimal buffer time")

        # Rule 3: Check weekend/holiday assignments
        if effective_from.weekday() >= 5:  # Saturday or Sunday
            issues.append(f"Assignment starts on {effective_from.strftime('%A')} - weekend start date")

        # Rule 4: Check for night shift to day shift transitions
        if last_assignment and last_assignment.shift.is_night_shift() and not shift.is_night_shift():
            issues.append("Transition from night shift to day shift - consider adjustment period")

        return issues

    def _check_working_days_alignment(self, shift: ShiftMaster, effective_from: date,
                                    effective_to: Optional[date]) -> Optional[str]:
        """Check if assignment period aligns with shift working days."""
        working_days = set(shift.working_days_list)

        # Check first week of assignment
        check_date = effective_from
        end_check = effective_to or (effective_from + timedelta(days=7))
        end_check = min(end_check, effective_from + timedelta(days=14))  # Max 2 weeks check

        working_day_found = False
        for i in range((end_check - check_date).days + 1):
            date_to_check = check_date + timedelta(days=i)
            if date_to_check.weekday() in working_days:
                working_day_found = True
                break

        if not working_day_found:
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            working_day_names = [day_names[i] for i in working_days]
            return f"Shift works on {', '.join(working_day_names)} but assignment period may not include these days"

        return None

    def _get_shift_recommendations(self, user, shift: ShiftMaster, effective_from: date) -> List[str]:
        """Get recommendations for the shift assignment."""
        recommendations = []

        # Recommendation 1: Optimal start dates
        if effective_from.weekday() == 0:  # Monday
            recommendations.append("Good choice: Starting assignment on Monday allows full week adjustment")
        elif effective_from.weekday() >= 5:  # Weekend
            recommendations.append("Consider: Weekend start may require special arrangements")

        # Recommendation 2: Grace period suggestions
        if shift.grace_period and shift.grace_period.total_seconds() < 600:  # Less than 10 minutes
            recommendations.append("Consider: Increase grace period for better attendance flexibility")

        # Recommendation 3: Break duration optimization
        if shift.break_duration:
            break_hours = shift.break_duration.total_seconds() / 3600
            if break_hours < 0.5 and shift.shift_duration >= 8:
                recommendations.append("Consider: Increase break duration for shifts 8+ hours long")

        return recommendations

    def end_shift_assignment(self, assignment_id: int, end_date: Optional[date] = None) -> Tuple[bool, str]:
        """
        End a shift assignment.

        Args:
            assignment_id: ID of assignment to end
            end_date: Date to end assignment (defaults to today)

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            assignment = ShiftAssignment.objects.get(id=assignment_id)

            if not end_date:
                end_date = timezone.now().date()

            if assignment.effective_from > end_date:
                return False, "End date cannot be before start date"

            with transaction.atomic():
                assignment.effective_to = end_date
                assignment.is_current = False
                assignment.save()

                self.logger.info(f"Ended shift assignment {assignment_id} on {end_date}")
                return True, f"Assignment ended successfully on {end_date}"

        except ShiftAssignment.DoesNotExist:
            return False, f"Assignment with ID {assignment_id} not found"
        except Exception as e:
            self.logger.error(f"Error ending assignment {assignment_id}: {str(e)}")
            return False, f"Error ending assignment: {str(e)}"

    def get_shift_assignments(self, filters: Dict[str, Any] = None, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
        """
        Get paginated shift assignments with filtering.

        Args:
            filters: Dictionary of filter criteria
            page: Page number
            per_page: Items per page

        Returns:
            Dictionary containing assignments and pagination info
        """
        try:
            query = ShiftAssignment.objects.select_related('user', 'shift').all()

            if filters:
                if filters.get('user_id'):
                    query = query.filter(user_id=filters['user_id'])
                if filters.get('shift_id'):
                    query = query.filter(shift_id=filters['shift_id'])
                if filters.get('is_current') is not None:
                    query = query.filter(is_current=filters['is_current'])
                if filters.get('effective_from'):
                    query = query.filter(effective_from__gte=filters['effective_from'])
                if filters.get('effective_to'):
                    query = query.filter(effective_to__lte=filters['effective_to'])

            query = query.order_by('-created_at')
            paginator = Paginator(query, per_page)
            page_obj = paginator.get_page(page)

            assignments_data = []
            for assignment in page_obj:
                assignments_data.append({
                    'id': assignment.id,
                    'user': {
                        'id': assignment.user.id,
                        'username': assignment.user.username,
                        'full_name': assignment.user.get_full_name(),
                        'email': assignment.user.email
                    },
                    'shift': {
                        'id': assignment.shift.id,
                        'name': assignment.shift.name,
                        'start_time': assignment.shift.start_time.strftime('%H:%M'),
                        'end_time': assignment.shift.end_time.strftime('%H:%M')
                    },
                    'effective_from': assignment.effective_from,
                    'effective_to': assignment.effective_to,
                    'is_current': assignment.is_current,
                    'days_remaining': assignment.days_remaining(),
                    'total_duration': assignment.total_duration(),
                    'has_ended': assignment.has_ended(),
                    'created_at': assignment.created_at
                })

            return {
                'assignments': assignments_data,
                'pagination': {
                    'current_page': page_obj.number,
                    'total_pages': paginator.num_pages,
                    'total_count': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                    'per_page': per_page
                }
            }

        except Exception as e:
            self.logger.error(f"Error getting shift assignments: {str(e)}")
            raise

    # ============================
    # USER SHIFT METHODS
    # ============================

    def get_current_shift(self, user: User, date: Optional[date] = None) -> Optional[ShiftMaster]:
        """
        Get user's current shift for a specific date.

        Args:
            user: User object
            date: Date to check (defaults to today)

        Returns:
            ShiftMaster object or None
        """
        if not date:
            date = timezone.now().date()

        return ShiftAssignment.get_user_current_shift(user, date)

    def is_working_day_for_user(self, user: User, date: date) -> bool:
        """
        Check if a date is a working day for the user based on their assigned shift.

        Args:
            user: User object
            date: Date to check

        Returns:
            True if it's a working day, False otherwise
        """
        try:
            # Check if it's a holiday first
            if Holiday.is_holiday(date):
                return False

            shift = self.get_current_shift(user, date)
            if not shift:
                return False

            return shift.is_working_day(date)

        except Exception as e:
            self.logger.error(f"Error checking working day for user {user.username}: {str(e)}")
            return False

    def is_user_on_shift_now(self, user: User) -> Dict[str, Any]:
        """
        Check if user is currently within their shift hours.

        Args:
            user: User object

        Returns:
            Dictionary with shift status information
        """
        try:
            now = timezone.now()
            today = now.date()
            current_time = now.time()

            shift = self.get_current_shift(user, today)
            if not shift:
                return {
                    'on_shift': False,
                    'message': 'No shift assigned',
                    'shift': None
                }

            # Check if today is a working day
            if not self.is_working_day_for_user(user, today):
                return {
                    'on_shift': False,
                    'message': 'Not a working day',
                    'shift': {
                        'name': shift.name,
                        'start_time': shift.start_time.strftime('%H:%M'),
                        'end_time': shift.end_time.strftime('%H:%M')
                    }
                }

            # Check if within shift hours (considering grace period)
            is_within_hours = shift.is_within_shift_hours(now, today)

            # Check with grace period
            grace_start = (datetime.combine(today, shift.start_time) - shift.grace_period).time()
            grace_end_date = today
            if shift.crosses_midnight:
                grace_end_date = today + timedelta(days=1)
            grace_end = (datetime.combine(grace_end_date, shift.end_time) + shift.grace_period).time()

            within_grace = False
            if shift.crosses_midnight:
                within_grace = current_time >= grace_start or current_time <= grace_end
            else:
                within_grace = grace_start <= current_time <= grace_end

            return {
                'on_shift': is_within_hours,
                'within_grace_period': within_grace,
                'shift': {
                    'name': shift.name,
                    'start_time': shift.start_time.strftime('%H:%M'),
                    'end_time': shift.end_time.strftime('%H:%M'),
                    'crosses_midnight': shift.crosses_midnight
                },
                'current_time': current_time.strftime('%H:%M'),
                'message': 'On shift' if is_within_hours else 'Off shift'
            }

        except Exception as e:
            self.logger.error(f"Error checking shift status for user {user.username}: {str(e)}")
            return {
                'on_shift': False,
                'message': f'Error checking shift status: {str(e)}',
                'shift': None
            }

    def get_user_shift_calendar(self, user: User, month: int, year: int) -> Dict[str, Any]:
        """
        Get calendar view of user's shifts for a specific month.

        Args:
            user: User object
            month: Month (1-12)
            year: Year

        Returns:
            Dictionary with calendar data
        """
        try:
            from calendar import monthrange

            # Get first and last day of month
            first_day = date(year, month, 1)
            last_day = date(year, month, monthrange(year, month)[1])

            calendar_data = []
            current_date = first_day

            while current_date <= last_day:
                shift = self.get_current_shift(user, current_date)
                is_working = self.is_working_day_for_user(user, current_date)
                is_holiday = Holiday.is_holiday(current_date)

                day_data = {
                    'date': current_date,
                    'day': current_date.day,
                    'weekday': current_date.strftime('%A'),
                    'is_working_day': is_working,
                    'is_holiday': is_holiday,
                    'shift': {
                        'name': shift.name if shift else None,
                        'start_time': shift.start_time.strftime('%H:%M') if shift else None,
                        'end_time': shift.end_time.strftime('%H:%M') if shift else None,
                        'duration': float(shift.shift_duration) if shift else None
                    } if shift else None
                }

                if is_holiday:
                    holiday = Holiday.objects.filter(
                        Q(date=current_date) |
                        Q(recurring_yearly=True, date__month=current_date.month, date__day=current_date.day)
                    ).first()
                    day_data['holiday_name'] = holiday.name if holiday else 'Holiday'

                calendar_data.append(day_data)
                current_date += timedelta(days=1)

            # Calculate summary
            working_days = sum(1 for day in calendar_data if day['is_working_day'])
            holidays = sum(1 for day in calendar_data if day['is_holiday'])
            total_hours = sum(day['shift']['duration'] for day in calendar_data
                            if day['shift'] and day['is_working_day']) or 0

            return {
                'month': month,
                'year': year,
                'calendar': calendar_data,
                'summary': {
                    'total_days': len(calendar_data),
                    'working_days': working_days,
                    'holidays': holidays,
                    'total_expected_hours': round(total_hours, 2)
                }
            }

        except Exception as e:
            self.logger.error(f"Error generating calendar for user {user.username}: {str(e)}")
            raise

    def get_shift_history(self, user_id: int, start_date: Optional[date] = None,
                         end_date: Optional[date] = None) -> List[Dict[str, Any]]:
        """
        Get shift assignment history for a user.

        Args:
            user_id: User ID
            start_date: Start date filter
            end_date: End date filter

        Returns:
            List of shift assignment history
        """
        try:
            assignments = ShiftAssignment.get_shift_history(
                User.objects.get(id=user_id),
                start_date,
                end_date
            )

            history = []
            for assignment in assignments:
                history.append({
                    'id': assignment.id,
                    'shift_name': assignment.shift.name,
                    'start_time': assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    'effective_from': assignment.effective_from,
                    'effective_to': assignment.effective_to,
                    'duration_days': assignment.total_duration(),
                    'is_current': assignment.is_current,
                    'created_at': assignment.created_at
                })

            return history

        except Exception as e:
            self.logger.error(f"Error getting shift history for user {user_id}: {str(e)}")
            raise

    # ============================
    # HOLIDAY METHODS
    # ============================

    def is_holiday(self, date: date) -> bool:
        """Check if a date is a holiday."""
        return Holiday.is_holiday(date)

    def get_holidays(self, year: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get list of holidays, optionally filtered by year.

        Args:
            year: Year to filter by (optional)

        Returns:
            List of holiday data
        """
        try:
            query = Holiday.objects.all()

            if year:
                query = query.filter(date__year=year)

            holidays = []
            for holiday in query.order_by('date'):
                holidays.append({
                    'id': holiday.id,
                    'name': holiday.name,
                    'date': holiday.date,
                    'recurring_yearly': holiday.recurring_yearly,
                    'created_at': holiday.created_at
                })

            return holidays

        except Exception as e:
            self.logger.error(f"Error getting holidays: {str(e)}")
            raise

    def create_holiday(self, holiday_data: Dict[str, Any]) -> Tuple[bool, Union[Holiday, str]]:
        """
        Create a new holiday.

        Args:
            holiday_data: Dictionary containing holiday information

        Returns:
            Tuple of (success: bool, result: Holiday or error_message)
        """
        try:
            # Validate required fields
            if not holiday_data.get('name') or not holiday_data.get('date'):
                return False, "Name and date are required"

            # Convert string date to date object if needed
            if isinstance(holiday_data['date'], str):
                try:
                    holiday_data['date'] = datetime.strptime(holiday_data['date'], '%Y-%m-%d').date()
                except ValueError:
                    return False, "Invalid date format. Use YYYY-MM-DD"

            # Check for duplicate
            existing = Holiday.objects.filter(
                name=holiday_data['name'],
                date=holiday_data['date']
            ).exists()

            if existing:
                return False, f"Holiday '{holiday_data['name']}' on {holiday_data['date']} already exists"

            # Set default for recurring_yearly
            holiday_data.setdefault('recurring_yearly', True)

            with transaction.atomic():
                holiday = Holiday.objects.create(**holiday_data)
                self.logger.info(f"Created holiday: {holiday.name} on {holiday.date}")
                return True, holiday

        except Exception as e:
            self.logger.error(f"Error creating holiday: {str(e)}")
            return False, f"Error creating holiday: {str(e)}"

    # ============================
    # CSV IMPORT METHODS
    # ============================

    def assign_shifts_from_csv(self, csv_file: InMemoryUploadedFile) -> Dict[str, Any]:
        """
        Bulk assign shifts from CSV file.

        Expected CSV format:
        username,shift_name,effective_from,effective_to

        Args:
            csv_file: Uploaded CSV file

        Returns:
            Dictionary with import results
        """
        try:
            # Read and validate CSV
            csv_content = csv_file.read().decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(csv_content))

            # Validate headers
            required_headers = ['username', 'shift_name', 'effective_from']
            missing_headers = [h for h in required_headers if h not in csv_reader.fieldnames]
            if missing_headers:
                return {
                    'success': False,
                    'message': f"Missing required headers: {', '.join(missing_headers)}",
                    'success_count': 0,
                    'error_count': 0,
                    'errors': []
                }

            results = {
                'success': True,
                'success_count': 0,
                'error_count': 0,
                'errors': [],
                'assignments': []
            }

            row_number = 1
            for row in csv_reader:
                row_number += 1
                try:
                    # Get user
                    try:
                        user = User.objects.get(username=row['username'])
                    except User.DoesNotExist:
                        results['errors'].append(f"Row {row_number}: User '{row['username']}' not found")
                        results['error_count'] += 1
                        continue

                    # Get shift
                    try:
                        shift = ShiftMaster.objects.get(name=row['shift_name'], is_active=True)
                    except ShiftMaster.DoesNotExist:
                        results['errors'].append(f"Row {row_number}: Shift '{row['shift_name']}' not found")
                        results['error_count'] += 1
                        continue

                    # Parse dates
                    try:
                        effective_from = datetime.strptime(row['effective_from'], '%Y-%m-%d').date()
                    except ValueError:
                        results['errors'].append(f"Row {row_number}: Invalid effective_from date format")
                        results['error_count'] += 1
                        continue

                    effective_to = None
                    if row.get('effective_to') and row['effective_to'].strip():
                        try:
                            effective_to = datetime.strptime(row['effective_to'], '%Y-%m-%d').date()
                        except ValueError:
                            results['errors'].append(f"Row {row_number}: Invalid effective_to date format")
                            results['error_count'] += 1
                            continue

                    # Assign shift
                    success, result = self.assign_shift_to_user(
                        user.id, shift.id, effective_from, effective_to
                    )

                    if success:
                        results['success_count'] += 1
                        results['assignments'].append({
                            'user': user.username,
                            'shift': shift.name,
                            'effective_from': effective_from,
                            'effective_to': effective_to
                        })
                    else:
                        results['error_count'] += 1
                        results['errors'].append(f"Row {row_number}: {result}")

                except Exception as e:
                    results['error_count'] += 1
                    results['errors'].append(f"Row {row_number}: {str(e)}")

            # Update overall success status
            results['success'] = results['error_count'] == 0

            self.logger.info(f"CSV import completed: {results['success_count']} successful, {results['error_count']} failed")
            return results

        except Exception as e:
            self.logger.error(f"Error processing CSV import: {str(e)}")
            return {
                'success': False,
                'message': f"Error processing CSV: {str(e)}",
                'success_count': 0,
                'error_count': 0,
                'errors': []
            }

    # ============================
    # STATISTICS AND REPORTING
    # ============================

    def get_shift_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive shift statistics.

        Returns:
            Dictionary with various statistics
        """
        try:
            today = timezone.now().date()

            # Basic counts
            total_shifts = ShiftMaster.objects.count()
            active_shifts = ShiftMaster.objects.filter(is_active=True).count()
            total_assignments = ShiftAssignment.objects.count()
            current_assignments = ShiftAssignment.objects.filter(is_current=True).count()

            # User statistics
            total_users = User.objects.count()
            users_with_shifts = User.objects.filter(
                shiftassignment__is_current=True
            ).distinct().count()
            users_without_shifts = total_users - users_with_shifts

            # Shift distribution
            shift_distribution = ShiftMaster.objects.annotate(
                assignment_count=Count('shiftassignment', filter=Q(shiftassignment__is_current=True))
            ).values('name', 'assignment_count')

            # Assignment trends (last 30 days)
            thirty_days_ago = today - timedelta(days=30)
            recent_assignments = ShiftAssignment.objects.filter(
                created_at__date__gte=thirty_days_ago
            ).count()

            # Upcoming changes (next 7 days)
            upcoming_changes = ShiftAssignment.upcoming_shift_endings(days=7).count()

            # Holiday count
            total_holidays = Holiday.objects.count()
            upcoming_holidays = Holiday.objects.filter(
                Q(date__gte=today, date__lte=today + timedelta(days=30)) |
                Q(recurring_yearly=True, date__month__gte=today.month,
                  date__day__gte=today.day if today.month == today.month else 1)
            ).count()

            # Work pattern distribution
            work_pattern_stats = ShiftMaster.objects.values('work_days').annotate(
                count=Count('id')
            )

            return {
                'overview': {
                    'total_shifts': total_shifts,
                    'active_shifts': active_shifts,
                    'inactive_shifts': total_shifts - active_shifts,
                    'total_assignments': total_assignments,
                    'current_assignments': current_assignments
                },
                'users': {
                    'total_users': total_users,
                    'users_with_shifts': users_with_shifts,
                    'users_without_shifts': users_without_shifts,
                    'coverage_percentage': round((users_with_shifts / total_users * 100) if total_users > 0 else 0, 2)
                },
                'shift_distribution': list(shift_distribution),
                'trends': {
                    'recent_assignments': recent_assignments,
                    'upcoming_changes': upcoming_changes
                },
                'holidays': {
                    'total_holidays': total_holidays,
                    'upcoming_holidays': upcoming_holidays
                },
                'work_patterns': list(work_pattern_stats),
                'updated_at': timezone.now()
            }

        except Exception as e:
            self.logger.error(f"Error getting shift statistics: {str(e)}")
            raise

    def get_shift_schedule_for_date(self, date: date) -> Dict[str, Any]:
        """
        Get who is on shift for a specific date.

        Args:
            date: Date to check

        Returns:
            Dictionary with schedule information
        """
        try:
            # Get all current assignments
            assignments = ShiftAssignment.objects.filter(
                effective_from__lte=date
            ).filter(
                Q(effective_to__gte=date) | Q(effective_to__isnull=True)
            ).select_related('user', 'shift')

            schedule = {}
            total_scheduled = 0

            for assignment in assignments:
                shift = assignment.shift
                user = assignment.user

                # Check if it's a working day for this shift
                if shift.is_working_day(date) and not Holiday.is_holiday(date):
                    if shift.name not in schedule:
                        schedule[shift.name] = {
                            'shift_info': {
                                'id': shift.id,
                                'name': shift.name,
                                'start_time': shift.start_time.strftime('%H:%M'),
                                'end_time': shift.end_time.strftime('%H:%M'),
                                'duration': float(shift.shift_duration),
                                'crosses_midnight': shift.crosses_midnight
                            },
                            'users': []
                        }

                    schedule[shift.name]['users'].append({
                        'id': user.id,
                        'username': user.username,
                        'full_name': user.get_full_name(),
                        'email': user.email
                    })
                    total_scheduled += 1

            # Check if it's a holiday
            is_holiday = Holiday.is_holiday(date)
            holiday_info = None
            if is_holiday:
                holiday = Holiday.objects.filter(
                    Q(date=date) |
                    Q(recurring_yearly=True, date__month=date.month, date__day=date.day)
                ).first()
                holiday_info = {
                    'name': holiday.name if holiday else 'Holiday',
                    'date': holiday.date if holiday else date,
                    'recurring': holiday.recurring_yearly if holiday else False
                }

            return {
                'date': date,
                'weekday': date.strftime('%A'),
                'is_holiday': is_holiday,
                'holiday_info': holiday_info,
                'total_scheduled': total_scheduled,
                'shifts': schedule,
                'summary': {
                    'total_shifts': len(schedule),
                    'total_users': total_scheduled
                }
            }

        except Exception as e:
            self.logger.error(f"Error getting schedule for date {date}: {str(e)}")
            raise

    def get_upcoming_shift_changes(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get shift assignments ending in the next N days.

        Args:
            days: Number of days to look ahead

        Returns:
            List of upcoming changes
        """
        try:
            upcoming = ShiftAssignment.upcoming_shift_endings(days)
            changes = []

            for assignment in upcoming:
                changes.append({
                    'id': assignment.id,
                    'user': {
                        'id': assignment.user.id,
                        'username': assignment.user.username,
                        'full_name': assignment.user.get_full_name()
                    },
                    'shift': {
                        'id': assignment.shift.id,
                        'name': assignment.shift.name,
                        'start_time': assignment.shift.start_time.strftime('%H:%M'),
                        'end_time': assignment.shift.end_time.strftime('%H:%M')
                    },
                    'effective_from': assignment.effective_from,
                    'effective_to': assignment.effective_to,
                    'days_remaining': assignment.days_remaining(),
                    'total_duration': assignment.total_duration()
                })

            return changes

        except Exception as e:
            self.logger.error(f"Error getting upcoming changes: {str(e)}")
            raise

    def generate_shift_report(self, start_date: date, end_date: date,
                            filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive shift report for date range.

        Args:
            start_date: Start date of report
            end_date: End date of report
            filters: Additional filters (user_ids, shift_ids, etc.)

        Returns:
            Dictionary with report data
        """
        try:
            # Get assignments in date range
            query = ShiftAssignment.objects.filter(
                effective_from__lte=end_date
            ).filter(
                Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
            ).select_related('user', 'shift')

            if filters:
                if filters.get('user_ids'):
                    query = query.filter(user_id__in=filters['user_ids'])
                if filters.get('shift_ids'):
                    query = query.filter(shift_id__in=filters['shift_ids'])

            assignments = list(query)

            # Process each day in range
            report_data = []
            current_date = start_date

            while current_date <= end_date:
                day_data = {
                    'date': current_date,
                    'weekday': current_date.strftime('%A'),
                    'is_holiday': Holiday.is_holiday(current_date),
                    'shifts': {}
                }

                # Process assignments for this date
                for assignment in assignments:
                    if assignment.is_active_on(current_date):
                        shift = assignment.shift
                        user = assignment.user

                        # Check if working day
                        if shift.is_working_day(current_date) and not day_data['is_holiday']:
                            shift_name = shift.name
                            if shift_name not in day_data['shifts']:
                                day_data['shifts'][shift_name] = {
                                    'shift_info': {
                                        'name': shift.name,
                                        'start_time': shift.start_time.strftime('%H:%M'),
                                        'end_time': shift.end_time.strftime('%H:%M'),
                                        'expected_hours': shift.expected_hours
                                    },
                                    'users': []
                                }

                            day_data['shifts'][shift_name]['users'].append({
                                'username': user.username,
                                'full_name': user.get_full_name()
                            })

                report_data.append(day_data)
                current_date += timedelta(days=1)

            # Calculate summary statistics
            total_days = len(report_data)
            working_days = sum(1 for day in report_data if not day['is_holiday'])
            holidays = total_days - working_days

            total_scheduled_days = sum(
                sum(len(shift_data['users']) for shift_data in day['shifts'].values())
                for day in report_data
            )

            return {
                'report_period': {
                    'start_date': start_date,
                    'end_date': end_date,
                    'total_days': total_days
                },
                'summary': {
                    'working_days': working_days,
                    'holidays': holidays,
                    'total_scheduled_days': total_scheduled_days,
                    'average_daily_assignments': round(total_scheduled_days / working_days if working_days > 0 else 0, 2)
                },
                'daily_data': report_data,
                'generated_at': timezone.now()
            }

        except Exception as e:
            self.logger.error(f"Error generating shift report: {str(e)}")
            raise

    # ============================
    # UTILITY METHODS
    # ============================

    def calculate_expected_hours(self, user: User, date: date) -> float:
        """
        Calculate expected working hours for a user on a specific date.

        Args:
            user: User object
            date: Date to calculate for

        Returns:
            Expected hours as float
        """
        try:
            if not self.is_working_day_for_user(user, date):
                return 0.0

            shift = self.get_current_shift(user, date)
            if not shift:
                return 0.0

            return shift.expected_hours

        except Exception as e:
            self.logger.error(f"Error calculating expected hours: {str(e)}")
            return 0.0

    def get_available_shifts_for_user(self, user: User, date: date) -> List[Dict[str, Any]]:
        """
        Get shifts that can be assigned to a user for a specific date.

        Args:
            user: User object
            date: Date to check availability for

        Returns:
            List of available shifts
        """
        try:
            available_shifts = []
            shifts = ShiftMaster.objects.filter(is_active=True)

            for shift in shifts:
                # Check if shift can be assigned (no conflicts)
                is_valid, message = self.validate_shift_assignment(user.id, shift.id, date)

                if is_valid:
                    available_shifts.append({
                        'id': shift.id,
                        'name': shift.name,
                        'start_time': shift.start_time.strftime('%H:%M'),
                        'end_time': shift.end_time.strftime('%H:%M'),
                        'duration': float(shift.shift_duration),
                        'work_days': shift.work_days,
                        'crosses_midnight': shift.crosses_midnight,
                        'expected_hours': shift.expected_hours
                    })

            return available_shifts

        except Exception as e:
            self.logger.error(f"Error getting available shifts for user: {str(e)}")
            return []

    def bulk_update_assignments(self, assignment_ids: List[int],
                              update_data: Dict[str, Any]) -> Tuple[int, int, List[str]]:
        """
        Bulk update multiple assignments.

        Args:
            assignment_ids: List of assignment IDs to update
            update_data: Data to update

        Returns:
            Tuple of (success_count, error_count, errors)
        """
        success_count = 0
        error_count = 0
        errors = []

        try:
            with transaction.atomic():
                for assignment_id in assignment_ids:
                    try:
                        assignment = ShiftAssignment.objects.get(id=assignment_id)

                        for field, value in update_data.items():
                            if hasattr(assignment, field):
                                setattr(assignment, field, value)

                        assignment.save()
                        success_count += 1

                    except ShiftAssignment.DoesNotExist:
                        error_count += 1
                        errors.append(f"Assignment {assignment_id} not found")
                    except Exception as e:
                        error_count += 1
                        errors.append(f"Assignment {assignment_id}: {str(e)}")

                self.logger.info(f"Bulk update completed: {success_count} successful, {error_count} failed")
                return success_count, error_count, errors

        except Exception as e:
            self.logger.error(f"Error in bulk update: {str(e)}")
            return 0, len(assignment_ids), [f"Bulk update failed: {str(e)}"]

    def get_shift_conflicts(self, start_date: date, end_date: date) -> List[Dict[str, Any]]:
        """
        Find potential shift assignment conflicts in date range.

        Args:
            start_date: Start date to check
            end_date: End date to check

        Returns:
            List of conflicts found
        """
        try:
            conflicts = []

            # Find overlapping assignments for same user
            assignments = ShiftAssignment.objects.filter(
                effective_from__lte=end_date
            ).filter(
                Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
            ).select_related('user', 'shift').order_by('user', 'effective_from')

            user_assignments = {}
            for assignment in assignments:
                user_id = assignment.user.id
                if user_id not in user_assignments:
                    user_assignments[user_id] = []
                user_assignments[user_id].append(assignment)

            # Check for overlaps within each user's assignments
            for user_id, user_assigns in user_assignments.items():
                for i, assign1 in enumerate(user_assigns):
                    for assign2 in user_assigns[i+1:]:
                        # Check if assignments overlap
                        assign1_end = assign1.effective_to or date(2099, 12, 31)
                        assign2_end = assign2.effective_to or date(2099, 12, 31)

                        if (assign1.effective_from <= assign2_end and
                            assign2.effective_from <= assign1_end):
                            conflicts.append({
                                'type': 'overlapping_assignments',
                                'user': {
                                    'id': assign1.user.id,
                                    'username': assign1.user.username
                                },
                                'assignment1': {
                                    'id': assign1.id,
                                    'shift': assign1.shift.name,
                                    'from': assign1.effective_from,
                                    'to': assign1.effective_to
                                },
                                'assignment2': {
                                    'id': assign2.id,
                                    'shift': assign2.shift.name,
                                    'from': assign2.effective_from,
                                    'to': assign2.effective_to
                                }
                            })

            return conflicts

        except Exception as e:
            self.logger.error(f"Error finding conflicts: {str(e)}")
            return []
