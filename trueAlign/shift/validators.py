"""
Multi-layered Validation System for Shift Management
Provides comprehensive validation with performance optimization
"""

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models import Q
from datetime import timedelta, date
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)


class ValidationLevel:
    """Validation level constants"""
    BASIC = 1
    CONFLICT = 2
    BUSINESS = 3
    ADVANCED = 4


class BaseValidator:
    """Base validator with common functionality"""
    
    def __init__(self, instance):
        self.instance = instance
        self.errors = {}
        self.warnings = []
    
    def validate(self):
        """Run all validation levels"""
        self._validate_level_1_basic()
        self._validate_level_2_conflicts()
        self._validate_level_3_business()
        self._validate_level_4_advanced()
        
        if self.errors:
            raise ValidationError(self.errors)
        
        return self.warnings
    
    def _validate_level_1_basic(self):
        """Level 1: Basic data validation"""
        pass
    
    def _validate_level_2_conflicts(self):
        """Level 2: Conflict detection"""
        pass
    
    def _validate_level_3_business(self):
        """Level 3: Business rules"""
        pass
    
    def _validate_level_4_advanced(self):
        """Level 4: Advanced validations"""
        pass


class ShiftAssignmentValidator(BaseValidator):
    """Comprehensive shift assignment validator"""
    
    def _validate_level_1_basic(self):
        """Basic field validation"""
        if not self.instance.user:
            self.errors['user'] = 'User is required.'
        
        if not self.instance.shift:
            self.errors['shift'] = 'Shift is required.'
        
        if not self.instance.effective_from:
            self.errors['effective_from'] = 'Effective from date is required.'
        
        # Date range validation
        if self.instance.effective_from and self.instance.effective_to:
            if self.instance.effective_to <= self.instance.effective_from:
                self.errors['effective_to'] = 'End date must be after start date.'
        
        # Past date validation
        if self.instance.effective_from:
            today = timezone.now().date()
            if self.instance.effective_from < (today - timedelta(days=7)):
                self.errors['effective_from'] = 'Assignment cannot be more than 7 days in the past.'
    
    def _validate_level_2_conflicts(self):
        """Conflict detection validation"""
        if not (self.instance.user and self.instance.effective_from):
            return
        
        # Check for overlapping assignments
        overlapping = self._check_overlapping_assignments()
        if overlapping:
            self.errors['__all__'] = f'Overlapping assignment: {overlapping}'
        
        # Check shift status
        if self.instance.shift and not self.instance.shift.is_active:
            self.errors['shift'] = 'Cannot assign inactive shift.'
    
    def _validate_level_3_business(self):
        """Business rules validation"""
        if not self.instance.shift:
            return
        
        # Rest period validation
        rest_violation = self._check_rest_period_violation()
        if rest_violation:
            self.warnings.append(f'Rest period warning: {rest_violation}')
        
        # Maximum hours validation
        hours_violation = self._check_daily_hours_limit()
        if hours_violation:
            self.warnings.append(f'Daily hours warning: {hours_violation}')
    
    def _validate_level_4_advanced(self):
        """Advanced role and team validations"""
        if not self.instance.user:
            return
        
        # Role-based validation
        role_violation = self._check_role_restrictions()
        if role_violation:
            self.errors['__all__'] = f'Role restriction: {role_violation}'
        
        # Team capacity validation
        capacity_warning = self._check_team_capacity()
        if capacity_warning:
            self.warnings.append(f'Team capacity: {capacity_warning}')
    
    def _check_overlapping_assignments(self):
        """Check for overlapping assignments"""
        from .models import ShiftAssignment
        
        queryset = ShiftAssignment.objects.filter(
            user=self.instance.user,
            status__in=['ACTIVE', 'APPROVED'],
            effective_from__lte=self.instance.effective_to or timezone.now().date()
        )
        
        if self.instance.effective_to:
            queryset = queryset.filter(effective_to__gte=self.instance.effective_from)
        else:
            queryset = queryset.filter(
                Q(effective_to__gte=self.instance.effective_from) | Q(effective_to__isnull=True)
            )
        
        if self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)
        
        overlapping = queryset.first()
        if overlapping:
            end_date = overlapping.effective_to or 'ongoing'
            return f"{overlapping.shift.name} from {overlapping.effective_from} to {end_date}"
        
        return None
    
    def _check_rest_period_violation(self):
        """Check minimum rest period between shifts"""
        from .models import ShiftAssignment
        
        min_rest_hours = self.instance.shift.min_rest_hours
        if not min_rest_hours:
            return None
        
        # Check previous assignment
        previous = ShiftAssignment.objects.filter(
            user=self.instance.user,
            effective_to__lt=self.instance.effective_from,
            status__in=['ACTIVE', 'APPROVED']
        ).order_by('-effective_to').first()
        
        if previous and previous.effective_to:
            rest_hours = (self.instance.effective_from - previous.effective_to).days * 24
            if rest_hours < min_rest_hours:
                return f'Only {rest_hours} hours rest, minimum {min_rest_hours} required'
        
        return None
    
    def _check_daily_hours_limit(self):
        """Check daily working hours limit"""
        # Implementation for daily hours check
        return None
    
    def _check_role_restrictions(self):
        """Check role-based shift restrictions"""
        # Implementation for role restrictions
        return None
    
    def _check_team_capacity(self):
        """Check team capacity constraints"""
        # Implementation for team capacity
        return None


class BulkAssignmentValidator:
    """Validator for bulk shift assignments"""
    
    def __init__(self, assignments_data):
        self.assignments_data = assignments_data
        self.errors = []
        self.warnings = []
    
    def validate(self):
        """Validate bulk assignments"""
        self._validate_data_format()
        self._validate_individual_assignments()
        self._validate_batch_conflicts()
        
        if self.errors:
            raise ValidationError({'bulk_errors': self.errors})
        
        return self.warnings
    
    def _validate_data_format(self):
        """Validate input data format"""
        if not isinstance(self.assignments_data, list):
            self.errors.append('Assignments data must be a list')
            return
        
        if len(self.assignments_data) > 1000:
            self.errors.append('Maximum 1000 assignments allowed per batch')
        
        required_fields = ['user_id', 'shift_id', 'effective_from']
        for i, data in enumerate(self.assignments_data):
            for field in required_fields:
                if field not in data:
                    self.errors.append(f'Assignment {i+1}: Missing {field}')
    
    def _validate_individual_assignments(self):
        """Validate each assignment individually"""
        from .models import ShiftAssignment
        
        for i, data in enumerate(self.assignments_data):
            try:
                assignment = ShiftAssignment(
                    user_id=data['user_id'],
                    shift_id=data['shift_id'],
                    effective_from=data['effective_from'],
                    effective_to=data.get('effective_to')
                )
                validator = ShiftAssignmentValidator(assignment)
                validator.validate()
            except ValidationError as e:
                self.errors.append(f'Assignment {i+1}: {e}')
    
    def _validate_batch_conflicts(self):
        """Check for conflicts within the batch"""
        user_assignments = {}
        
        for i, data in enumerate(self.assignments_data):
            user_id = data['user_id']
            if user_id not in user_assignments:
                user_assignments[user_id] = []
            user_assignments[user_id].append((i, data))
        
        # Check for overlaps within batch
        for user_id, assignments in user_assignments.items():
            if len(assignments) > 1:
                self._check_batch_overlaps(assignments)
    
    def _check_batch_overlaps(self, assignments):
        """Check overlaps within batch for same user"""
        for i, (idx1, data1) in enumerate(assignments):
            for idx2, data2 in assignments[i+1:]:
                if self._assignments_overlap(data1, data2):
                    self.errors.append(
                        f'Assignments {idx1+1} and {idx2+1} overlap for same user'
                    )
    
    def _assignments_overlap(self, data1, data2):
        """Check if two assignments overlap"""
        start1, end1 = data1['effective_from'], data1.get('effective_to')
        start2, end2 = data2['effective_from'], data2.get('effective_to')
        
        # If either has no end date, they overlap if start dates are same
        if not end1 or not end2:
            return start1 == start2
        
        # Check date range overlap
        return start1 <= end2 and start2 <= end1


class PerformanceValidator:
    """Performance-optimized validation for large datasets"""
    
    @staticmethod
    def validate_assignments_batch(assignments, batch_size=100):
        """Validate assignments in batches for performance"""
        results = {'errors': [], 'warnings': []}
        
        for i in range(0, len(assignments), batch_size):
            batch = assignments[i:i + batch_size]
            try:
                validator = BulkAssignmentValidator(batch)
                warnings = validator.validate()
                results['warnings'].extend(warnings)
            except ValidationError as e:
                results['errors'].extend(e.message_dict.get('bulk_errors', []))
        
        return results
    
    @staticmethod
    def preload_validation_data():
        """Preload data for faster validation"""
        from .models import ShiftMaster, ShiftValidationRule
        
        # Cache active shifts
        active_shifts = {
            shift.id: shift for shift in 
            ShiftMaster.objects.filter(is_active=True)
        }
        
        # Cache validation rules
        validation_rules = {
            rule.rule_type: rule for rule in 
            ShiftValidationRule.objects.filter(is_active=True)
        }
        
        return {
            'shifts': active_shifts,
            'rules': validation_rules
        }
