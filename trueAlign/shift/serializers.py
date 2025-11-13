"""
Serializers for Shift Management API
Provides comprehensive serialization with validation
"""

from rest_framework import serializers
from django.contrib.auth.models import User, Group
from .models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule
from .validators import ShiftAssignmentValidator, BulkAssignmentValidator


class UserBasicSerializer(serializers.ModelSerializer):
    """Basic user serializer for shift assignments"""
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'full_name', 'email']


class ShiftValidationRuleSerializer(serializers.ModelSerializer):
    """Serializer for shift validation rules"""
    group_name = serializers.CharField(source='group.name', read_only=True)
    
    class Meta:
        model = ShiftValidationRule
        fields = '__all__'


class ShiftMasterSerializer(serializers.ModelSerializer):
    """Comprehensive shift master serializer"""
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    working_days_display = serializers.SerializerMethodField()
    shift_type_display = serializers.CharField(source='get_shift_type_display', read_only=True)
    work_days_display = serializers.CharField(source='get_work_days_display', read_only=True)
    expected_work_hours = serializers.DecimalField(max_digits=5, decimal_places=2, read_only=True)
    crosses_midnight = serializers.BooleanField(read_only=True)
    is_night_shift = serializers.SerializerMethodField()
    active_assignments_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ShiftMaster
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at', 'created_by']
    
    def get_working_days_display(self, obj):
        """Get formatted working days"""
        try:
            return obj.get_working_days()
        except:
            return []
    
    def get_is_night_shift(self, obj):
        """Check if it's a night shift"""
        return obj.is_night_shift()
    
    def get_active_assignments_count(self, obj):
        """Get count of active assignments"""
        return obj.assignments.filter(status__in=['ACTIVE', 'APPROVED']).count()
    
    def validate(self, data):
        """Custom validation"""
        # Create temporary instance for validation
        instance = ShiftMaster(**data)
        if self.instance:
            for attr, value in data.items():
                setattr(self.instance, attr, value)
            instance = self.instance
        
        try:
            instance.clean()
        except Exception as e:
            raise serializers.ValidationError(str(e))
        
        return data


class ShiftMasterListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for shift list views"""
    shift_type_display = serializers.CharField(source='get_shift_type_display', read_only=True)
    active_assignments_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ShiftMaster
        fields = [
            'id', 'name', 'shift_type', 'shift_type_display', 'start_time', 
            'end_time', 'shift_duration', 'is_active', 'color_code',
            'active_assignments_count'
        ]
    
    def get_active_assignments_count(self, obj):
        return obj.assignments.filter(status__in=['ACTIVE', 'APPROVED']).count()


class ShiftAssignmentSerializer(serializers.ModelSerializer):
    """Comprehensive shift assignment serializer"""
    user_details = UserBasicSerializer(source='user', read_only=True)
    shift_details = ShiftMasterListSerializer(source='shift', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    approved_by_name = serializers.CharField(source='approved_by.get_full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    # Computed fields
    is_active_assignment = serializers.BooleanField(read_only=True)
    duration_days = serializers.IntegerField(read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = ShiftAssignment
        fields = '__all__'
        read_only_fields = [
            'created_at', 'updated_at', 'created_by', 'assignment_hash',
            'approved_by', 'approved_at'
        ]
    
    def validate(self, data):
        """Custom validation using validator"""
        # Create temporary instance for validation
        instance = ShiftAssignment(**data)
        if self.instance:
            for attr, value in data.items():
                setattr(self.instance, attr, value)
            instance = self.instance
        
        validator = ShiftAssignmentValidator(instance)
        try:
            warnings = validator.validate()
            # Store warnings in context for later use
            if warnings:
                self.context['warnings'] = warnings
        except Exception as e:
            raise serializers.ValidationError(str(e))
        
        return data
    
    def create(self, validated_data):
        """Create with proper user assignment"""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class ShiftAssignmentListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for assignment list views"""
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    shift_name = serializers.CharField(source='shift.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = ShiftAssignment
        fields = [
            'id', 'user', 'user_name', 'shift', 'shift_name', 
            'effective_from', 'effective_to', 'status', 'status_display',
            'is_current', 'days_remaining'
        ]


class BulkShiftAssignmentSerializer(serializers.Serializer):
    """Serializer for bulk shift assignments"""
    assignments = serializers.ListField(
        child=serializers.DictField(),
        min_length=1,
        max_length=1000
    )
    
    def validate_assignments(self, value):
        """Validate bulk assignments"""
        validator = BulkAssignmentValidator(value)
        try:
            warnings = validator.validate()
            self.context['warnings'] = warnings
        except Exception as e:
            raise serializers.ValidationError(str(e))
        
        return value
    
    def create(self, validated_data):
        """Create bulk assignments"""
        from .models import ShiftAssignment
        
        assignments_data = validated_data['assignments']
        created_by = self.context['request'].user
        
        return ShiftAssignment.bulk_assign_shifts(assignments_data, created_by)


class ShiftConflictSerializer(serializers.ModelSerializer):
    """Serializer for shift conflicts"""
    assignment_details = ShiftAssignmentListSerializer(source='assignment', read_only=True)
    conflicting_assignment_details = ShiftAssignmentListSerializer(
        source='conflicting_assignment', read_only=True
    )
    conflict_type_display = serializers.CharField(source='get_conflict_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    resolved_by_name = serializers.CharField(source='resolved_by.get_full_name', read_only=True)
    
    class Meta:
        model = ShiftConflict
        fields = '__all__'
        read_only_fields = ['created_at', 'resolved_by', 'resolved_at']


class ShiftAssignmentApprovalSerializer(serializers.Serializer):
    """Serializer for assignment approval/rejection"""
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        if data['action'] == 'reject' and not data.get('reason'):
            raise serializers.ValidationError({
                'reason': 'Reason is required when rejecting an assignment.'
            })
        return data


class ShiftCalendarSerializer(serializers.Serializer):
    """Serializer for shift calendar view"""
    date = serializers.DateField()
    user_id = serializers.IntegerField(required=False)
    shift_id = serializers.IntegerField(required=False)
    
    def validate_date(self, value):
        from datetime import date
        if value < date.today() - timedelta(days=365):
            raise serializers.ValidationError("Date cannot be more than 1 year in the past")
        if value > date.today() + timedelta(days=365):
            raise serializers.ValidationError("Date cannot be more than 1 year in the future")
        return value


class ShiftReportSerializer(serializers.Serializer):
    """Serializer for shift reports"""
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        allow_empty=True
    )
    shift_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        allow_empty=True
    )
    include_conflicts = serializers.BooleanField(default=False)
    
    def validate(self, data):
        if data['end_date'] < data['start_date']:
            raise serializers.ValidationError({
                'end_date': 'End date must be after start date.'
            })
        
        # Limit report range to 1 year
        if (data['end_date'] - data['start_date']).days > 365:
            raise serializers.ValidationError({
                'date_range': 'Report range cannot exceed 1 year.'
            })
        
        return data


class ShiftStatisticsSerializer(serializers.Serializer):
    """Serializer for shift statistics"""
    total_shifts = serializers.IntegerField(read_only=True)
    active_shifts = serializers.IntegerField(read_only=True)
    total_assignments = serializers.IntegerField(read_only=True)
    active_assignments = serializers.IntegerField(read_only=True)
    pending_approvals = serializers.IntegerField(read_only=True)
    conflicts_count = serializers.IntegerField(read_only=True)
    users_with_shifts = serializers.IntegerField(read_only=True)
    
    # Shift type breakdown
    shift_type_breakdown = serializers.DictField(read_only=True)
    assignment_status_breakdown = serializers.DictField(read_only=True)
    
    # Recent activity
    recent_assignments = ShiftAssignmentListSerializer(many=True, read_only=True)
    recent_conflicts = ShiftConflictSerializer(many=True, read_only=True)
