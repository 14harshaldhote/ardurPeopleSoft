"""
Business Logic Services for Shift Management
Provides high-level operations and business rules
"""

from django.db import transaction
from django.utils import timezone
from django.contrib.auth.models import User
from datetime import datetime, timedelta, date
from decimal import Decimal
import logging

from .models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule
from .validators import ShiftAssignmentValidator, BulkAssignmentValidator

logger = logging.getLogger(__name__)


class ShiftService:
    """Service for shift master operations"""
    
    @staticmethod
    def create_shift(shift_data, created_by=None):
        """Create a new shift with validation"""
        shift = ShiftMaster(**shift_data)
        if created_by:
            shift.created_by = created_by
        
        shift.save()
        logger.info(f"Shift created: {shift.name} by {created_by}")
        return shift
    
    @staticmethod
    def duplicate_shift(shift_id, new_name=None, created_by=None):
        """Duplicate an existing shift"""
        original_shift = ShiftMaster.objects.get(id=shift_id)
        
        if not new_name:
            new_name = f"{original_shift.name} (Copy)"
            counter = 1
            while ShiftMaster.objects.filter(name=new_name).exists():
                new_name = f"{original_shift.name} (Copy {counter})"
                counter += 1
        
        new_shift = ShiftMaster.objects.create(
            name=new_name,
            shift_type=original_shift.shift_type,
            start_time=original_shift.start_time,
            end_time=original_shift.end_time,
            shift_duration=original_shift.shift_duration,
            break_duration=original_shift.break_duration,
            grace_period_in=original_shift.grace_period_in,
            grace_period_out=original_shift.grace_period_out,
            work_days=original_shift.work_days,
            custom_work_days=original_shift.custom_work_days,
            min_rest_hours=original_shift.min_rest_hours,
            max_consecutive_days=original_shift.max_consecutive_days,
            overtime_threshold=original_shift.overtime_threshold,
            color_code=original_shift.color_code,
            description=f"Duplicated from {original_shift.name}",
            created_by=created_by
        )
        
        logger.info(f"Shift duplicated: {original_shift.name} -> {new_shift.name}")
        return new_shift
    
    @staticmethod
    def get_shift_utilization(shift_id, start_date=None, end_date=None):
        """Get shift utilization statistics"""
        shift = ShiftMaster.objects.get(id=shift_id)
        
        if not start_date:
            start_date = timezone.now().date() - timedelta(days=30)
        if not end_date:
            end_date = timezone.now().date()
        
        assignments = ShiftAssignment.objects.filter(
            shift=shift,
            effective_from__lte=end_date,
            status__in=['ACTIVE', 'APPROVED']
        ).filter(
            Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
        )
        
        total_days = (end_date - start_date).days + 1
        assigned_days = sum(
            min(assignment.effective_to or end_date, end_date) - 
            max(assignment.effective_from, start_date)
            for assignment in assignments
        ).days
        
        utilization_rate = (assigned_days / total_days) * 100 if total_days > 0 else 0
        
        return {
            'shift': shift,
            'period': {'start_date': start_date, 'end_date': end_date},
            'total_assignments': assignments.count(),
            'unique_users': assignments.values('user').distinct().count(),
            'utilization_rate': round(utilization_rate, 2),
            'total_days': total_days,
            'assigned_days': assigned_days
        }


class ShiftAssignmentService:
    """Service for shift assignment operations"""
    
    @staticmethod
    @transaction.atomic
    def create_assignment(assignment_data, created_by=None):
        """Create a single shift assignment with full validation"""
        assignment = ShiftAssignment(**assignment_data)
        if created_by:
            assignment.created_by = created_by
        
        # Run validation
        validator = ShiftAssignmentValidator(assignment)
        warnings = validator.validate()
        
        # Save assignment
        assignment.save()
        
        # Check for conflicts and create conflict records
        conflicts = ConflictDetectionService.detect_conflicts(assignment)
        
        logger.info(f"Assignment created: {assignment} by {created_by}")
        
        return {
            'assignment': assignment,
            'warnings': warnings,
            'conflicts': conflicts
        }
    
    @staticmethod
    @transaction.atomic
    def bulk_create_assignments(assignments_data, created_by=None):
        """Create multiple assignments with batch validation"""
        # Validate entire batch
        validator = BulkAssignmentValidator(assignments_data)
        warnings = validator.validate()
        
        created_assignments = []
        all_conflicts = []
        
        for data in assignments_data:
            assignment = ShiftAssignment(
                user_id=data['user_id'],
                shift_id=data['shift_id'],
                effective_from=data['effective_from'],
                effective_to=data.get('effective_to'),
                notes=data.get('notes', ''),
                created_by=created_by
            )
            assignment.save()
            created_assignments.append(assignment)
            
            # Detect conflicts for each assignment
            conflicts = ConflictDetectionService.detect_conflicts(assignment)
            all_conflicts.extend(conflicts)
        
        logger.info(f"Bulk assignment created: {len(created_assignments)} assignments by {created_by}")
        
        return {
            'assignments': created_assignments,
            'warnings': warnings,
            'conflicts': all_conflicts
        }
    
    @staticmethod
    def reassign_shift(assignment_id, new_shift_id, effective_from=None, reason=""):
        """Reassign user to a different shift"""
        assignment = ShiftAssignment.objects.get(id=assignment_id)
        new_shift = ShiftMaster.objects.get(id=new_shift_id)
        
        if not effective_from:
            effective_from = timezone.now().date()
        
        # End current assignment
        if assignment.effective_to is None or assignment.effective_to > effective_from:
            assignment.effective_to = effective_from - timedelta(days=1)
            assignment.is_current = False
            assignment.save()
        
        # Create new assignment
        new_assignment_data = {
            'user': assignment.user,
            'shift': new_shift,
            'effective_from': effective_from,
            'notes': f"Reassigned from {assignment.shift.name}. Reason: {reason}",
            'created_by': assignment.created_by
        }
        
        result = ShiftAssignmentService.create_assignment(new_assignment_data)
        
        logger.info(f"Shift reassigned: {assignment.user.username} from {assignment.shift.name} to {new_shift.name}")
        
        return result
    
    @staticmethod
    def get_user_shift_timeline(user_id, start_date=None, end_date=None):
        """Get complete shift timeline for a user"""
        if not start_date:
            start_date = timezone.now().date() - timedelta(days=365)
        if not end_date:
            end_date = timezone.now().date() + timedelta(days=365)
        
        assignments = ShiftAssignment.objects.filter(
            user_id=user_id,
            effective_from__lte=end_date
        ).filter(
            Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
        ).select_related('shift').order_by('effective_from')
        
        timeline = []
        for assignment in assignments:
            timeline.append({
                'assignment': assignment,
                'start_date': max(assignment.effective_from, start_date),
                'end_date': min(assignment.effective_to or end_date, end_date),
                'duration_days': assignment.duration_days,
                'is_current': assignment.is_current,
                'status': assignment.status
            })
        
        return timeline
    
    @staticmethod
    def get_team_assignments(date_obj=None, team_ids=None):
        """Get all team assignments for a specific date"""
        if date_obj is None:
            date_obj = timezone.now().date()
        
        assignments = ShiftAssignment.get_active_assignments(date_obj)
        
        if team_ids:
            assignments = assignments.filter(user__groups__id__in=team_ids)
        
        # Group by shift
        shift_assignments = {}
        for assignment in assignments:
            shift_name = assignment.shift.name
            if shift_name not in shift_assignments:
                shift_assignments[shift_name] = {
                    'shift': assignment.shift,
                    'assignments': [],
                    'total_users': 0
                }
            
            shift_assignments[shift_name]['assignments'].append(assignment)
            shift_assignments[shift_name]['total_users'] += 1
        
        return {
            'date': date_obj,
            'shift_assignments': shift_assignments,
            'total_assignments': assignments.count()
        }


class ConflictDetectionService:
    """Service for detecting and managing shift conflicts"""
    
    @staticmethod
    def detect_conflicts(assignment):
        """Detect all types of conflicts for an assignment"""
        conflicts = []
        
        # Check overlapping assignments
        overlap_conflict = ConflictDetectionService._check_overlap_conflict(assignment)
        if overlap_conflict:
            conflicts.append(overlap_conflict)
        
        # Check rest period violations
        rest_conflict = ConflictDetectionService._check_rest_period_conflict(assignment)
        if rest_conflict:
            conflicts.append(rest_conflict)
        
        # Check maximum hours violations
        hours_conflict = ConflictDetectionService._check_max_hours_conflict(assignment)
        if hours_conflict:
            conflicts.append(hours_conflict)
        
        # Check role restrictions
        role_conflict = ConflictDetectionService._check_role_restriction_conflict(assignment)
        if role_conflict:
            conflicts.append(role_conflict)
        
        return conflicts
    
    @staticmethod
    def _check_overlap_conflict(assignment):
        """Check for overlapping assignments"""
        overlapping = ShiftAssignment.objects.filter(
            user=assignment.user,
            status__in=['ACTIVE', 'APPROVED'],
            effective_from__lte=assignment.effective_to or timezone.now().date()
        ).filter(
            Q(effective_to__gte=assignment.effective_from) | Q(effective_to__isnull=True)
        ).exclude(id=assignment.id if assignment.id else None).first()
        
        if overlapping:
            conflict = ShiftConflict.objects.create(
                assignment=assignment,
                conflicting_assignment=overlapping,
                conflict_type='OVERLAP',
                severity='HIGH',
                description=f'Assignment overlaps with existing assignment: {overlapping}'
            )
            return conflict
        
        return None
    
    @staticmethod
    def _check_rest_period_conflict(assignment):
        """Check for rest period violations"""
        min_rest_hours = assignment.shift.min_rest_hours
        if not min_rest_hours:
            return None
        
        # Check previous assignment
        previous = ShiftAssignment.objects.filter(
            user=assignment.user,
            effective_to__lt=assignment.effective_from,
            status__in=['ACTIVE', 'APPROVED']
        ).order_by('-effective_to').first()
        
        if previous and previous.effective_to:
            rest_hours = (assignment.effective_from - previous.effective_to).days * 24
            if rest_hours < min_rest_hours:
                conflict = ShiftConflict.objects.create(
                    assignment=assignment,
                    conflicting_assignment=previous,
                    conflict_type='REST_VIOLATION',
                    severity='MEDIUM',
                    description=f'Only {rest_hours} hours rest, minimum {min_rest_hours} required'
                )
                return conflict
        
        return None
    
    @staticmethod
    def _check_max_hours_conflict(assignment):
        """Check for maximum hours violations"""
        # Implementation for checking daily/weekly hour limits
        # This would involve calculating total hours for the period
        return None
    
    @staticmethod
    def _check_role_restriction_conflict(assignment):
        """Check for role-based restrictions"""
        # Implementation for role-based shift restrictions
        # This would check user groups against shift requirements
        return None
    
    @staticmethod
    def resolve_conflict(conflict_id, resolved_by, resolution_notes=""):
        """Resolve a specific conflict"""
        conflict = ShiftConflict.objects.get(id=conflict_id)
        conflict.resolve(resolved_by, resolution_notes)
        
        logger.info(f"Conflict resolved: {conflict} by {resolved_by}")
        return conflict
    
    @staticmethod
    def get_conflict_summary(start_date=None, end_date=None):
        """Get summary of conflicts for a period"""
        if not start_date:
            start_date = timezone.now().date() - timedelta(days=30)
        if not end_date:
            end_date = timezone.now().date()
        
        conflicts = ShiftConflict.objects.filter(
            created_at__date__range=[start_date, end_date]
        )
        
        summary = {
            'total_conflicts': conflicts.count(),
            'unresolved_conflicts': conflicts.filter(is_resolved=False).count(),
            'by_type': {},
            'by_severity': {},
            'resolution_rate': 0
        }
        
        # Group by type
        for conflict_type, _ in ShiftConflict.CONFLICT_TYPES:
            count = conflicts.filter(conflict_type=conflict_type).count()
            summary['by_type'][conflict_type] = count
        
        # Group by severity
        for severity, _ in ShiftConflict.CONFLICT_SEVERITY:
            count = conflicts.filter(severity=severity).count()
            summary['by_severity'][severity] = count
        
        # Calculate resolution rate
        if summary['total_conflicts'] > 0:
            resolved_count = conflicts.filter(is_resolved=True).count()
            summary['resolution_rate'] = round(
                (resolved_count / summary['total_conflicts']) * 100, 2
            )
        
        return summary


class ReportingService:
    """Service for generating shift reports"""
    
    @staticmethod
    def generate_assignment_report(start_date, end_date, user_ids=None, shift_ids=None):
        """Generate comprehensive assignment report"""
        assignments = ShiftAssignment.objects.filter(
            effective_from__gte=start_date,
            effective_from__lte=end_date
        ).select_related('user', 'shift', 'created_by')
        
        if user_ids:
            assignments = assignments.filter(user_id__in=user_ids)
        if shift_ids:
            assignments = assignments.filter(shift_id__in=shift_ids)
        
        # Calculate statistics
        stats = {
            'total_assignments': assignments.count(),
            'unique_users': assignments.values('user').distinct().count(),
            'unique_shifts': assignments.values('shift').distinct().count(),
            'by_status': {},
            'by_shift_type': {},
            'average_duration': 0
        }
        
        # Group by status
        for status, _ in ShiftAssignment.ASSIGNMENT_STATUS:
            count = assignments.filter(status=status).count()
            stats['by_status'][status] = count
        
        # Group by shift type
        for shift_type, _ in ShiftMaster.SHIFT_TYPES:
            count = assignments.filter(shift__shift_type=shift_type).count()
            stats['by_shift_type'][shift_type] = count
        
        # Calculate average duration
        durations = [a.duration_days for a in assignments if a.duration_days]
        if durations:
            stats['average_duration'] = round(sum(durations) / len(durations), 1)
        
        return {
            'period': {'start_date': start_date, 'end_date': end_date},
            'statistics': stats,
            'assignments': assignments
        }
    
    @staticmethod
    def generate_utilization_report(start_date, end_date):
        """Generate shift utilization report"""
        shifts = ShiftMaster.objects.filter(is_active=True)
        utilization_data = []
        
        for shift in shifts:
            utilization = ShiftService.get_shift_utilization(
                shift.id, start_date, end_date
            )
            utilization_data.append(utilization)
        
        # Sort by utilization rate
        utilization_data.sort(key=lambda x: x['utilization_rate'], reverse=True)
        
        return {
            'period': {'start_date': start_date, 'end_date': end_date},
            'shift_utilization': utilization_data,
            'summary': {
                'total_shifts': len(utilization_data),
                'average_utilization': round(
                    sum(u['utilization_rate'] for u in utilization_data) / len(utilization_data), 2
                ) if utilization_data else 0
            }
        }
    
    @staticmethod
    def get_dashboard_statistics():
        """Get statistics for dashboard"""
        today = timezone.now().date()
        
        return {
            'shifts': {
                'total': ShiftMaster.objects.count(),
                'active': ShiftMaster.objects.filter(is_active=True).count(),
            },
            'assignments': {
                'total': ShiftAssignment.objects.count(),
                'active_today': ShiftAssignment.get_active_assignments(today).count(),
                'pending_approval': ShiftAssignment.objects.filter(status='PENDING').count(),
                'expiring_soon': ShiftAssignment.objects.filter(
                    effective_to__range=[today, today + timedelta(days=7)]
                ).count(),
            },
            'conflicts': {
                'total': ShiftConflict.objects.count(),
                'unresolved': ShiftConflict.objects.filter(is_resolved=False).count(),
                'high_priority': ShiftConflict.objects.filter(
                    severity='HIGH', is_resolved=False
                ).count(),
            },
            'users': {
                'with_active_shifts': ShiftAssignment.objects.filter(
                    effective_from__lte=today,
                    status__in=['ACTIVE', 'APPROVED']
                ).filter(
                    Q(effective_to__gte=today) | Q(effective_to__isnull=True)
                ).values('user').distinct().count(),
            }
        }
