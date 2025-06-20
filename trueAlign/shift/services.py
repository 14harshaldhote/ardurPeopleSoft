# services/shift_service.py
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg, Sum, Case, When, IntegerField, F
from django.utils import timezone
from datetime import datetime, timedelta, time
from typing import Dict, List, Optional, Any, Tuple
import logging
from decimal import Decimal
import pytz

logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

class ShiftService:
    """Service class for shift-related operations and management"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_all_shifts(self, include_inactive=False):
        """Get all shifts with optional filtering for active only"""
        try:
            from ..models import ShiftMaster  # Import here to avoid circular imports
            
            queryset = ShiftMaster.objects.all()
            if not include_inactive:
                queryset = queryset.filter(is_active=True)
                
            return queryset.order_by('name')
        except Exception as e:
            self.logger.error(f"Error fetching shifts: {str(e)}")
            return []
    
    def get_shift_by_id(self, shift_id: int):
        """Get shift by ID"""
        try:
            from ..models import ShiftMaster
            return ShiftMaster.objects.get(id=shift_id)
        except Exception as e:
            self.logger.error(f"Error fetching shift with ID {shift_id}: {str(e)}")
            return None
    
    def get_shift_assignments(self, user_id=None, active_only=True, date=None):
        """Get shift assignments with optional filtering"""
        try:
            from ..models import ShiftAssignment
            
            if date is None:
                date = timezone.now().date()
                
            queryset = ShiftAssignment.objects.select_related('user', 'shift')
            
            if user_id:
                queryset = queryset.filter(user_id=user_id)
                
            if active_only:
                queryset = queryset.filter(
                    Q(effective_to__isnull=True) | Q(effective_to__gte=date),
                    effective_from__lte=date
                )
                
            return queryset.order_by('-effective_from')
        except Exception as e:
            self.logger.error(f"Error fetching shift assignments: {str(e)}")
            return []
    
    def get_users_without_shifts(self, date=None):
        """Get users who don't have any shift assignment"""
        try:
            from ..models import ShiftAssignment
            
            if date is None:
                date = timezone.now().date()
            
            # Get users with active shift assignments
            users_with_shifts = ShiftAssignment.objects.filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=date),
                effective_from__lte=date
            ).values_list('user_id', flat=True).distinct()
            
            # Get active users without shift assignments
            users_without_shifts = User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).exclude(id__in=users_with_shifts)
            
            return users_without_shifts.select_related('profile').order_by('first_name', 'last_name')
        except Exception as e:
            self.logger.error(f"Error fetching users without shifts: {str(e)}")
            return []
    
    def create_shift(self, shift_data: Dict[str, Any]):
        """Create a new shift"""
        try:
            from ..models import ShiftMaster
            
            shift = ShiftMaster.objects.create(**shift_data)
            return shift
        except Exception as e:
            self.logger.error(f"Error creating shift: {str(e)}")
            return None
    
    def update_shift(self, shift_id: int, shift_data: Dict[str, Any]):
        """Update an existing shift"""
        try:
            from ..models import ShiftMaster
            
            shift = ShiftMaster.objects.get(id=shift_id)
            for key, value in shift_data.items():
                setattr(shift, key, value)
            shift.save()
            return shift
        except Exception as e:
            self.logger.error(f"Error updating shift with ID {shift_id}: {str(e)}")
            return None
    
    def assign_shift_to_user(self, user_id: int, shift_id: int, effective_from: datetime.date, effective_to: Optional[datetime.date] = None):
        """Assign a shift to a user"""
        try:
            from ..models import ShiftAssignment
            
            # Create new assignment
            assignment = ShiftAssignment.objects.create(
                user_id=user_id,
                shift_id=shift_id,
                effective_from=effective_from,
                effective_to=effective_to,
                is_current=True
            )
            
            return assignment
        except Exception as e:
            self.logger.error(f"Error assigning shift to user: {str(e)}")
            return None
    
    def end_shift_assignment(self, assignment_id: int, end_date: datetime.date):
        """End a shift assignment by setting effective_to date"""
        try:
            from ..models import ShiftAssignment
            
            assignment = ShiftAssignment.objects.get(id=assignment_id)
            assignment.effective_to = end_date
            assignment.is_current = False
            assignment.save()
            
            return assignment
        except Exception as e:
            self.logger.error(f"Error ending shift assignment with ID {assignment_id}: {str(e)}")
            return None
    
    def get_shift_history(self, user_id: int):
        """Get shift assignment history for a user"""
        try:
            from ..models import ShiftAssignment
            
            return ShiftAssignment.objects.filter(
                user_id=user_id
            ).select_related('shift').order_by('-effective_from')
        except Exception as e:
            self.logger.error(f"Error fetching shift history for user {user_id}: {str(e)}")
            return []
    
    def get_upcoming_shift_changes(self, days: int = 7):
        """Get shift assignments ending in the next N days"""
        try:
            from ..models import ShiftAssignment
            
            today = timezone.now().date()
            end_date = today + timedelta(days=days)
            
            return ShiftAssignment.objects.filter(
                effective_to__range=[today, end_date]
            ).select_related('user', 'shift').order_by('effective_to')
        except Exception as e:
            self.logger.error(f"Error fetching upcoming shift changes: {str(e)}")
            return []
    
    def get_shift_statistics(self):
        """Get statistics about shift distribution"""
        try:
            from ..models import ShiftAssignment, ShiftMaster
            
            today = timezone.now().date()
            
            # Get active shift assignments
            active_assignments = ShiftAssignment.objects.filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=today),
                effective_from__lte=today
            ).select_related('shift')
            
            # Count users per shift
            shift_counts = active_assignments.values('shift__name').annotate(
                user_count=Count('user_id', distinct=True)
            ).order_by('-user_count')
            
            # Get total active users
            total_users = User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).count()
            
            # Get users without shifts
            users_without_shifts = total_users - sum(item['user_count'] for item in shift_counts)
            
            return {
                'shift_distribution': list(shift_counts),
                'total_users': total_users,
                'users_without_shifts': users_without_shifts
            }
        except Exception as e:
            self.logger.error(f"Error calculating shift statistics: {str(e)}")
            return {
                'shift_distribution': [],
                'total_users': 0,
                'users_without_shifts': 0
            }
    
    def get_holidays(self, year=None):
        """Get holidays for a specific year or all holidays"""
        try:
            from ..models import Holiday
            
            queryset = Holiday.objects.all()
            
            if year:
                queryset = queryset.filter(
                    Q(date__year=year) | Q(recurring_yearly=True)
                )
                
            return queryset.order_by('date')
        except Exception as e:
            self.logger.error(f"Error fetching holidays: {str(e)}")
            return []
    
    def create_holiday(self, holiday_data: Dict[str, Any]):
        """Create a new holiday"""
        try:
            from ..models import Holiday
            
            holiday = Holiday.objects.create(**holiday_data)
            return holiday
        except Exception as e:
            self.logger.error(f"Error creating holiday: {str(e)}")
            return None