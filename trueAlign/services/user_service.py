# services/user_service.py
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg, Sum
from django.utils import timezone
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class UserService:
    """Service class for user-related operations and statistics"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_active_users(self) -> List[User]:
        """Get all active users with their profile information"""
        try:
            return User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).select_related('profile').order_by('first_name', 'last_name')
        except Exception as e:
            self.logger.error(f"Error fetching active users: {str(e)}")
            return []
    
    def get_users_by_location(self, location: str = None) -> List[User]:
        """Get users filtered by location"""
        try:
            queryset = User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).select_related('profile')
            
            if location:
                queryset = queryset.filter(profile__work_location=location)
            
            return queryset.order_by('first_name', 'last_name')
        except Exception as e:
            self.logger.error(f"Error fetching users by location {location}: {str(e)}")
            return []
    
    def get_all_locations(self) -> List[str]:
        """Get all unique work locations"""
        try:
            locations = User.objects.filter(
                is_active=True,
                profile__employment_status='active',
                profile__work_location__isnull=False
            ).values_list('profile__work_location', flat=True).distinct()
            
            return [loc for loc in locations if loc and loc.strip()]
        except Exception as e:
            self.logger.error(f"Error fetching locations: {str(e)}")
            return []
    
    def get_user_basic_info(self, user_id: int) -> Dict[str, Any]:
        """Get basic user information for display"""
        try:
            user = User.objects.select_related('profile').get(id=user_id)
            return {
                'id': user.id,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email': user.email,
                'location': getattr(user.profile, 'work_location', 'N/A') if hasattr(user, 'profile') else 'N/A',
                'employee_type': getattr(user.profile, 'employee_type', 'N/A') if hasattr(user, 'profile') else 'N/A',
                'employment_status': getattr(user.profile, 'employment_status', 'N/A') if hasattr(user, 'profile') else 'N/A'
            }
        except User.DoesNotExist:
            self.logger.warning(f"User with id {user_id} not found")
            return {}
        except Exception as e:
            self.logger.error(f"Error fetching user info for id {user_id}: {str(e)}")
            return {}
    
    def get_users_with_shifts(self, date: datetime.date = None) -> List[Dict[str, Any]]:
        """Get users with their current shift information"""
        try:
            from ..models import ShiftAssignment  # Import here to avoid circular imports
            
            if not date:
                date = timezone.now().date()
            
             # Get current shift assignments
            shift_assignments = ShiftAssignment.objects.filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=date),
                effective_from__lte=date,
                is_current=True
            ).select_related('user', 'user__profile', 'shift')
            
            users_with_shifts = []
            for assignment in shift_assignments:
                user_info = self.get_user_basic_info(assignment.user.id)
                user_info.update({
                    'shift_name': assignment.shift.name,
                    'shift_start_time': assignment.shift.start_time,
                    'shift_end_time': assignment.shift.end_time,
                    'shift_duration': assignment.shift.shift_duration,
                    'grace_period': assignment.shift.grace_period.total_seconds() / 60  # in minutes
                })
                users_with_shifts.append(user_info)
            
            return users_with_shifts
            
        except Exception as e:
            self.logger.error(f"Error fetching users with shifts: {str(e)}")
            return []
    
    def search_users(self, search_term: str) -> List[Dict[str, Any]]:
        """Search users by name, email, or employee ID"""
        try:
            if not search_term or len(search_term.strip()) < 2:
                return []
            
            search_term = search_term.strip()
            
            users = User.objects.filter(
                Q(first_name__icontains=search_term) |
                Q(last_name__icontains=search_term) |
                Q(username__icontains=search_term) |
                Q(email__icontains=search_term),
                is_active=True
            ).select_related('profile')[:50]  # Limit results
            
            return [self.get_user_basic_info(user.id) for user in users]
            
        except Exception as e:
            self.logger.error(f"Error searching users with term '{search_term}': {str(e)}")
            return []
    
    def get_total_employee_count(self) -> int:
        """Get total count of active employees"""
        try:
            return User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).count()
        except Exception as e:
            self.logger.error(f"Error getting total employee count: {str(e)}")
            return 0
    
    def get_location_wise_employee_count(self) -> Dict[str, int]:
        """Get employee count grouped by location"""
        try:
            location_counts = User.objects.filter(
                is_active=True,
                profile__employment_status='active',
                profile__work_location__isnull=False
            ).values('profile__work_location').annotate(
                count=Count('id')
            ).order_by('profile__work_location')
            
            return {
                item['profile__work_location']: item['count'] 
                for item in location_counts 
                if item['profile__work_location']
            }
        except Exception as e:
            self.logger.error(f"Error getting location-wise employee count: {str(e)}")
            return {}
    
    def get_employment_type_distribution(self) -> Dict[str, int]:
        """Get distribution of employees by employment type"""
        try:
            type_counts = User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).values('profile__employee_type').annotate(
                count=Count('id')
            ).order_by('profile__employee_type')
            
            return {
                item['profile__employee_type'] or 'Not Specified': item['count']
                for item in type_counts
            }
        except Exception as e:
            self.logger.error(f"Error getting employment type distribution: {str(e)}")
            return {}
    
    def get_users_by_employment_status(self, status: str = 'active') -> List[User]:
        """Get users filtered by employment status"""
        try:
            return User.objects.filter(
                is_active=True,
                profile__employment_status=status
            ).select_related('profile').order_by('first_name', 'last_name')
        except Exception as e:
            self.logger.error(f"Error fetching users by employment status {status}: {str(e)}")
            return []
    
    def get_new_joiners(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get users who joined in the last N days"""
        try:
            cutoff_date = timezone.now().date() - timedelta(days=days)
            
            new_users = User.objects.filter(
                is_active=True,
                profile__start_date__gte=cutoff_date
            ).select_related('profile').order_by('-profile__start_date')
            
            return [
                {
                    **self.get_user_basic_info(user.id),
                    'start_date': user.profile.start_date,
                    'days_since_joining': (timezone.now().date() - user.profile.start_date).days
                }
                for user in new_users if hasattr(user, 'profile') and user.profile.start_date
            ]
        except Exception as e:
            self.logger.error(f"Error fetching new joiners: {str(e)}")
            return []
    
    def get_users_on_probation(self) -> List[Dict[str, Any]]:
        """Get users currently on probation"""
        try:
            probation_users = User.objects.filter(
                is_active=True,
                profile__employment_status='probation'
            ).select_related('profile').order_by('profile__probation_end_date')
            
            return [
                {
                    **self.get_user_basic_info(user.id),
                    'probation_end_date': user.profile.probation_end_date,
                    'days_remaining': (user.profile.probation_end_date - timezone.now().date()).days if user.profile.probation_end_date else None
                }
                for user in probation_users if hasattr(user, 'profile')
            ]
        except Exception as e:
            self.logger.error(f"Error fetching users on probation: {str(e)}")
            return []
    
    def validate_user_exists(self, user_id: int) -> bool:
        """Validate if user exists and is active"""
        try:
            return User.objects.filter(
                id=user_id,
                is_active=True
            ).exists()
        except Exception as e:
            self.logger.error(f"Error validating user {user_id}: {str(e)}")
            return False
    
    def get_user_contact_info(self, user_id: int) -> Dict[str, Any]:
        """Get user contact information"""
        try:
            user = User.objects.select_related('profile').get(id=user_id)
            if not hasattr(user, 'profile'):
                return {}
            
            return {
                'primary_contact': user.profile.contact_number_primary,
                'personal_email': user.profile.personal_email,
                'company_email': user.profile.company_email,
                'emergency_contact_name': user.profile.emergency_contact_name,
                'emergency_contact_number': user.profile.emergency_contact_number,
                'emergency_contact_relationship': user.profile.emergency_contact_relationship
            }
        except User.DoesNotExist:
            return {}
        except Exception as e:
            self.logger.error(f"Error fetching contact info for user {user_id}: {str(e)}")
            return {}