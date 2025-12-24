"""
Minimal Master Data Fixtures for Integration Tests

Creates essential data including leave types and shifts.
"""

from django.contrib.auth.models import User, Group
from trueAlign.models import OfficeLocation, LeaveType, ShiftMaster
from datetime import time


class MasterDataFixtures:
    """Setup minimal master data for integration tests."""
    
    @staticmethod
    def create_groups():
        """Create user groups/roles."""
        groups = {}
        group_names = ['Admin', 'HR', 'Manager', 'Employee', 'Management']
        
        for name in group_names:
            group, _ = Group.objects.get_or_create(name=name)
            groups[name.lower()] = group
        
        return groups
    
    @staticmethod
    def create_office_locations():
        """Create office locations."""
        locations = {}
        
        # Office A - Mumbai
        office_a, _ = OfficeLocation.objects.get_or_create(
            code='MUM',
            defaults={
                'name': 'Mumbai Office',
                'address_line1': 'Bandra West',
                'city': 'Mumbai',
                'state': 'Maharashtra',
                'postal_code': '400050',
                'country': 'India',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 0),
                'working_hours_end': time(18, 0),
                'is_active': True
            }
        )
        locations['office_a'] = office_a
        
        # Office B - Pune
        office_b, _ = OfficeLocation.objects.get_or_create(
            code='PUN',
            defaults={
                'name': 'Pune Office',
                'address_line1': 'Hinjewadi Phase 1',
                'city': 'Pune',
                'state': 'Maharashtra',
                'postal_code': '411057',
                'country': 'India',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 0),
                'working_hours_end': time(18, 0),
                'is_active': True
            }
        )
        locations['office_b'] = office_b
        
        return locations
    
    @staticmethod
    def create_leave_types():
        """Create leave types with correct fields."""
        leave_types = {}
        
        # Annual Leave
        annual, _ = LeaveType.objects.get_or_create(
            name='Annual Leave',
            defaults={
                'description': 'Annual paid leave',
                'is_paid': True,
                'requires_approval': True,
                'is_active': True,
                'max_days_allowed': 20,
                'can_be_half_day': True,
                'carry_forward_allowed': True
            }
        )
        leave_types['annual'] = annual
        
        # Sick Leave
        sick, _ = LeaveType.objects.get_or_create(
            name='Sick Leave',
            defaults={
                'description': 'Sick leave',
                'is_paid': True,
                'requires_approval': True,
                'requires_documentation': True,
                'is_active': True,
                'max_days_allowed': 12,
                'can_be_half_day': True
            }
        )
        leave_types['sick'] = sick
        
        # Casual Leave
        casual, _ = LeaveType.objects.get_or_create(
            name='Casual Leave',
            defaults={
                'description': 'Casual leave',
                'is_paid': True,
                'requires_approval': True,
                'is_active': True,
                'max_days_allowed': 10,
                'can_be_half_day': True
            }
        )
        leave_types['casual'] = casual
        
        return leave_types
    
    @staticmethod
    def create_shifts():
        """Create shift masters with correct fields."""
        shifts = {}
        
        # Morning Shift
        morning, _ = ShiftMaster.objects.get_or_create(
            name='Morning Shift',
            defaults={
                'start_time': time(9, 0),
                'end_time': time(18, 0),
                'is_active': True
            }
        )
        shifts['morning'] = morning
        
        # Evening Shift
        evening, _ = ShiftMaster.objects.get_or_create(
            name='Evening Shift',
            defaults={
                'start_time': time(13, 0),
                'end_time': time(22, 0),
                'is_active': True
            }
        )
        shifts['evening'] = evening
        
        return shifts
    
    @classmethod
    def setup_all_fixtures(cls):
        """Setup all master data fixtures."""
        fixtures = {}
        
        # Create groups (roles)
        fixtures['groups'] = cls.create_groups()
        
        # Create office locations
        fixtures['locations'] = cls.create_office_locations()
        
        # Create leave types
        fixtures['leave_types'] = cls.create_leave_types()
        
        # Create shifts
        fixtures['shifts'] = cls.create_shifts()
        
        # Empty placeholders for other optional fixtures
        fixtures['conference_rooms'] = {}
        
        return fixtures
