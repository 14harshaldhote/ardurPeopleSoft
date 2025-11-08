"""
Test Data Factories for Attendance System Testing
Generates realistic test data for users, shifts, sessions, and attendance
"""

from datetime import datetime, timedelta, time
from decimal import Decimal
import pytz
from django.contrib.auth.models import User, Group
from django.utils import timezone
from trueAlign.models import (
    UserSession, ShiftMaster, ShiftAssignment,
    Attendance, Holiday, UserDetails
)


IST = pytz.timezone('Asia/Kolkata')


class TestUserFactory:
    """Factory for creating test users"""
    
    @staticmethod
    def create_user(username, email=None, first_name="Test", last_name="User"):
        """Create a basic test user"""
        if email is None:
            email = f"{username}@test.com"
        
        user = User.objects.create_user(
            username=username,
            email=email,
            password="testpass123",
            first_name=first_name,
            last_name=last_name
        )
        
        # Create UserDetails if it doesn't exist
        try:
            UserDetails.objects.get_or_create(
                user=user,
                defaults={
                    'phone_number': '1234567890',
                    'emergency_contact_number': '09876543210',
                }
            )
        except:
            pass  # Handle if UserDetails model structure is different
        
        return user
    
    @staticmethod
    def create_multiple_users(count=10):
        """Create multiple test users"""
        users = []
        for i in range(1, count + 1):
            user = TestUserFactory.create_user(
                username=f"testuser{i}",
                first_name=f"Test{i}",
                last_name=f"User{i}"
            )
            users.append(user)
        return users
    
    @staticmethod
    def create_hr_user():
        """Create an HR user"""
        user = TestUserFactory.create_user("hr_test", first_name="HR", last_name="Manager")
        hr_group, _ = Group.objects.get_or_create(name='HR')
        user.groups.add(hr_group)
        return user


class TestShiftFactory:
    """Factory for creating test shifts"""
    
    @staticmethod
    def create_day_shift(name="Day Shift"):
        """Create a standard day shift (9 AM - 5 PM)"""
        shift = ShiftMaster.objects.create(
            name=name,
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            break_duration=timedelta(minutes=30),
            grace_period=timedelta(minutes=15),
            work_days='Weekdays',
            is_active=True
        )
        return shift
    
    @staticmethod
    def create_night_shift(name="Night Shift"):
        """Create a night shift (10 PM - 6 AM)"""
        shift = ShiftMaster.objects.create(
            name=name,
            start_time=time(22, 0),
            end_time=time(6, 0),
            shift_duration=Decimal('8.0'),
            break_duration=timedelta(minutes=30),
            grace_period=timedelta(minutes=15),
            work_days='All Days',
            is_active=True
        )
        return shift
    
    @staticmethod
    def create_custom_shift(name="Custom Shift", start_hour=12, duration=9):
        """Create a custom shift"""
        start = time(start_hour, 0)
        end_hour = (start_hour + duration) % 24
        end = time(end_hour, 0)
        
        shift = ShiftMaster.objects.create(
            name=name,
            start_time=start,
            end_time=end,
            shift_duration=Decimal(str(duration)),
            break_duration=timedelta(minutes=45),
            grace_period=timedelta(minutes=10),
            work_days='Weekdays',
            is_active=True
        )
        return shift
    
    @staticmethod
    def create_all_shifts():
        """Create all standard shift types"""
        day = TestShiftFactory.create_day_shift()
        night = TestShiftFactory.create_night_shift()
        custom = TestShiftFactory.create_custom_shift()
        return {'day': day, 'night': night, 'custom': custom}


class TestShiftAssignmentFactory:
    """Factory for creating shift assignments"""
    
    @staticmethod
    def assign_shift_to_user(user, shift, effective_from=None, effective_to=None):
        """Assign a shift to a user"""
        if effective_from is None:
            # Set to 5 days ago (within the 7-day validation limit)
            effective_from = timezone.now().date() - timedelta(days=5)
        
        assignment = ShiftAssignment.objects.create(
            user=user,
            shift=shift,
            effective_from=effective_from,
            effective_to=effective_to,
            is_current=True,
            notes="Test assignment"
        )
        return assignment
    
    @staticmethod
    def assign_shifts_to_users(users, shifts):
        """Assign shifts to multiple users (distribute evenly)"""
        shift_list = list(shifts.values())
        assignments = []
        
        for i, user in enumerate(users):
            shift = shift_list[i % len(shift_list)]
            assignment = TestShiftAssignmentFactory.assign_shift_to_user(user, shift)
            assignments.append(assignment)
        
        return assignments


class TestSessionFactory:
    """Factory for creating test sessions"""
    
    @staticmethod
    def create_session(user, date=None, login_hour=9, logout_hour=17, 
                      location_type="Office", idle_minutes=0):
        """Create a complete user session"""
        if date is None:
            date = timezone.now().date()
        
        # Create login and logout times in IST
        login_time = timezone.make_aware(
            datetime.combine(date, time(login_hour, 0)),
            IST
        )
        
        # Handle cases where logout_hour might be > 23 from night shift calculation
        actual_logout_hour = logout_hour % 24
        logout_time = timezone.make_aware(
            datetime.combine(date, time(actual_logout_hour, 0)),
            IST
        )
        # If logout is earlier (next day) or hour was >= 24, add a day
        if logout_hour < login_hour or logout_hour >= 24:
            logout_time += timedelta(days=1)
        
        session = UserSession.objects.create(
            user=user,
            login_time=login_time,
            logout_time=logout_time,
            is_active=False,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            browser="Chrome",
            os="Windows 10",
            device_type="Desktop",
            screen_resolution="1920x1080",
            location_type=location_type,
            location_city="Mumbai",
            location_country="India",
            total_idle_time=timedelta(minutes=idle_minutes)
        )
        
        return session
    
    @staticmethod
    def create_multiple_sessions_same_day(user, date, sessions_data):
        """
        Create multiple sessions for same day
        sessions_data: list of dicts with login_hour, logout_hour
        """
        sessions = []
        for data in sessions_data:
            session = TestSessionFactory.create_session(
                user=user,
                date=date,
                login_hour=data.get('login_hour', 9),
                logout_hour=data.get('logout_hour', 17),
                location_type=data.get('location_type', 'Office'),
                idle_minutes=data.get('idle_minutes', 0)
            )
            sessions.append(session)
        return sessions
    
    @staticmethod
    def create_late_session(user, date, shift, late_minutes=30):
        """Create a session where user arrives late"""
        shift_start_hour = shift.start_time.hour
        shift_start_minute = shift.start_time.minute
        shift_end_hour = shift.end_time.hour
        
        # Calculate late arrival time
        login_time_obj = time(shift_start_hour, shift_start_minute) 
        login_datetime = datetime.combine(date, login_time_obj)
        login_datetime += timedelta(minutes=late_minutes)
        
        return TestSessionFactory.create_session(
            user=user,
            date=date,
            login_hour=login_datetime.hour,
            logout_hour=shift_end_hour
        )
    
    @staticmethod
    def create_overtime_session(user, date, shift, overtime_hours=2):
        """Create a session where user works overtime"""
        shift_start_hour = shift.start_time.hour
        shift_end_hour = shift.end_time.hour
        
        # Calculate overtime end
        overtime_end = (shift_end_hour + overtime_hours) % 24
        
        return TestSessionFactory.create_session(
            user=user,
            date=date,
            login_hour=shift_start_hour,
            logout_hour=overtime_end
        )


class TestHolidayFactory:
    """Factory for creating holidays"""
    
    @staticmethod
    def create_holiday(date, name="Test Holiday"):
        """Create a holiday"""
        holiday = Holiday.objects.create(
            date=date,
            name=name,
            recurring_yearly=False  # Test holidays don't recur
        )
        return holiday


class TestDataGenerator:
    """Master generator for creating complete test scenarios"""
    
    @staticmethod
    def setup_complete_test_environment():
        """Set up a complete test environment with users, shifts, and assignments"""
        print("🚀 Setting up test environment...")
        
        # Create users
        print("  📝 Creating 10 test users...")
        users = TestUserFactory.create_multiple_users(10)
        hr_user = TestUserFactory.create_hr_user()
        
        # Create shifts
        print("  ⏰ Creating shifts (Day, Night, Custom)...")
        shifts = TestShiftFactory.create_all_shifts()
        
        # Assign shifts to users
        print("  🔗 Assigning shifts to users...")
        assignments = TestShiftAssignmentFactory.assign_shifts_to_users(users, shifts)
        
        # Create a holiday
        tomorrow = timezone.now().date() + timedelta(days=1)
        print(f"  🎉 Creating holiday on {tomorrow}...")
        holiday = TestHolidayFactory.create_holiday(tomorrow, "Test Holiday")
        
        print("✅ Test environment setup complete!")
        
        return {
            'users': users,
            'hr_user': hr_user,
            'shifts': shifts,
            'assignments': assignments,
            'holiday': holiday
        }
    
    @staticmethod
    def cleanup_test_data():
        """Clean up all test data"""
        print("🧹 Cleaning up test data...")
        
        # Delete in reverse order of dependencies
        Attendance.objects.filter(user__username__startswith='testuser').delete()
        Attendance.objects.filter(user__username='hr_test').delete()
        UserSession.objects.filter(user__username__startswith='testuser').delete()
        ShiftAssignment.objects.filter(user__username__startswith='testuser').delete()
        Holiday.objects.filter(name__contains='Test').delete()
        ShiftMaster.objects.filter(name__contains='Shift').delete()
        User.objects.filter(username__startswith='testuser').delete()
        User.objects.filter(username='hr_test').delete()
        
        print("✅ Cleanup complete!")
