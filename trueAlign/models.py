from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.utils.timezone import now
from django.conf import settings
from django.dispatch import receiver
from datetime import time, timedelta, date


IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

'''------------------------- CLINET PROFILE --------------------'''
class ClientProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='client_profile')
    company_name = models.CharField(max_length=100)
    contact_info = models.TextField()
    
    # Professional Level Details
    industry_type = models.CharField(max_length=100)  # Industry type the company belongs to
    company_size = models.CharField(
        max_length=50, 
        choices=[('Small', 'Small'), ('Medium', 'Medium'), ('Large', 'Large')],  # Company size categories
        default='Small'
    )
    registration_number = models.CharField(max_length=50, blank=True, null=True)  # Business registration number
    business_location = models.CharField(max_length=255, blank=True, null=True)  # Location of the business
    website_url = models.URLField(blank=True, null=True)  # Company website URL
    year_established = models.IntegerField(blank=True, null=True)  # Year the company was established
    annual_revenue = models.DecimalField(
        max_digits=15, decimal_places=2, blank=True, null=True
    )  # Annual revenue of the company (optional field)

    def __str__(self):
        return self.company_name
    
'''------------------------- USERSESSION --------------------'''
from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
import random
import string

class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)  # Added missing field
    login_time = models.DateTimeField(default=timezone.now)
    logout_time = models.DateTimeField(null=True, blank=True)
    working_hours = models.DurationField(null=True, blank=True)
    idle_time = models.DurationField(default=timedelta(0))
    last_activity = models.DateTimeField(default=timezone.now)
    location = models.CharField(max_length=50, null=True, blank=True)
    session_duration = models.FloatField(null=True, blank=True)  # Added missing field for duration in minutes
    # Add is_active flag for easier querying
    is_active = models.BooleanField(default=True)

    # Define constants at the model level
    IDLE_THRESHOLD_MINUTES = 1
    SESSION_TIMEOUT_MINUTES = 30
    OFFICE_IPS = ['116.75.62.90']

    class Meta:
        indexes = [
            models.Index(fields=['user', 'login_time']),
            # Add index for faster lookups
            models.Index(fields=['is_active']),
        ]

    @staticmethod
    def generate_session_key():
        """Generate a unique session key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=40))

    @classmethod
    def get_or_create_session(cls, user, session_key=None, ip_address=None, user_agent=None):
        """Get existing active session or create new one"""
        from django.db import transaction
        
        with transaction.atomic():
            current_time = timezone.now()
            
            # Look for an active session
            existing_session = cls.objects.filter(
                user=user,
                is_active=True
            ).select_for_update().first()

            if existing_session:
                # If the user has been inactive for more than 30 minutes, end the session and create a new one
                if (current_time - existing_session.last_activity) > timedelta(minutes=cls.SESSION_TIMEOUT_MINUTES):
                    existing_session.end_session()
                    session_key = session_key or cls.generate_session_key()
                    return cls.objects.create(
                        user=user,
                        session_key=session_key,
                        ip_address=ip_address,
                        user_agent=user_agent,  # Added user_agent
                        last_activity=current_time,
                        is_active=True
                    )
                else:
                    # Update last activity and continue with the same session
                    existing_session.update_activity(current_time)
                    return existing_session
            
            # If no active session, create a new session
            if not session_key:
                session_key = cls.generate_session_key()
                
            new_session = cls.objects.create(
                user=user,
                session_key=session_key,
                ip_address=ip_address,
                user_agent=user_agent,  # Added user_agent
                last_activity=current_time,
                is_active=True
            )
            
            # Set location
            new_session.location = new_session.determine_location()
            new_session.save(update_fields=['location'])
            
            return new_session

    def determine_location(self):
        """Determine if the user is working from home or office based on IP address."""
        if not self.ip_address:
            return 'Unknown'
            
        ip = self.ip_address.strip()
        print(f"Determining location for IP: {ip}")
        
        return 'Office' if ip in self.OFFICE_IPS else 'Home'

    def update_activity(self, current_time=None):
        """Update the last activity timestamp and calculate idle time"""
        from django.db import transaction
        
        with transaction.atomic():
            current_time = current_time or timezone.now()
            
            # Calculate idle time since last activity
            time_since_last_activity = current_time - self.last_activity
            
            # If more than threshold, add to idle time
            if time_since_last_activity > timedelta(minutes=self.IDLE_THRESHOLD_MINUTES):
                # Use F() expression for atomic update
                from django.db.models import F
                UserSession.objects.filter(pk=self.pk).update(
                    idle_time=F('idle_time') + time_since_last_activity,
                    last_activity=current_time
                )
                # Refresh to get the updated values
                self.refresh_from_db()
            else:
                # Just update last activity
                self.last_activity = current_time
                self.save(update_fields=['last_activity'])
            
            return self

    def end_session(self, logout_time=None):
        """End the current session"""
        if not self.is_active:
            return self
            
        from django.db import transaction
        
        with transaction.atomic():
            logout_time = logout_time or timezone.now()
            
            # Calculate final idle time
            time_since_last_activity = logout_time - self.last_activity
            
            # Add final idle time if needed
            if time_since_last_activity > timedelta(minutes=self.IDLE_THRESHOLD_MINUTES):
                from django.db.models import F
                UserSession.objects.filter(pk=self.pk).update(
                    idle_time=F('idle_time') + time_since_last_activity
                )
                # Refresh to get the updated idle_time
                self.refresh_from_db(fields=['idle_time'])
            
            # Set logout time
            self.logout_time = logout_time
            self.is_active = False
            
            # Calculate working hours
            total_duration = logout_time - self.login_time
            self.working_hours = total_duration - self.idle_time
            
            # Calculate session duration in minutes
            self.session_duration = (logout_time - self.login_time).total_seconds() / 60
            
            self.save(update_fields=['logout_time', 'is_active', 'working_hours', 'session_duration'])
            
            return self
            
    def save(self, *args, **kwargs):
        # Remove complex business logic from save method
        if not self.pk and not self.location:
            self.location = self.determine_location()
            
        super().save(*args, **kwargs)

'''---------- ATTENDANCE AREA ----------'''
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Q, Sum, Avg
from datetime import timedelta
import calendar
class Leave(models.Model):
    LEAVE_TYPES = [
        ('Sick Leave', 'Sick Leave'),
        ('Casual Leave', 'Casual Leave'), 
        ('Loss of Pay', 'Loss of Pay'),
        ('Emergency', 'Emergency')
    ]

    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'), 
        ('Cancelled', 'Cancelled')
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    half_day = models.BooleanField(default=False)
    leave_days = models.DecimalField(max_digits=4, decimal_places=1, default=0)  # Changed to have default=0
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(User, related_name='leave_approvals', on_delete=models.SET_NULL, null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    suggested_dates = models.JSONField(null=True, blank=True)
    documentation = models.FileField(upload_to='leave_docs/', null=True, blank=True)
    is_retroactive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'start_date', 'status']),
        ]

    def clean(self):
        if self.start_date > self.end_date:
            raise ValidationError("End date must be after start date")
        
        # Check for overlapping leaves
        overlapping_leaves = Leave.objects.filter(
            status='Approved',
            start_date__lte=self.end_date,
            end_date__gte=self.start_date,
            user=self.user
        ).exclude(id=self.id)
        
        if overlapping_leaves.exists():
            raise ValidationError("You already have approved leave during this period")

    def auto_convert_leave_type(self):
        """Auto convert leave type based on balance"""
        balance = self.get_leave_balance(self.user)
        
        if self.leave_type == 'Sick Leave' and balance['total_leaves'] < self.leave_days:
            self.leave_type = 'Loss of Pay'

    def calculate_leave_days(self):
        if not (self.start_date and self.end_date):
            return 0
            
        total_days = 0
        current_date = self.start_date
        while current_date <= self.end_date:
            # Skip only Sundays unless emergency leave
            if current_date.weekday() != 6 or self.leave_type == 'Emergency':
                # For half day leave requests, count each day as 0.5
                if self.half_day:
                    total_days += 0.5
                else:
                    total_days += 1.0
            current_date += timedelta(days=1)
            
        return total_days

    def save(self, *args, **kwargs):
        # Convert half_day string to boolean if needed
        if isinstance(self.half_day, str):
            self.half_day = self.half_day.lower() == 'true'
            
        # Recalculate leave days on every save to ensure accuracy
        self.leave_days = self.calculate_leave_days()
            
        if not self.pk:  # New leave request
            self.auto_convert_leave_type()
            
        super().save(*args, **kwargs)
        
        if self.status == 'Approved':
            self.update_attendance()

    def update_attendance(self):
        """Update attendance records for approved leave period"""
        current_date = self.start_date
        while current_date <= self.end_date:
            if current_date.weekday() != 6:  # All days except Sunday
                defaults = {
                    'status': 'On Leave',
                    'leave_type': self.leave_type,
                    'is_half_day': self.half_day
                }
                    
                Attendance.objects.update_or_create(
                    user=self.user,
                    date=current_date,
                    defaults=defaults
                )
            current_date += timedelta(days=1)

    @classmethod
    def get_leave_balance(cls, user):
        """Calculate leave balance from total 18 leaves per year"""
        year = timezone.now().year
        month = timezone.now().month
        
        # Total annual leave allocation is 18
        TOTAL_ANNUAL_LEAVES = 18.0
        
        # Get used leaves - include all counted leave types
        used_leaves = float(cls.objects.filter(
            user=user,
            status='Approved',
            start_date__year=year,
            leave_type__in=['Sick Leave', 'Casual Leave', 'Half Day', 'Emergency']
        ).aggregate(
            total=Sum('leave_days')
        )['total'] or 0)
        
        # Calculate comp off balance
        comp_off_balance = float(cls.get_comp_off_balance(user))
        
        # Calculate loss of pay leaves - maintain separate tracking
        loss_of_pay = float(cls.objects.filter(
            user=user,
            status='Approved',
            leave_type='Loss of Pay',
            start_date__year=year
        ).aggregate(
            total=Sum('leave_days')
        )['total'] or 0)
        
        # Calculate total available leaves
        total_available = TOTAL_ANNUAL_LEAVES - used_leaves + comp_off_balance
        
        return {
            'total_leaves': total_available,
            'used_leaves': used_leaves,
            'comp_off': comp_off_balance,
            'loss_of_pay': loss_of_pay
        }

    @classmethod
    def get_comp_off_balance(cls, user):
        """Track comp-off earned and used"""
        year = timezone.now().year
        
        earned = float(Attendance.objects.filter(
            user=user,
            date__year=year,
            is_weekend=True,
            status='Present'
        ).count())
        
        used = float(cls.objects.filter(
            user=user,
            leave_type='Comp Off',
            status='Approved',
            start_date__year=year
        ).aggregate(total=Sum('leave_days'))['total'] or 0)
        
        return earned - used
    
# First, let's create a ShiftMaster model to define different shifts
class ShiftMaster(models.Model):
    SHIFT_CHOICES = [
        ('Day Shift', 'Day Shift'),  # 9:00 AM to 5:30 PM (8.5 hours)
        ('Night Shift', 'Night Shift'),  # After 6:30 PM (9 hours)
        ('Custom Shift', 'Custom Shift')  # For any other shift pattern
    ]
    WORK_DAYS_CHOICES = [
        ('Weekdays', 'Monday to Friday'),
        ('All Days', 'Monday to Saturday'), 
        ('Custom', 'Custom Days')
    ]
    name = models.CharField(max_length=50)
    start_time = models.TimeField()
    end_time = models.TimeField()
    shift_duration = models.DecimalField(max_digits=5, decimal_places=2, default=8.0)
    break_duration = models.DurationField(default=timedelta(minutes=30))
    grace_period = models.DurationField(default=timedelta(minutes=15))
    work_days = models.CharField(max_length=20, choices=WORK_DAYS_CHOICES, default='Weekdays')
    # Increased max_length to 255 to handle longer custom day lists
    custom_work_days = models.CharField(max_length=255, null=True, blank=True,
                                      help_text="Comma-separated day names (Monday,Tuesday,etc.)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Shift"
        verbose_name_plural = "Shifts"

    @property
    def crosses_midnight(self):
        """Determine if the shift crosses midnight"""
        return self.end_time < self.start_time

    @property
    def working_days_list(self):
        """Return a list of working days (0=Monday, 6=Sunday)"""
        weekday_map = {
            'Monday': 0, 'Tuesday': 1, 'Wednesday': 2, 
            'Thursday': 3, 'Friday': 4, 'Saturday': 5, 'Sunday': 6
        }
        
        if self.work_days == 'Weekdays':
            return [0, 1, 2, 3, 4]  # Monday to Friday
        elif self.work_days == 'All Days':
            return [0, 1, 2, 3, 4, 5]  # Monday to Saturday
        elif self.work_days == 'Custom' and self.custom_work_days:
            try:
                # Parse day names from custom_work_days
                day_names = [day.strip() for day in self.custom_work_days.split(',')]
                return [weekday_map[day] for day in day_names if day in weekday_map]
            except (ValueError, KeyError):
                return [0, 1, 2, 3, 4]  # Default to weekdays if parsing fails
        return [0, 1, 2, 3, 4]  # Default to weekdays

    def is_working_day(self, date):
        """Check if the given date is a working day for this shift"""
        return date.weekday() in self.working_days_list

    def is_within_shift_hours(self, datetime_obj, date):
        """Check if a datetime is within shift hours considering date boundaries"""
        # Create datetime objects for shift start and end on the given date
        start_datetime = timezone.make_aware(
            timezone.datetime.combine(date, self.start_time)
        )
        
        # If shift crosses midnight, end_datetime should be on the next day
        end_date = date
        if self.crosses_midnight:
            end_date = date + timedelta(days=1)
        
        end_datetime = timezone.make_aware(
            timezone.datetime.combine(end_date, self.end_time)
        )
        
        return start_datetime <= datetime_obj <= end_datetime

    def expected_hours(self):
        """Calculate expected working hours for this shift"""
        # Convert break duration from timedelta to hours as decimal
        break_hours = self.break_duration.total_seconds() / 3600
        return self.shift_duration - break_hours

    def __str__(self):
        return f"{self.name} ({self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')})"

    def save(self, *args, **kwargs):
        # Set default times and durations based on shift type
        if self.name == 'Day Shift' and not self.start_time and not self.end_time:
            self.start_time = time(9, 0)  # 9:00 AM
            self.end_time = time(17, 30)  # 5:30 PM (8.5 hours)
            self.shift_duration = 8.5
            self.work_days = 'All Days'  # Monday to Saturday
        elif self.name == 'Night Shift' and not self.start_time and not self.end_time:
            self.start_time = time(18, 30)  # 6:30 PM
            self.end_time = time(3, 30)    # 3:30 AM (9 hours)
            self.shift_duration = 9.0
            self.work_days = 'Weekdays'  # Monday to Friday
        
        # Calculate shift duration if not provided
        if not self.shift_duration:
            # Calculate hours between start and end time
            if self.crosses_midnight:
                # For shifts crossing midnight
                midnight = time(0, 0)
                hours_before_midnight = (24 - self.start_time.hour - self.start_time.minute/60)
                hours_after_midnight = self.end_time.hour + self.end_time.minute/60
                self.shift_duration = round(hours_before_midnight + hours_after_midnight, 2)
            else:
                # For regular shifts
                hours = self.end_time.hour - self.start_time.hour
                minutes = self.end_time.minute - self.start_time.minute
                self.shift_duration = round(hours + minutes/60, 2)
        
        super().save(*args, **kwargs)

# Now, let's add a holiday model to properly track holidays
class Holiday(models.Model):
    name = models.CharField(max_length=100)
    date = models.DateField()
    recurring_yearly = models.BooleanField(default=True, help_text="If True, this holiday occurs on the same date every year")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Holiday"
        verbose_name_plural = "Holidays"

    def __str__(self):
        return f"{self.name} ({self.date.strftime('%d-%b')})"

    @classmethod
    def is_holiday(cls, date):
        """Check if a given date is a holiday"""
        # Check for exact date match
        if cls.objects.filter(date=date).exists():
            return True
        
        # Check for recurring yearly holidays (same month and day)
        if cls.objects.filter(
            recurring_yearly=True,
            date__month=date.month,
            date__day=date.day
        ).exists():
            return True
        
        return False

# Now, let's enhance the shift assignment model to assign shifts to employees
class ShiftAssignment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    shift = models.ForeignKey(ShiftMaster, on_delete=models.CASCADE)
    effective_from = models.DateField()
    effective_to = models.DateField(null=True, blank=True)
    is_current = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Shift Assignment"
        verbose_name_plural = "Shift Assignments"
        indexes = [
            models.Index(fields=['user', 'effective_from']),
            models.Index(fields=['is_current']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.shift.name} (from {self.effective_from})"

    def save(self, *args, **kwargs):
        # Convert effective_from to a proper date object if it's a string
        if isinstance(self.effective_from, str):
            self.effective_from = timezone.datetime.strptime(self.effective_from, '%Y-%m-%d').date()
        
        # If this is a new current assignment, make all other assignments for this user not current
        if self.is_current:
            # Get other current assignments for this user
            other_assignments = ShiftAssignment.objects.filter(
                user=self.user,
                is_current=True
            ).exclude(id=self.id if self.id else None)
            
            # Update each assignment individually to prevent type errors
            for assignment in other_assignments:
                assignment.is_current = False
                assignment.effective_to = self.effective_from - timedelta(days=1)
                assignment.save(update_fields=['is_current', 'effective_to'])
        
        super().save(*args, **kwargs)

    @classmethod
    def get_user_current_shift(cls, user, date=None):
        """Get the user's assigned shift for a specific date or current date if not specified"""
        if date is None:
            date = timezone.now().date()
        
        # Try to find an active assignment for the given date
        assignment = cls.objects.filter(
            user=user,
            effective_from__lte=date,
            effective_to__isnull=True
        ).select_related('shift').first()
        
        if not assignment:
            # Try with effective_to date for completed assignments
            assignment = cls.objects.filter(
                user=user,
                effective_from__lte=date,
                effective_to__gte=date
            ).select_related('shift').first()
        
        if not assignment:
            # If no assignment found, get most recent assignment
            assignment = cls.objects.filter(
                user=user,
                effective_from__lte=date
            ).order_by('-effective_from').select_related('shift').first()
        
        # If still no assignment, return default Day Shift
        if not assignment:
            day_shift = ShiftMaster.objects.filter(name='Day Shift').first()
            if not day_shift:
                # Create default Day Shift if it doesn't exist
                day_shift = ShiftMaster.objects.create(
                    name='Day Shift',
                    start_time=time(9, 0),
                    end_time=time(17, 30),
                    shift_duration=8.5,
                    work_days='All Days'
                )
            return day_shift
        
        return assignment.shift
    
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Q, Sum, Avg
from datetime import timedelta
import calendar

class Attendance(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Present & Late', 'Present & Late'),
        ('Absent', 'Absent'),
        ('Late', 'Late'), 
        ('Half Day', 'Half Day'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
        ('Weekend', 'Weekend'),
        ('Holiday', 'Holiday'),
        ('Comp Off', 'Comp Off'),
        ('Not Marked', 'Not Marked') # Added new status for unmarked attendance
    ]

    LOCATION_CHOICES = [
        ('Office', 'Office'),
        ('Home', 'Home'), 
        ('Remote', 'Remote'),
        ('Other', 'Other')
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Not Marked') # Changed default to Not Marked
    is_half_day = models.BooleanField(default=False)
    leave_type = models.CharField(max_length=50, null=True, blank=True)
    clock_in_time = models.DateTimeField(null=True, blank=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)
    breaks = models.JSONField(default=list)
    total_hours = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    expected_hours = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    is_weekend = models.BooleanField(default=False)
    is_holiday = models.BooleanField(default=False)
    location = models.CharField(max_length=50, choices=LOCATION_CHOICES, default='Office')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.JSONField(null=True, blank=True)
    shift = models.ForeignKey('ShiftMaster', on_delete=models.SET_NULL, null=True, blank=True)
    late_minutes = models.IntegerField(default=0)
    last_modified = models.DateTimeField(auto_now=True)
    modified_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='attendance_modifications')
    regularization_reason = models.TextField(null=True, blank=True)
    regularization_status = models.CharField(max_length=20, choices=[
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected')
    ], null=True, blank=True)
    user_session = models.ForeignKey('UserSession', on_delete=models.SET_NULL, null=True, blank=True)
    overtime_hours = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    is_overtime_approved = models.BooleanField(default=False)
    remarks = models.TextField(null=True, blank=True)

    class Meta:
        unique_together = ['user', 'date']
        indexes = [
            models.Index(fields=['user', 'date', 'status']),
            models.Index(fields=['shift']),
            models.Index(fields=['date']),
            models.Index(fields=['user', 'status']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.status}"

    def check_late_arrival(self):
        """Check if user arrived late based on shift timing"""
        if not self.clock_in_time:
            self.status = 'Not Marked' # Changed to Not Marked instead of Absent
            return

        try:
            # Get user's shift if not set
            if not self.shift:
                from .models import ShiftAssignment
                self.shift = ShiftAssignment.get_user_current_shift(self.user, self.date)
                if not self.shift:
                    self.status = 'Present'
                    return

            # Get shift start time for the date
            shift_start = timezone.make_aware(
                timezone.datetime.combine(self.date, self.shift.start_time)
            )

            # Add grace period if defined
            grace_period = getattr(self.shift, 'grace_period', timedelta(minutes=0))
            latest_allowed_time = shift_start + grace_period

            # Compare clock in time with allowed time
            if self.clock_in_time > latest_allowed_time:
                self.status = 'Present & Late'
                # Calculate late minutes
                late_duration = self.clock_in_time - latest_allowed_time
                self.late_minutes = int(late_duration.total_seconds() // 60)
            else:
                self.status = 'Present'

        except Exception as e:
            import traceback
            print(f"Error checking late arrival: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            self.status = 'Present'

    def calculate_hours(self):
        """Calculate total working hours excluding breaks"""
        if not (self.clock_in_time and self.clock_out_time):
            return None

        try:
            # Ensure times are timezone aware
            clock_in = self.ensure_timezone_aware(self.clock_in_time)
            clock_out = self.ensure_timezone_aware(self.clock_out_time)

            # Calculate total duration
            total_time = (clock_out - clock_in).total_seconds() / 3600

            # Subtract break time
            break_time = self.calculate_break_time()
            total_worked = total_time - break_time

            # Calculate overtime if applicable
            regular_hours = self.expected_hours or (self.shift.expected_hours() if self.shift else 8.0)
            if total_worked > float(regular_hours):
                self.overtime_hours = round(total_worked - float(regular_hours), 2)
            else:
                self.overtime_hours = 0

            return round(total_worked, 2)

        except Exception as e:
            import traceback
            print(f"Error calculating hours: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            return None

    def calculate_break_time(self):
        """Calculate total break time in hours"""
        break_time = 0
        if not self.breaks:
            return break_time

        try:
            if isinstance(self.breaks, list):
                for break_data in self.breaks:
                    start = break_data.get('start')
                    end = break_data.get('end')

                    # Convert string times to datetime if needed
                    if isinstance(start, str):
                        try:
                            start = timezone.datetime.fromisoformat(start)
                        except ValueError:
                            continue
                    if isinstance(end, str):
                        try:
                            end = timezone.datetime.fromisoformat(end)
                        except ValueError:
                            continue

                    # Ensure timezone awareness
                    start = self.ensure_timezone_aware(start)
                    end = self.ensure_timezone_aware(end)

                    if start and end and end > start:
                        break_time += (end - start).total_seconds() / 3600

        except Exception as e:
            print(f"Error calculating break time: {str(e)}")

        return break_time

    def ensure_timezone_aware(self, datetime_obj):
        """Ensure datetime is timezone aware"""
        if datetime_obj and timezone.is_naive(datetime_obj):
            return timezone.make_aware(datetime_obj)
        return datetime_obj

    def determine_attendance_status(self):
        """Determine final attendance status based on various factors"""
        # Check for approved leave
        from .models import Leave
        leave = Leave.objects.filter(
            user=self.user,
            start_date__lte=self.date,
            end_date__gte=self.date,
            status='Approved'
        ).first()

        if leave:
            self.status = 'On Leave'
            self.leave_type = leave.leave_type
            self.is_half_day = leave.half_day
            return

        # Check for holiday
        if self.is_holiday:
            self.status = 'Holiday'
            return

        # Check for weekend and shift work days
        if self.is_weekend:
            if self.shift:
                # Check if custom work days are defined
                if self.shift.work_days == 'Custom':
                    custom_days = self.shift.custom_work_days.split(',')
                    weekday = calendar.day_name[self.date.weekday()]
                    if weekday not in custom_days:
                        self.status = 'Weekend'
                        return
                elif self.shift.work_days != 'All Days':
                    self.status = 'Weekend'
                    return
            else:
                self.status = 'Weekend'
                return

        # Handle no clock in
        if not self.clock_in_time:
            self.status = 'Not Marked' # Changed to Not Marked instead of Absent
            return

        # Handle work from home
        if self.location == 'Home':
            self.status = 'Work From Home'

        # Check for half day based on hours worked
        if self.clock_in_time and self.clock_out_time and self.total_hours is not None:
            expected = self.expected_hours or (self.shift.shift_duration if self.shift else 8.0)
            half_day_threshold = float(expected) / 2

            if float(self.total_hours) < half_day_threshold:
                self.status = 'Half Day'
                self.is_half_day = True
            elif self.status not in ['Late', 'Present & Late', 'Work From Home']:
                self.status = 'Present'

    def clean(self):
        """Validate attendance data"""
        if self.clock_in_time and self.clock_out_time:
            if self.clock_out_time < self.clock_in_time:
                raise ValidationError("Clock out must be after clock in")

        if self.breaks:
            try:
                for break_data in self.breaks:
                    start = break_data.get('start')
                    end = break_data.get('end')
                    if start and end:
                        if isinstance(start, str):
                            start = timezone.datetime.fromisoformat(start)
                        if isinstance(end, str):
                            end = timezone.datetime.fromisoformat(end)
                        if end <= start:
                            raise ValidationError("Break end time must be after start time")
            except Exception as e:
                raise ValidationError(f"Invalid break data: {str(e)}")

    def save(self, recalculate=False, *args, **kwargs):
        try:
            # Ensure timezone awareness
            self.clock_in_time = self.ensure_timezone_aware(self.clock_in_time)
            self.clock_out_time = self.ensure_timezone_aware(self.clock_out_time)

            # Handle breaks timezone awareness
            if self.breaks and isinstance(self.breaks, list):
                for i, break_data in enumerate(self.breaks):
                    start = break_data.get('start')
                    end = break_data.get('end')
                    if isinstance(start, str):
                        try:
                            start = timezone.datetime.fromisoformat(start)
                            self.breaks[i]['start'] = self.ensure_timezone_aware(start)
                        except (ValueError, TypeError):
                            self.breaks[i]['start'] = None
                    if isinstance(end, str):
                        try:
                            end = timezone.datetime.fromisoformat(end)
                            self.breaks[i]['end'] = self.ensure_timezone_aware(end)
                        except (ValueError, TypeError):
                            self.breaks[i]['end'] = None

            # Set basic flags
            self.is_weekend = self.date.weekday() >= 5
            self.is_holiday = self.check_if_holiday()

            # Get shift if not set
            if not self.shift_id:
                from .models import ShiftAssignment
                self.shift = ShiftAssignment.get_user_current_shift(self.user, self.date)

            # Set expected hours from shift
            if self.shift:
                self.expected_hours = self.shift.shift_duration

            # Calculate total hours and determine status
            if recalculate or not self.status or self.status == 'Not Marked': # Changed from Absent to Not Marked
                if self.clock_in_time and self.clock_out_time:
                    self.total_hours = self.calculate_hours()

                if self.clock_in_time and not str(self.status).startswith(('On Leave', 'Holiday', 'Weekend')):
                    self.check_late_arrival()

                self.determine_attendance_status()

            # Force WFH status if location is Home
            if self.location == 'Home' and self.clock_in_time:
                self.status = 'Work From Home'

            super().save(*args, **kwargs)

        except Exception as e:
            import traceback
            print(f"Error saving attendance: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            # Still try to save basic data
            super().save(*args, **kwargs)

    def check_if_holiday(self):
        """Check if date is a holiday"""
        from .models import Holiday
        return Holiday.is_holiday(self.date)

    @classmethod
    def determine_shift_date(cls, user, clock_in_time):
        """Determine the shift date and get shift for clock in time"""
        try:
            attendance_date = clock_in_time.date()
            from .models import ShiftAssignment
            shift = ShiftAssignment.get_user_current_shift(user, attendance_date)
            
            # Handle overnight shifts
            if shift and shift.start_time > shift.end_time:
                # If clock in is before midnight, use current date
                # If clock in is after midnight, use previous date
                if clock_in_time.time() < shift.end_time:
                    attendance_date = attendance_date - timedelta(days=1)
            
            return attendance_date, shift
            
        except Exception as e:
            print(f"Error in determine_shift_date: {str(e)}")
            return clock_in_time.date(), None

    @classmethod
    def create_attendance(cls, user, clock_in_time, location="Office", ip_address=None, device_info=None):
        """Create new attendance record"""
        try:
            # Get active user session
            from .models import UserSession
            user_session = UserSession.objects.filter(
                user=user,
                is_active=True,
                login_time__date=clock_in_time.date()
            ).first()

            # Determine shift date and get shift
            shift_date, shift = cls.determine_shift_date(user, clock_in_time)

            # Check for existing leave
            from .models import Leave
            existing_leave = Leave.objects.filter(
                user=user,
                start_date__lte=shift_date,
                end_date__gte=shift_date,
                status='Approved'
            ).first()

            # Check holiday and weekend status
            from .models import Holiday
            is_holiday = Holiday.is_holiday(shift_date)
            is_weekend = shift_date.weekday() >= 5
            
            # Check if it's a working day based on shift
            is_working_day = True
            if shift:
                if shift.work_days == 'Custom':
                    weekday = calendar.day_name[shift_date.weekday()]
                    is_working_day = weekday in shift.custom_work_days.split(',')
                elif shift.work_days != 'All Days':
                    is_working_day = not is_weekend

            # Determine initial status
            if existing_leave:
                initial_status = 'On Leave'
                leave_type = existing_leave.leave_type
                is_half_day = existing_leave.half_day
            elif is_holiday:
                initial_status = 'Holiday'
                leave_type = None
                is_half_day = False
            elif is_weekend and not is_working_day:
                initial_status = 'Weekend'
                leave_type = None
                is_half_day = False
            elif location == 'Home':
                initial_status = 'Work From Home'
                leave_type = None
                is_half_day = False
            else:
                initial_status = 'Present'
                leave_type = None
                is_half_day = False

            # Create or update attendance
            attendance, created = cls.objects.get_or_create(
                user=user,
                date=shift_date,
                defaults={
                    'clock_in_time': clock_in_time,
                    'status': initial_status,
                    'location': location,
                    'ip_address': ip_address,
                    'device_info': device_info,
                    'shift': shift,
                    'expected_hours': shift.shift_duration if shift else 8.0,
                    'is_weekend': is_weekend,
                    'is_holiday': is_holiday,
                    'leave_type': leave_type,
                    'is_half_day': is_half_day,
                    'user_session': user_session
                }
            )

            if not created and not attendance.clock_in_time:
                attendance.clock_in_time = clock_in_time
                attendance.location = location
                attendance.ip_address = ip_address
                attendance.device_info = device_info
                attendance.shift = shift
                attendance.user_session = user_session
                if attendance.status not in ['On Leave', 'Holiday']:
                    attendance.status = initial_status
                attendance.save(recalculate=True)

            return attendance

        except Exception as e:
            import traceback
            print(f"Error creating attendance: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            # Fallback to basic attendance creation
            return cls.objects.create(
                user=user,
                date=clock_in_time.date(),
                clock_in_time=clock_in_time,
                status='Present',
                location=location,
                ip_address=ip_address,
                device_info=device_info
            )

    @classmethod
    def clock_out(cls, user, clock_out_time, breaks=None):
        """Record clock out time for user"""
        try:
            # Get current date's attendance
            today = clock_out_time.date()
            attendance = cls.objects.filter(
                user=user,
                date=today,
                clock_in_time__isnull=False,
                clock_out_time__isnull=True
            ).first()

            # For overnight shifts, also check previous day
            if not attendance:
                yesterday = today - timedelta(days=1)
                attendance = cls.objects.filter(
                    user=user,
                    date=yesterday,
                    clock_in_time__isnull=False,
                    clock_out_time__isnull=True
                ).first()

            if attendance:
                attendance.clock_out_time = clock_out_time
                if breaks:
                    attendance.breaks = breaks
                attendance.save(recalculate=True)
                return attendance
            else:
                print(f"No active attendance found for user {user} to clock out.")
                return None

        except Exception as e:
            import traceback
            print(f"Error in clock_out: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            return None

    @classmethod
    def get_attendance_summary(cls, user, year=None, month=None):
        """Get monthly attendance summary"""
        if not year:
            year = timezone.now().year
        if not month:
            month = timezone.now().month

        start_date = timezone.datetime(year, month, 1).date()
        if month == 12:
            end_date = timezone.datetime(year + 1, 1, 1).date() - timedelta(days=1)
        else:
            end_date = timezone.datetime(year, month + 1, 1).date() - timedelta(days=1)

        from .models import ShiftAssignment
        shift = ShiftAssignment.get_user_current_shift(user)
        attendances = cls.objects.filter(
            user=user,
            date__range=(start_date, end_date)
        )

        working_days = 0
        current_date = start_date
        from .models import Holiday
        while current_date <= end_date:
            if shift:
                if shift.work_days == 'Custom':
                    weekday = calendar.day_name[current_date.weekday()]
                    if weekday in shift.custom_work_days.split(',') and not Holiday.is_holiday(current_date):
                        working_days += 1
                elif shift.work_days == 'All Days' or (shift.work_days != 'Custom' and current_date.weekday() < 5):
                    if not Holiday.is_holiday(current_date):
                        working_days += 1
            else:
                if current_date.weekday() < 5 and not Holiday.is_holiday(current_date):
                    working_days += 1
            current_date += timedelta(days=1)

        summary = {
            'year': year,
            'month': month,
            'month_name': calendar.month_name[month],
            'working_days': working_days,
            'present_days': attendances.filter(status='Present').count(),
            'late_days': attendances.filter(status='Late').count(),
            'wfh_days': attendances.filter(status='Work From Home').count(),
            'absent_days': attendances.filter(status='Not Marked').count(), # Changed from Absent to Not Marked
            'half_days': attendances.filter(is_half_day=True).count(),
            'leave_days': attendances.filter(status='On Leave').count(),
            'total_hours': sum(att.total_hours or 0 for att in attendances),
            'overtime_hours': sum(att.overtime_hours or 0 for att in attendances),
            'avg_hours': attendances.filter(total_hours__isnull=False).aggregate(models.Avg('total_hours'))['total_hours__avg'] or 0,
            'max_hours': attendances.filter(total_hours__isnull=False).aggregate(models.Max('total_hours'))['total_hours__max'] or 0,
            'attendance_percentage': 0
        }

        if working_days > 0:
            present_equivalent = (
                summary['present_days'] +
                summary['late_days'] +
                summary['wfh_days'] +
                (summary['half_days'] * 0.5) +
                summary['leave_days']
            )
            summary['attendance_percentage'] = round((present_equivalent / working_days) * 100, 2)

        return summary

    @classmethod
    def get_annual_report(cls, user, year):
        """Get annual attendance report"""
        annual_data = []
        for month in range(1, 13):
            monthly_summary = cls.get_attendance_summary(user, year, month)
            annual_data.append(monthly_summary)

        yearly_totals = {
            'working_days': sum(month['working_days'] for month in annual_data),
            'present_days': sum(month['present_days'] for month in annual_data),
            'late_days': sum(month['late_days'] for month in annual_data),
            'wfh_days': sum(month['wfh_days'] for month in annual_data),
            'absent_days': sum(month['absent_days'] for month in annual_data),
            'half_days': sum(month['half_days'] for month in annual_data),
            'leave_days': sum(month['leave_days'] for month in annual_data),
            'total_hours': sum(month['total_hours'] for month in annual_data),
            'overtime_hours': sum(month['overtime_hours'] for month in annual_data),
        }

        if yearly_totals['working_days'] > 0:
            present_equivalent = (
                yearly_totals['present_days'] +
                yearly_totals['late_days'] +
                yearly_totals['wfh_days'] +
                (yearly_totals['half_days'] * 0.5) +
                yearly_totals['leave_days']
            )
            yearly_totals['attendance_percentage'] = round((present_equivalent / yearly_totals['working_days']) * 100, 2)
        else:
            yearly_totals['attendance_percentage'] = 0

        return {
            'year': year,
            'monthly_data': annual_data,
            'yearly_totals': yearly_totals
        }


'''-------------------------------------------- SUPPORT AREA ---------------------------------------'''
import uuid
from django.db import models
from django.utils.timezone import now
from django.contrib.auth import get_user_model

User = get_user_model()

class Support(models.Model):
    class Status(models.TextChoices):
        NEW = 'New', 'New'
        OPEN = 'Open', 'Open'
        IN_PROGRESS = 'In Progress', 'In Progress'
        PENDING_USER = 'Pending User Response', 'Pending User Response'
        PENDING_THIRD_PARTY = 'Pending Third Party', 'Pending Third Party'
        ON_HOLD = 'On Hold', 'On Hold'
        RESOLVED = 'Resolved', 'Resolved'
        CLOSED = 'Closed', 'Closed'

    class Priority(models.TextChoices):
        LOW = 'Low', 'Low'
        MEDIUM = 'Medium', 'Medium'
        HIGH = 'High', 'High'
        CRITICAL = 'Critical', 'Critical'

    class IssueType(models.TextChoices):
        HARDWARE = 'Hardware Issue', 'Hardware Issue'
        SOFTWARE = 'Software Issue', 'Software Issue'
        NETWORK = 'Network Issue', 'Network Issue'
        INTERNET = 'Internet Issue', 'Internet Issue'
        APPLICATION = 'Application Issue', 'Application Issue'
        HR = 'HR Related Issue', 'HR Related Issue'
        ACCESS = 'Access Management', 'Access Management'
        SECURITY = 'Security Incident', 'Security Incident'
        SERVICE = 'Service Request', 'Service Request'

    class AssignedTo(models.TextChoices):
        HR = 'HR', 'HR'
        ADMIN = 'Admin', 'Admin'

    # Core Fields
    ticket_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tickets')
    issue_type = models.CharField(max_length=50, choices=IssueType.choices)
    subject = models.CharField(max_length=200)
    description = models.TextField()

    # Status and Assignment
    status = models.CharField(max_length=30, choices=Status.choices, default=Status.NEW)
    priority = models.CharField(max_length=20, choices=Priority.choices, default=Priority.MEDIUM)
    assigned_to = models.CharField(max_length=50, choices=AssignedTo.choices, default=AssignedTo.HR)
    assigned_to_user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='assigned_tickets'
    )

    # Timestamps
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    due_date = models.DateTimeField(null=True, blank=True)

    # Additional Fields
    department = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=100, blank=True)
    asset_id = models.CharField(max_length=50, blank=True, help_text="Related hardware/software asset ID")

    # Related Issues
    parent_ticket = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='sub_tickets',
        help_text="Parent ticket for related issues"
    )

    # SLA and Resolution
    sla_breach = models.BooleanField(default=False)
    resolution_summary = models.TextField(blank=True)
    resolution_time = models.DurationField(null=True, blank=True)

    # User Satisfaction
    satisfaction_rating = models.IntegerField(null=True, blank=True, choices=[(i, i) for i in range(1, 6)])
    feedback = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ticket_id']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['user']),
            models.Index(fields=['due_date']),
        ]
        verbose_name = "Support Ticket"
        verbose_name_plural = "Support Tickets"

    def __str__(self):
        return f"[{self.priority}] {self.ticket_id} - {self.subject} ({self.status})"

    @property
    def is_overdue(self):
        return bool(self.due_date and self.due_date < now())


class StatusLog(models.Model):
    ticket = models.ForeignKey(Support, on_delete=models.CASCADE, related_name='status_logs')
    old_status = models.CharField(max_length=30, choices=Support.Status.choices)
    new_status = models.CharField(max_length=30, choices=Support.Status.choices)
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    changed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ticket.ticket_id}: {self.old_status} -> {self.new_status}"
    
''' ------------------------------------------- REmove employee AREA ------------------------------------------- '''

# Employee model to store employee-specific information
class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # Reference to the User model
    shift = models.CharField(max_length=10, choices=[('Day', 'Day'), ('Night', 'Night')])  # Shift the employee works
    leave_balance = models.IntegerField(default=18)  # Number of leaves the employee has
    attendance_record = models.PositiveIntegerField(default=0)  # Number of days the employee worked
    late_arrivals = models.PositiveIntegerField(default=0)  # Number of times the employee was late
    early_departures = models.PositiveIntegerField(default=0)  # Number of times the employee left early

    def __str__(self):
        """Return a string representation of the employee."""
        return f"{self.user.username} - {', '.join([group.name for group in self.user.groups.all()])}"
    
''' ------------------------------------------- PROFILE AREA ------------------------------------------- '''
# models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserDetails(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    # Personal Information
    dob = models.DateField(null=True, blank=True)
    blood_group = models.CharField(
        max_length=10, 
        choices=[
            ('', '--------'),
            ('A+', 'A+'),
            ('A-', 'A-'),
            ('B+', 'B+'),
            ('B-', 'B-'),
            ('AB+', 'AB+'),
            ('AB-', 'AB-'),
            ('O+', 'O+'),
            ('O-', 'O-'),
        ], 
        null=True, 
        blank=True,
        default='Unknown'
    )
    gender = models.CharField(
        max_length=10, 
        choices=[
            ('', '--------'),
            ('Male', 'Male'), 
            ('Female', 'Female'), 
            ('Other', 'Other')
        ], 
        null=True, 
        blank=True
    )
    
    # Contact Information
    country_code = models.CharField(max_length=5, null=True, blank=True)
    contact_number_primary = models.CharField(max_length=13, null=True, blank=True)
    personal_email = models.EmailField(null=True, blank=True)
    
    # Address Information
    address_line1 = models.CharField(max_length=100, null=True, blank=True)
    address_line2 = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    postal_code = models.CharField(max_length=10, null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    
    # Emergency Contact
    emergency_contact_name = models.CharField(max_length=100, null=True, blank=True)
    emergency_contact_primary = models.CharField(max_length=13, null=True, blank=True)
    emergency_contact_address = models.TextField(null=True, blank=True)
    
    # Employment Information
    employee_type = models.CharField(
        max_length=20,
        choices=[
            ('payroll', 'Payroll'),
            ('contract', 'Contract'),
        ],
        null=True,
        blank=True
    )
    hire_date = models.DateField(null=True, blank=True)
    start_date = models.DateField(null=True, blank=True)
    job_description = models.TextField(null=True, blank=True)
    work_location = models.CharField(max_length=100, null=True, blank=True)
    employment_status = models.CharField(
        max_length=50,
        choices=[
            ('', '--------'),
            ('active', 'Active'),
            ('inactive', 'Inactive'),
            ('terminated', 'Terminated'),
            ('resigned', 'Resigned'),
            ('suspended', 'Suspended'),
            ('absconding', 'Absconding'),
        ],
        blank=True,
        null=True,
    )
    
    # Government IDs
    panno = models.CharField(max_length=10, null=True, blank=True)
    aadharno = models.CharField(max_length=14, null=True, blank=True)  # To store Aadhar with spaces
    
    # Role/Group
    group = models.ForeignKey('auth.Group', on_delete=models.SET_NULL, null=True, blank=True)
    
    # HR Management
    onboarded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='onboarded_users')
    onboarding_date = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    last_status_change = models.DateTimeField(null=True, blank=True)
    
    # Methods
    def save(self, *args, **kwargs):
        # Track employment status changes
        if self.pk:
            old_instance = UserDetails.objects.get(pk=self.pk)
            if old_instance.employment_status != self.employment_status:
                self.last_status_change = timezone.now()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Details for {self.user.username}"
    
    # Formatted contact number with country code
    @property
    def formatted_contact(self):
        if self.contact_number_primary and self.country_code:
            return f"{self.country_code} {self.contact_number_primary}"
        return self.contact_number_primary
    
    # Employment duration
    @property
    def employment_duration(self):
        if not self.start_date:
            return None
        
        today = timezone.now().date()
        delta = today - self.start_date
        years = delta.days // 365
        months = (delta.days % 365) // 30
        
        if years > 0:
            return f"{years} year{'s' if years > 1 else ''}, {months} month{'s' if months > 1 else ''}"
        return f"{months} month{'s' if months > 1 else ''}"

    # Employment status for display with color coding
    @property
    def status_display(self):
        status_colors = {
            'active': 'success',
            'inactive': 'secondary',
            'terminated': 'danger',
            'resigned': 'warning',
            'suspended': 'info',
            'absconding': 'dark'
        }
        
        if not self.employment_status:
            return {'text': 'Unknown', 'color': 'secondary'}
        
        status_text = dict(self._meta.get_field('employment_status').choices).get(self.employment_status, 'Unknown')
        status_color = status_colors.get(self.employment_status, 'secondary')
        
        return {'text': status_text, 'color': status_color}


# User action log for tracking important HR actions
class UserActionLog(models.Model):
    ACTION_TYPES = [
        ('create', 'User Created'),
        ('update', 'User Updated'),
        ('status_change', 'Status Changed'),
        ('role_change', 'Role Changed'),
        ('deactivate', 'User Deactivated'),
        ('activate', 'User Activated'),
        ('password_reset', 'Password Reset'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_logs')
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    action_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='performed_actions')
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.get_action_type_display()} for {self.user.username} on {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

''' ------------------------------------------- Clinet - PROJECT AREA ------------------------------------------- '''
class Project(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    start_date = models.DateField(default=timezone.now)
    deadline = models.DateField()
    status = models.CharField(
        max_length=20, 
        choices=[('Completed', 'Completed'), ('In Progress', 'In Progress'), ('Pending', 'Pending'),('On Hold', 'On Hold')]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    users = models.ManyToManyField(User, through='ProjectAssignment', related_name='projects_assigned')
    clients = models.ManyToManyField(User, related_name='projects_as_client', limit_choices_to={'groups__name': 'Client'})
    total_value = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    delivery_format = models.CharField(max_length=50, default='CSV')  # CSV, JSON, XLSX, etc.


    def __str__(self):
        return self.name

    def is_overdue(self):
        return self.deadline < timezone.now().date() and self.status != 'Completed'

    @classmethod
    def is_valid_status(cls, status):
        return status in dict(cls._meta.get_field('status').choices)


class ClientParticipation(models.Model):
    project = models.ForeignKey('Project', on_delete=models.CASCADE, related_name='client_participations')  # updated to plural
    client = models.ForeignKey(User, on_delete=models.CASCADE, related_name='client_participations')
    feedback = models.TextField(blank=True, null=True)
    approved = models.BooleanField(default=False)
    date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)  # Added for soft delete

    def __str__(self):
        return f"{self.client.username} - {self.project.name}"

    def deactivate(self):
        """Soft delete a client participation by setting is_active to False"""
        self.is_active = False
        self.save()



class ProjectAssignment(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    assigned_date = models.DateField(auto_now_add=True)
    hours_worked = models.FloatField(default=0.0)
    role_in_project = models.CharField(
        max_length=50, 
        choices=[('Manager', 'Manager'), ('Employee', 'Employee'), ('Support', 'Support'),
                 ('Appraisal', 'Appraisal'), ('QC', 'QC')],
        default='Employee'
    )
    end_date = models.DateField(null=True, blank=True)  # Soft delete field
    is_active = models.BooleanField(default=True)  # Soft delete indicator

    def __str__(self):
        return f"{self.user.username} assigned to {self.project.name}"

    def get_total_hours(self):
        # Calculate total hours worked, considering the current hours worked and any additional logic.
        return self.hours_worked

    def deactivate(self):
        """Soft delete an assignment by setting is_active to False and updating the end_date"""
        self.is_active = False
        self.end_date = timezone.now().date()
        self.save()

    def update_hours(self, hours):
        """Update hours worked for a project assignment."""
        self.hours_worked += hours
        self.save()

''' ------------------------------------------- TRACK AREA ------------------------------------------- '''


# FailedLoginAttempt model to track failed login attempts
class FailedLoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User who attempted to log in
    attempt_time = models.DateTimeField(auto_now_add=True)  # Time of the failed login attempt
    ip_address = models.GenericIPAddressField()  # IP address from which the failed login attempt was made

    def __str__(self):
        """Return a string representation of the failed login attempt."""
        return f"Failed login for {self.user.username} from {self.ip_address}"


# PasswordChange model to store password change logs
class PasswordChange(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User who changed the password
    old_password = models.CharField(max_length=255)  # Old password before the change
    new_password = models.CharField(max_length=255)  # New password after the change
    change_time = models.DateTimeField(auto_now_add=True)  # Time when the password was changed

    def __str__(self):
        """Return a string representation of the password change."""
        return f"Password change for {self.user.username} at {self.change_time}"


# RoleAssignmentAudit model to track role assignment history
class RoleAssignmentAudit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User whose role was changed
    role_assigned = models.CharField(max_length=50)  # Role that was assigned
    assigned_by = models.ForeignKey(User, related_name="role_assigned_by", on_delete=models.CASCADE)  # Admin user who assigned the role
    assigned_date = models.DateTimeField(auto_now_add=True)  # Date when the role was assigned

    def __str__(self):
        """Return a string representation of the role assignment."""
        return f"{self.user.username} assigned {self.role_assigned} by {self.assigned_by.username}"


# SystemUsage model to store system usage data
class SystemUsage(models.Model):
    peak_time_start = models.DateTimeField()  # Start time of peak system usage
    peak_time_end = models.DateTimeField()  # End time of peak system usage
    active_users_count = models.PositiveIntegerField()  # Number of active users during peak time

    def __str__(self):
        """Return a string representation of the system usage period."""
        return f"Peak usage: {self.peak_time_start} - {self.peak_time_end}"


# FeatureUsage model to track usage of specific system features
class FeatureUsage(models.Model):
    feature_name = models.CharField(max_length=100)  # Name of the feature
    usage_count = models.PositiveIntegerField()  # Number of times the feature was used

    def __str__(self):
        """Return a string representation of the feature usage."""
        return f"{self.feature_name} - {self.usage_count} uses"


# SystemError model to store information about system errors
class SystemError(models.Model):
    error_message = models.TextField()  # Description of the system error
    error_time = models.DateTimeField(auto_now_add=True)  # Time when the error occurred
    resolved = models.BooleanField(default=False)  # Whether the error is resolved

    def __str__(self):
        """Return a string representation of the system error."""
        return f"Error: {self.error_message[:50]} - Resolved: {self.resolved}"



''' ------------------------------------------------- TIMESHEET AREA --------------------------------------------------- '''
class Timesheet(models.Model):
    APPROVAL_STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Partially_Approved', 'Partially Approved'),
        ('Rejected', 'Rejected'),
        ('Clarification_Requested', 'Clarification Requested')
    ]
    
    REJECTION_REASON_CHOICES = [
        ('Insufficient_Detail', 'Insufficient Detail'),
        ('Hours_Discrepancy', 'Hours Discrepancy'),
        ('Wrong_Project', 'Wrong Project Allocation'),
        ('Incomplete_Documentation', 'Incomplete Documentation'),
        ('Other', 'Other')
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='timesheets')
    week_start_date = models.DateField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='timesheets')
    task_name = models.CharField(max_length=255)
    task_description = models.TextField(help_text="Detailed description of work performed")
    hours = models.FloatField()
    adjusted_hours = models.FloatField(null=True, blank=True, help_text="Hours adjusted by manager during review")
    approval_status = models.CharField(
        max_length=25,
        choices=APPROVAL_STATUS_CHOICES,
        default='Pending'
    )
    rejection_reason = models.CharField(
        max_length=30,
        choices=REJECTION_REASON_CHOICES,
        null=True, 
        blank=True
    )
    manager_comments = models.TextField(blank=True, null=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    original_submission_id = models.IntegerField(null=True, blank=True, help_text="ID of original submission if this is a resubmission")
    version = models.PositiveIntegerField(default=1, help_text="Version number of this timesheet entry")
    
    def __str__(self):
        return f"Timesheet for {self.project.name} - {self.week_start_date} (v{self.version})"
    
    def clean(self):
        # Convert string dates to datetime.date objects if needed
        if isinstance(self.week_start_date, str):
            try:
                from datetime import datetime
                self.week_start_date = datetime.strptime(self.week_start_date, '%Y-%m-%d').date()
            except ValueError:
                raise ValidationError("Invalid date format for week_start_date")
        
        # Get current date for comparison
        current_date = timezone.now().date()
        
        # Prevent backdated submissions beyond 14 days
        if self.week_start_date < (current_date - timedelta(days=14)):
            raise ValidationError("Cannot submit timesheet entries older than 14 days")
        
        # Prevent future submissions beyond current week
        if self.week_start_date > current_date:
            raise ValidationError("Cannot submit timesheet entries for future dates")
        
        # Enforce maximum hours per day (8 hours)
        if self.hours > 8:
            raise ValidationError("Maximum 8 hours can be logged per day per project")
        
        # Check weekly hour limit (45 hours) across all projects for this week
        week_end_date = self.week_start_date + timedelta(days=6)
        total_hours = Timesheet.objects.filter(
            user=self.user,
            week_start_date__gte=self.week_start_date,
            week_start_date__lte=week_end_date
        ).exclude(pk=self.pk).aggregate(models.Sum('hours'))['hours__sum'] or 0
        
        if total_hours + self.hours > 45:
            raise ValidationError(f"Total weekly hours cannot exceed 45. Current total: {total_hours}")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)
    
    class Meta:
        unique_together = ('user', 'week_start_date', 'project', 'task_name', 'version')
        ordering = ['-week_start_date', '-version']
        permissions = [
            ("approve_timesheet", "Can approve or reject timesheets"),
            ("view_team_timesheets", "Can view timesheets for team members"),
        ]

# Signal to update 'reviewed_at' field when approval status changes
from django.db.models.signals import pre_save
from django.dispatch import receiver

@receiver(pre_save, sender=Timesheet)
def update_reviewed_at(sender, instance, **kwargs):
    if instance.pk:
        try:
            old_instance = Timesheet.objects.get(pk=instance.pk)
            if old_instance.approval_status != instance.approval_status:
                instance.reviewed_at = timezone.now()
                
                # If this is a rejection and no original submission exists yet
                if instance.approval_status == 'Rejected' and not instance.original_submission_id:
                    instance.original_submission_id = instance.pk
        except Timesheet.DoesNotExist:
            pass

# Signal to create a new version when resubmitting after rejection
@receiver(pre_save, sender=Timesheet)
def handle_resubmission(sender, instance, **kwargs):
    if instance.pk and instance.approval_status == 'Rejected':
        # When resubmitting a rejected timesheet, create a new version
        if not hasattr(instance, '_resubmitting') or not instance._resubmitting:
            instance._resubmitting = True
            # Create a new version with incremented version number
            latest_version = Timesheet.objects.filter(
                original_submission_id=instance.original_submission_id or instance.pk
            ).order_by('-version').first()
            
            if latest_version:
                instance.version = latest_version.version + 1
            else:
                instance.version = 2
                
            if not instance.original_submission_id:
                instance.original_submission_id = instance.pk


'''----------------------------- HR --------------------------'''

class GlobalUpdate(models.Model):
    STATUS_CHOICES = [
        ('upcoming', 'Upcoming'),
        ('released', 'Just Released'),
        ('scheduled', 'Scheduled'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    scheduled_date = models.DateTimeField(null=True, blank=True)  # Optional, for scheduled status
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # To track modifications
    managed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)  # HR or manager who created the update

    def clean(self):
        if self.status == 'scheduled' and not self.scheduled_date:
            raise ValidationError("Scheduled updates must have a scheduled date.")
        if self.status != 'scheduled' and self.scheduled_date:
            raise ValidationError("Scheduled date can only be set for 'scheduled' status.")

    def __str__(self):
        return f"{self.title} ({self.status})"

    class Meta:
        permissions = [
            ("manage_globalupdate", "Can manage Global Updates"),
        ]


'''------------------------------- BREAK MODULE --------------------------'''
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now
from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.timezone import now
from datetime import timedelta

class Break(models.Model):
    BREAK_TYPES = [
        ('Tea Break 1', 'Tea Break 1'),
        ('Lunch/Dinner Break', 'Lunch/Dinner Break'),
        ('Tea Break 2', 'Tea Break 2'),
    ]
    
    BREAK_DURATIONS = {
        'Tea Break 1': timedelta(minutes=5),
        'Lunch/Dinner Break': timedelta(minutes=35),
        'Tea Break 2': timedelta(minutes=5),
    }
    
    DAILY_BREAK_LIMITS = {
        'Tea Break': 1,
        'Lunch/Dinner Break ': 1,
        'Tea Break ': 1,
    }
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    break_type = models.CharField(max_length=50, choices=BREAK_TYPES)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    reason_for_extension = models.TextField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Break"
        verbose_name_plural = "Breaks"
        ordering = ['-start_time']

    def get_breaks_taken_today(self):
        """Get the number of breaks taken today by type."""
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        return Break.objects.filter(
            user=self.user,
            break_type=self.break_type,
            start_time__range=(today_start, today_end)
        ).count()

    def clean(self):
        """Enhanced validation to check for daily break limits and active breaks."""
        super().clean()
        
        # Check for active breaks
        if not self.end_time:  # Only check for new breaks
            active_breaks = Break.objects.filter(
                user=self.user, 
                end_time__isnull=True
            ).exclude(pk=self.pk)
            
            if active_breaks.exists():
                raise ValidationError("You already have an active break.")
            
            # Check daily limit for this break type
            breaks_taken = self.get_breaks_taken_today()
            allowed_breaks = self.DAILY_BREAK_LIMITS.get(self.break_type, 1)
            
            if breaks_taken >= allowed_breaks:
                break_type_display = dict(self.BREAK_TYPES)[self.break_type]
                raise ValidationError(
                    f"You have already taken your allowed {break_type_display} for today. "
                    f"Limit: {allowed_breaks} per day."
                )

    @property
    def is_active(self):
        """Check if the break is currently active."""
        if self.end_time is None:
            start_time_aware = timezone.localtime(self.start_time)
            max_duration = self.BREAK_DURATIONS.get(self.break_type, timedelta())
            return timezone.now() - start_time_aware <= max_duration
        return False

    def end_break(self, reason=None):
        """End the break and record reason if provided."""
        if not self.is_active:
            raise ValidationError("This break has already ended.")
        
        self.end_time = timezone.now()
        if reason:
            self.reason_for_extension = reason
        self.save()

    @classmethod
    def get_available_breaks(cls, user):
        """Get list of break types still available today for the user."""
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        taken_breaks = Break.objects.filter(
            user=user,
            start_time__range=(today_start, today_end)
        ).values_list('break_type', flat=True)
        
        # Count breaks taken today by type
        break_counts = {}
        for break_type in taken_breaks:
            break_counts[break_type] = break_counts.get(break_type, 0) + 1
        
        # Filter available breaks based on limits
        available_breaks = []
        for break_type, limit in cls.DAILY_BREAK_LIMITS.items():
            if break_counts.get(break_type, 0) < limit:
                available_breaks.append(break_type)
        
        return available_breaks

    def __str__(self):
        return f"{self.user.username} - {self.break_type} ({'Active' if self.is_active else 'Ended'})"
    
'''---------------------------------- Manager updates team --------------------------------'''


class ProjectUpdate(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=[('upcoming', 'Upcoming'), ('in_progress', 'In Progress'), ('completed', 'Completed')], default='upcoming')
    scheduled_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Update for {self.project.name} by {self.created_by.username}"
    

'''---------------- Chat System Models -----------------------'''
from django.db import models
from django.contrib.auth.models import User, Group
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models import Count, Q

class ChatGroup(models.Model):
    """Represents team/department chat groups that only managers/admins can create"""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_groups'
    )
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)

    def clean(self):
        # Ensure only managers/admins can create groups
        if not self.created_by.groups.filter(name__in=['Admin', 'Manager']).exists():
            raise ValidationError("Only managers and administrators can create chat groups")

    def get_unread_count(self, user):
        """Get count of unread messages for a user in this group"""
        return self.messages.filter(
            read_receipts__user=user,
            read_receipts__read_at__isnull=True
        ).count()



class GroupMember(models.Model):
    """Tracks group membership and roles"""
    ROLES = [
        ('admin', 'Group Admin'),
        ('member', 'Member')
    ]

    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_memberships')
    role = models.CharField(max_length=20, choices=ROLES, default='member')
    joined_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(auto_now=True)
    typing_status = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ['group', 'user']

    def mark_typing(self):
        """Update typing status"""
        self.typing_status = timezone.now()
        self.save()

    def clear_typing(self):
        """Clear typing status"""
        self.typing_status = None
        self.save()

class DirectMessage(models.Model):
    """Represents one-to-one private chats between users"""
    participants = models.ManyToManyField(User, related_name='direct_messages')
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)

    def clean(self):
        # Ensure exactly two participants
        if self.participants.all().count() != 2:
            raise ValidationError("Direct messages must have exactly two participants")

    def get_unread_count(self, user):
        """Get count of unread messages for a user in this conversation"""
        return self.messages.filter(
            messageread__user=user,
            messageread__read_at__isnull=True
        ).count()

    def get_other_participant(self, user):
        """Get the other participant in the conversation"""
        return self.participants.exclude(id=user.id).first()

    def get_messages(self):
        """Get all messages in this conversation"""
        return self.messages.all().order_by('sent_at')
    
class Message(models.Model):
    """Represents messages in both groups and direct messages"""
    MESSAGE_TYPES = [
        ('text', 'Text Message'),
        ('file', 'File Attachment'), 
        ('system', 'System Message')
    ]

    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE, null=True, blank=True, related_name='messages')
    direct_message = models.ForeignKey(DirectMessage, on_delete=models.CASCADE, null=True, blank=True, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField()
    message_type = models.CharField(max_length=20, choices=MESSAGE_TYPES, default='text')
    file_attachment = models.FileField(upload_to='chat_files/%Y/%m/%d/', null=True, blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    edited_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['sent_at']
        indexes = [
            models.Index(fields=['group', 'sent_at']),
            models.Index(fields=['direct_message', 'sent_at']),
            models.Index(fields=['sender', 'sent_at'])
        ]

    def clean(self):
        # Message must belong to either group or direct message
        if (self.group and self.direct_message) or (not self.group and not self.direct_message):
            raise ValidationError("Message must belong to either a group or direct message")
        
        # Validate file attachment if message type is file
        if self.message_type == 'file' and not self.file_attachment:
            raise ValidationError("File attachment is required for file type messages")

    def soft_delete(self):
        """Soft delete a message"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
        
    def get_file_name(self):
        """Get the name of the attached file"""
        if self.file_attachment and hasattr(self.file_attachment, 'name'):
            return self.file_attachment.name.split('/')[-1]
        return None
        
    def get_file_url(self):
        """Get the URL of the attached file"""
        if self.file_attachment:
            return self.file_attachment.url
        return None

    def __str__(self):
        try:
            # Format the timestamp in a user-friendly way
            formatted_time = self.sent_at.strftime("%b %d, %I:%M %p")
            
            # Get a short preview of the message content (first 30 chars)
            content_preview = self.content[:30] + "..." if len(self.content) > 30 else self.content
            
            if self.is_deleted:
                return f"[Deleted message]"
            
            attachment_info = f" [with attachment: {self.get_file_name()}]" if self.file_attachment else ""
            
            if self.group:
                return f"{self.sender.username} in {self.group.name}: {content_preview}{attachment_info} • {formatted_time}"
            elif self.direct_message:
                return f"{self.sender.username}: {content_preview}{attachment_info} • {formatted_time}"
            else:
                return f"Message from {self.sender.username}: {content_preview}{attachment_info} • {formatted_time}"
        except Exception:
            # Fallback that still provides useful information
            return f"Message {self.id} from {getattr(self.sender, 'username', 'Unknown')}"
        
class MessageRead(models.Model):
    """Tracks message read status per user"""
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='read_receipts')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ['message', 'user']
        indexes = [
            models.Index(fields=['user', 'read_at']),
            models.Index(fields=['message', 'user'])
        ]

    def mark_as_read(self):
        """Mark message as read"""
        if not self.read_at:
            self.read_at = timezone.now()
            self.save()

'''------------------------ marking manula attendace ----------------'''
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    
    def __str__(self):
        return self.name

class EmployeeType(models.TextChoices):
    BACKOFFICE = 'backoffice', 'Backoffice Support'
    MANAGEMENT = 'management', 'Management'
    OTHER = 'other', 'Other'

class PresenceStatus(models.TextChoices):
    PRESENT = 'present', 'Present'
    ABSENT = 'absent', 'Absent'
    LATE = 'late', 'Late'
    LEAVE = 'leave', 'On Leave'
    WORK_FROM_HOME = 'wfh', 'Work From Home'
    BUSINESS_TRIP = 'business_trip', 'Business Trip'

class Presence(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='presences')
    date = models.DateField(default=timezone.now)
    status = models.CharField(
        max_length=20,
        choices=PresenceStatus.choices,
        default=PresenceStatus.ABSENT
    )
    marked_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='presence_marked'
    )
    marked_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'date'], name='unique_presence_per_user_per_day')
        ]
        ordering = ['-date', 'user__first_name']

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} - {self.date} - {self.get_status_display()}"

'''---------------------------------- Finance ----------------------------------'''
from django.db import models
from django.contrib.auth.models import User

TRANSACTION_TYPES = (
    ('income', 'Income'),
    ('expense', 'Expense'),
    ('transfer', 'Transfer'),
)



class ChartOfAccount(models.Model):
    name = models.CharField(max_length=100)
    account_type = models.CharField(max_length=50)  # asset, liability, income, expense
    code = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return f"{self.code} - {self.name}"


class Transaction(models.Model):
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, blank=True)
    account = models.ForeignKey(ChartOfAccount, on_delete=models.PROTECT)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    date = models.DateField(auto_now_add=True)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} ({self.account.name})"


class Vendor(models.Model):
    name = models.CharField(max_length=100)
    service = models.CharField(max_length=100, blank=True)  # e.g., "OCR API", "Cloud Hosting"
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return self.name


class Payment(models.Model):
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, blank=True)
    date = models.DateField()
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    paid_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"Payment to {self.vendor.name} - {self.amount}"


class ClientPayment(models.Model):
    client = models.ForeignKey(ClientProfile, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, blank=True)
    date = models.DateField()
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    received_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    reference_note = models.TextField(blank=True)

    def __str__(self):
        return f"Payment from {self.client.company_name} - {self.amount}"
