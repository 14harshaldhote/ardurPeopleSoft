from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.utils.timezone import now
from django.conf import settings
from datetime import timedelta
from django.dispatch import receiver
import datetime


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
    login_time = models.DateTimeField(default=timezone.now)
    logout_time = models.DateTimeField(null=True, blank=True)
    working_hours = models.DurationField(null=True, blank=True)
    idle_time = models.DurationField(default=timedelta(0))
    last_activity = models.DateTimeField(default=timezone.now)
    location = models.CharField(max_length=50, null=True, blank=True)
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
    def get_or_create_session(cls, user, session_key=None, ip_address=None):
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
            
            self.save(update_fields=['logout_time', 'is_active', 'working_hours'])
            
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
    
    
from datetime import time, timedelta
from django.utils import timezone
from django.db import models
from django.core.exceptions import ValidationError

class Attendance(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'), 
        ('Late', 'Late'),
        ('Half Day', 'Half Day'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
        ('Weekend', 'Weekend'),
        ('Holiday', 'Holiday')
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Absent')
    is_half_day = models.BooleanField(default=False)
    leave_type = models.CharField(max_length=50, null=True, blank=True)
    clock_in_time = models.DateTimeField(null=True, blank=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)
    breaks = models.JSONField(default=list)
    total_hours = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)
    is_weekend = models.BooleanField(default=False)
    is_holiday = models.BooleanField(default=False)
    location = models.CharField(max_length=50, default='Office')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.JSONField(null=True, blank=True)
    last_modified = models.DateTimeField(auto_now=True)
    modified_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='attendance_modifications')
    regularization_reason = models.TextField(null=True, blank=True)
    regularization_status = models.CharField(max_length=20, null=True, blank=True)
    
    class Meta:
        unique_together = ['user', 'date']
        indexes = [
            models.Index(fields=['user', 'date', 'status']),
        ]

    def clean(self):
        if self.clock_in_time and self.clock_out_time:
            if self.clock_out_time < self.clock_in_time:
                print("Validation Error: Clock out must be after clock in")
                raise ValidationError("Clock out must be after clock in")

    def calculate_hours(self):
        """Calculate total working hours including breaks"""
        if not (self.clock_in_time and self.clock_out_time):
            print("No clock in or clock out time available for calculation")
            return None
            
        total_time = (self.clock_out_time - self.clock_in_time).total_seconds() / 3600
        
        # Handle breaks if they exist
        break_time = 0
        if self.breaks:
            try:
                break_time = sum((b['end'] - b['start']).total_seconds() / 3600 
                                for b in self.breaks)
            except:
                print("Error calculating break time, using 0")
        
        print(f"Calculated total hours: {round(total_time - break_time, 2)}")
        return round(total_time - break_time, 2)

    def check_late_arrival(self):
        """Check for late arrival and apply penalties"""
        if not self.clock_in_time:
            self.status = 'Absent'
            print("No clock in time, marking status as Absent")
            return
        
        # Create a timezone-aware datetime for the start time (9:00 AM)
        # First create a naive datetime by combining the date with 9:00 AM time
        naive_start_time = timezone.datetime.combine(self.date, time(9, 0))
        
        # Then make it timezone-aware with the current timezone
        start_time = timezone.make_aware(naive_start_time)
        
        print(f"Start time (timezone-aware): {start_time}")
        print(f"Clock in time: {self.clock_in_time}")
        print(f"Is clock_in_time timezone-aware: {timezone.is_aware(self.clock_in_time)}")
        
        # Ensure clock_in_time is timezone-aware
        if timezone.is_naive(self.clock_in_time):
            self.clock_in_time = timezone.make_aware(self.clock_in_time)
            print(f"Made clock_in_time timezone-aware: {self.clock_in_time}")

        grace_period = timedelta(minutes=15)
        
        if self.clock_in_time > (start_time + grace_period):
            self.status = 'Late'
            print(f"User {self.user} is late. Status updated to Late.")
            
            # Track late arrivals but don't create automatic leave deductions
            try:
                late_count = Attendance.objects.filter(
                    user=self.user,
                    date__month=self.date.month,
                    status='Late'
                ).count()
                
                if late_count >= 3:
                    print(f"User {self.user} has {late_count} late arrivals this month.")
                    # We're just logging this information without creating automatic leave deductions
            except Exception as e:
                print(f"Error counting late arrivals: {str(e)}")

    def save(self, recalculate=False, *args, **kwargs):
        # Set weekend flag
        self.is_weekend = self.date.weekday() == 6
        self.is_holiday = self.check_if_holiday()
        
        print(f"Saving attendance for user {self.user} on {self.date}. Weekend: {self.is_weekend}, Holiday: {self.is_holiday}")
        
        # Ensure timezone awareness for datetime fields
        if self.clock_in_time and timezone.is_naive(self.clock_in_time):
            self.clock_in_time = timezone.make_aware(self.clock_in_time)
            print(f"Made clock_in_time timezone-aware during save: {self.clock_in_time}")
            
        if self.clock_out_time and timezone.is_naive(self.clock_out_time):
            self.clock_out_time = timezone.make_aware(self.clock_out_time)
            print(f"Made clock_out_time timezone-aware during save: {self.clock_out_time}")
        
        # Skip late arrival check and other processing for weekends and holidays
        if not self.is_weekend and not self.is_holiday:
            if not self.clock_in_time:
                self.status = 'Absent'
                print("No clock in time, marking status as Absent")
            else:
                # Only check late arrival for regular days
                try:
                    self.check_late_arrival()
                except Exception as e:
                    print(f"Error in check_late_arrival: {str(e)}")
                    # Don't let this error prevent saving
                
                # Calculate hours if both clock times are available
                if self.clock_in_time and self.clock_out_time:
                    try:
                        self.total_hours = self.calculate_hours()
                        
                        if self.total_hours and self.total_hours < 4:
                            self.is_half_day = True
                            print(f"Total hours less than 4, marking as half day for user {self.user}.")
                    except Exception as e:
                        print(f"Error calculating hours: {str(e)}")
                
        if recalculate and self.clock_in_time and self.clock_out_time:
            try:
                self.total_hours = self.calculate_hours()
            except Exception as e:
                print(f"Error recalculating hours: {str(e)}")
        
        super().save(*args, **kwargs)
        print(f"Attendance saved for user {self.user} on {self.date} with status {self.status}.")

    def check_if_holiday(self):
        """Check if date is a holiday"""
        # Add holiday checking logic here
        print(f"Checking if {self.date} is a holiday.")
        return False

    @classmethod
    def bulk_update_status(cls, start_date, end_date, status, reason=None):
        """Bulk update attendance status (e.g. for lockdowns)"""
        updated_count = cls.objects.filter(
            date__range=(start_date, end_date)
        ).update(
            status=status,
            regularization_reason=reason
        )
        print(f"Bulk updated attendance status to {status} for {updated_count} records from {start_date} to {end_date}.")

    @classmethod
    def get_attendance_trends(cls, user, days=30):
        """Analyze attendance patterns"""
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)
        
        attendance = cls.objects.filter(
            user=user,
            date__range=(start_date, end_date)
        )
        
        trends = {
            'late_arrivals': attendance.filter(status='Late').count(),
            'half_days': attendance.filter(is_half_day=True).count(),
            'absences': attendance.filter(status='Absent').count(),
            'wfh_days': attendance.filter(status='Work From Home').count(),
            'avg_hours': attendance.aggregate(models.Avg('total_hours'))['total_hours__avg']
        }
        
        print(f"Attendance trends for user {user}: {trends}")
        return trends

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
