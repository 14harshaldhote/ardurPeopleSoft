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
    session_key = models.CharField(max_length=40)  # Removed unique=True
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    login_time = models.DateTimeField(default=timezone.now)
    logout_time = models.DateTimeField(null=True, blank=True)
    working_hours = models.DurationField(null=True, blank=True)
    idle_time = models.DurationField(default=timedelta(0))
    last_activity = models.DateTimeField(default=timezone.now)
    location = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'login_time']),
        ]


    def generate_session_key():
        """Generate a unique session key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=40))

    @classmethod
    def get_or_create_session(cls, user, session_key=None, ip_address=None):
        """Get existing active session or create new one"""
        current_time = timezone.now()
        
        # Look for an active session from today
        today_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
        existing_session = cls.objects.filter(
            user=user,
            login_time__gte=today_start,
            logout_time__isnull=True
        ).first()

        if existing_session:
            # If the user has been inactive for more than 30 minutes, end the session and create a new one
            if (current_time - existing_session.last_activity) > timedelta(minutes=30):
                existing_session.end_session()
                session_key = generate_session_key()  # Generate new session key
                return cls.objects.create(
                    user=user,
                    session_key=session_key,
                    ip_address=ip_address
                )
            else:
                # Update last activity and continue with the same session
                existing_session.update_activity()
                return existing_session
        
        # If no active session, create a new session
        if not session_key:
            session_key = generate_session_key()  # Generate a new session key
        return cls.objects.create(
            user=user,
            session_key=session_key,
            ip_address=ip_address
        )
    def save(self, *args, **kwargs):
        current_time = timezone.now()

        if not self.pk:
            self.last_activity = self.login_time

        if self.logout_time:
            # Calculate the total duration and idle time when the session is ended
            total_duration = self.logout_time - self.login_time
            time_since_last_activity = self.logout_time - self.last_activity

            # Only count as idle if more than 5 minutes of inactivity
            if time_since_last_activity > timedelta(minutes=5):
                self.idle_time = time_since_last_activity
            
            self.working_hours = total_duration - self.idle_time
        else:
            # Calculate the duration and idle time if the session is ongoing
            time_since_login = current_time - self.login_time
            time_since_last_activity = current_time - self.last_activity

            # Only count as idle if more than 5 minutes of inactivity
            if time_since_last_activity > timedelta(minutes=5):
                self.idle_time += time_since_last_activity

            self.working_hours = time_since_login - self.idle_time

        self.location = self.determine_location()
        super().save(*args, **kwargs)


        
    """Determine if the user is working from home or office based on IP address."""

    def determine_location(self):
        office_ips = ['116.75.62.90']  # Ensure this matches the real office IP
        ip = self.ip_address.strip()  # Remove spaces

        print(f"Detected IP: {ip}")  # Debugging: See actual stored IP

        return 'Office' if ip in office_ips else 'Home'


    def update_activity(self):
        """Update the last activity timestamp"""
        current_time = timezone.now()
        time_since_last_activity = current_time - self.last_activity
        
        # Only count as idle if more than 5 minutes of inactivity
        if time_since_last_activity > timedelta(minutes=5):
            self.idle_time += time_since_last_activity
            
        self.last_activity = current_time
        self.save(update_fields=['last_activity', 'idle_time'])

    def end_session(self):
        """End the current session"""
        if not self.logout_time:
            current_time = timezone.now()
            time_since_last_activity = current_time - self.last_activity
            
            # Only count as idle if more than 5 minutes of inactivity
            if time_since_last_activity > timedelta(minutes=5):
                self.idle_time += time_since_last_activity
                
            self.logout_time = current_time
            self.last_activity = current_time
            self.save()



'''---------- ATTENDANCE AREA ----------'''

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Leave(models.Model):
    LEAVE_TYPES = [
        ('Sick Leave', 'Sick Leave'),
        ('Casual Leave', 'Casual Leave'),
        ('Earned Leave', 'Earned Leave'),
        ('Loss of Pay', 'Loss of Pay'),
    ]
    
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    leave_days = models.IntegerField(null=True, blank=True)
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(
        User, related_name='leave_approvals', on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Leave Request by {self.user.username} for {self.leave_type}"

    def calculate_leave_days(self):
        if self.start_date and self.end_date:
            self.leave_days = (self.end_date - self.start_date).days + 1
            return self.leave_days

    def save(self, *args, **kwargs):
        if not self.leave_days:
            self.leave_days = self.calculate_leave_days()
        super().save(*args, **kwargs)
        self.update_attendance_status()

    def update_attendance_status(self):
        """Update attendance status for the user during the leave period"""
        if self.status == 'Approved':
            attendance_records = Attendance.objects.filter(
                user=self.user,
                date__range=[self.start_date, self.end_date]
            )
            for attendance in attendance_records:
                attendance.status = 'On Leave'
                attendance.save()

    @classmethod
    def get_leave_balance(cls, user):
        """Calculate leave balance dynamically"""
        TOTAL_LEAVES = 18  # Annual leave allocation, adjust as necessary

        # Get approved leaves
        approved_leaves = cls.objects.filter(
            user=user,
            status='Approved',
            start_date__year=timezone.now().year
        ).aggregate(
            total_days=models.Sum('leave_days')
        )['total_days'] or 0

        # Get pending leaves
        pending_leaves = cls.objects.filter(
            user=user,
            status='Pending',
            start_date__year=timezone.now().year
        ).aggregate(
            total_days=models.Sum('leave_days')
        )['total_days'] or 0

        available_leave = TOTAL_LEAVES - approved_leaves - pending_leaves

        return {
            'total_leave': TOTAL_LEAVES,
            'consumed_leave': approved_leaves,
            'pending_leave': pending_leaves,
            'available_leave': available_leave,
        }
    @classmethod
    def calculate_lop_per_month(cls, user, month, year):
        """Calculate the number of Loss of Pay days taken per month for the user"""
        lop_leaves = cls.objects.filter(
            user=user,
            leave_type='Loss of Pay',
            status='Approved',
            start_date__year=year,
            start_date__month=month
        )
        
        # Count total LOP days in the given month
        total_lop_days = 0
        for leave in lop_leaves:
            # Add leave days for each leave request
            total_lop_days += leave.leave_days

        return total_lop_days


    
    @classmethod
    def can_apply_leave(cls, user, requested_days):
        """Check if user can apply for leave"""
        balance = cls.get_leave_balance(user)
        return balance['available_leave'] >= requested_days

from django.contrib.auth.models import User, Group
from django.conf import settings
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError


class Attendance(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'),
        ('Pending', 'Pending'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
        ('Weekend', 'Weekend'),
        ('Holiday', 'Holiday'),
    ]

    LOCATION_CHOICES = [
        ('Office', 'Office'),
        ('Home', 'Work From Home'),
        ('Remote', 'Remote'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Correctly reference the default User model
        on_delete=models.CASCADE
    )
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    location = models.CharField(max_length=20, choices=LOCATION_CHOICES, null=True, blank=True)
    clock_in_time = models.DateTimeField(null=True, blank=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)
    total_hours = models.DurationField(null=True, blank=True)
    leave_request = models.ForeignKey(
        'Leave',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='attendances'
    )
    last_updated = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ['user', 'date']
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date']),
        ]

    def clean(self):
        """Validate attendance record"""
        if self.clock_in_time and self.clock_out_time:
            if self.clock_in_time > self.clock_out_time:
                raise ValidationError("Clock-out time must be after clock-in time")

    def process_attendance(self, user_sessions):
        """Comprehensive attendance processing"""
        if self.date.weekday() >= 6:  # Weekend check
            self.status = 'Weekend'
            self._reset_times()
            return self

        if self.leave_request and self.leave_request.status == 'Approved':  # Leave check
            self.status = 'On Leave'
            self._reset_times()
            return self

        # Get existing clock times before processing new sessions
        existing_clock_in = self.clock_in_time
        existing_clock_out = self.clock_out_time

        if not user_sessions:  # No sessions found
            if existing_clock_in is None:  # Only update if no previous clock-in
                self.status = 'Absent' if self.date < timezone.now().date() else 'Pending'
                self._reset_times()
            return self

        # Process sessions
        total_seconds = self._calculate_total_work_time(user_sessions)
        self.total_hours = timezone.timedelta(seconds=total_seconds)

        # Update clock times only if they haven't been set
        first_session = user_sessions.first()
        last_session = user_sessions.last()
        
        if not existing_clock_in:
            self.clock_in_time = first_session.login_time
        
        if last_session.logout_time:  # Only update clock-out if session is ended
            self.clock_out_time = last_session.logout_time

        # Determine location
        self.location = self._determine_location(user_sessions)
        self.status = 'Work From Home' if self.location == 'Home' else 'Present'

        return self

    def _calculate_total_work_time(self, sessions):
        """Calculate total work time from user sessions"""
        total_seconds = 0
        for session in sessions:
            duration = (session.logout_time or timezone.now()) - session.login_time
            if session.idle_time:
                duration -= session.idle_time
            total_seconds += max(duration.total_seconds(), 0)
        return total_seconds

    def _determine_location(self, sessions):
        """Determine work location from sessions"""
        locations = [session.location for session in sessions]
        return 'Home' if 'Home' in locations else 'Office'

    def _reset_times(self):
        """Reset time-related fields"""
        self.clock_in_time = None
        self.clock_out_time = None
        self.total_hours = None
        self.location = None

    def save(self, *args, **kwargs):
        """Enhanced save method with comprehensive processing"""
        recalculate = kwargs.pop('recalculate', False)

        self.full_clean()

        # Link leave request if not already linked
        if not self.leave_request:
            self.leave_request = Leave.objects.filter(
                user=self.user,
                start_date__lte=self.date,
                end_date__gte=self.date,
                status='Approved'
            ).first()

        # Only recalculate if explicitly requested or it's a new record
        if recalculate or not self.pk:
            user_sessions = UserSession.objects.filter(
                user=self.user,
                login_time__date=self.date
            ).order_by('login_time')

            self.process_attendance(user_sessions)

        super().save(*args, **kwargs)



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
from django.core.exceptions import ValidationError

from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.models import User, Group

class UserDetails(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    dob = models.DateField(null=True, blank=True)
    blood_group = models.CharField(
        max_length=10, 
        choices=[ ('', '--------'),
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
    hire_date = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[('', '--------'),('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], null=True, blank=True)
    
    panno = models.CharField(max_length=10, null=True, blank=True)

    job_description = models.TextField(null=True, blank=True)
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
        blank=True,         null=True, 
 # No default value here
    )
    emergency_contact_address = models.TextField(null=True, blank=True)
    emergency_contact_primary = models.CharField(max_length=13, null=True, blank=True)
    emergency_contact_name = models.CharField(max_length=100, null=True, blank=True)
    start_date = models.DateField(null=True, blank=True)
    work_location = models.CharField(max_length=100, null=True, blank=True)
    contact_number_primary = models.CharField(max_length=13, null=True, blank=True)
    country_code = models.CharField(max_length=5, null=True, blank=True)  # Add this field
    personal_email = models.EmailField(null=True, blank=True)
    aadharno = models.CharField(max_length=14, null=True, blank=True)  # To store Aadhar with spaces
    group = models.ForeignKey('auth.Group', on_delete=models.SET_NULL, null=True, blank=True)

    # Ensure the contact number is in the correct format

    def __str__(self):
        return f"Details for {self.user.username}" 


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
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='timesheets')
    week_start_date = models.DateField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='timesheets')  # Linked to Project
    task_name = models.CharField(max_length=255)
    hours = models.FloatField()
    approval_status = models.CharField(
        max_length=10,
        choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')],
        default='Pending'
    )
    manager_comments = models.TextField(blank=True, null=True)  # Allows manager to provide feedback
    submitted_at = models.DateTimeField(auto_now_add=True)  # Tracks when the timesheet was submitted
    reviewed_at = models.DateTimeField(null=True, blank=True)  # Tracks when the timesheet was reviewed

    def __str__(self):
        return f"Timesheet for {self.project.name} - {self.week_start_date}"

    class Meta:
        unique_together = ('user', 'week_start_date', 'project', 'task_name')  # Prevent duplicates
        ordering = ['-week_start_date']
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
        except Timesheet.DoesNotExist:
            pass


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
    
    

'''---------------- chat -----------------------'''
from django.db import models
from django.contrib.auth.models import User

class Chat(models.Model):
    CHAT_TYPES = [
        ('personal', 'Personal'),
        ('group', 'Group')
    ]
    
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=20, choices=CHAT_TYPES)
    members = models.ManyToManyField(User, related_name='chats')
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        related_name='created_chats', 
        null=True
    )

    def get_last_message(self):
        """Retrieve the most recent message in the chat."""
        return self.messages.order_by('-timestamp').first()

    def get_other_member(self, current_user):
        """Get the other member in a personal chat."""
        if self.type == 'personal':
            return self.members.exclude(id=current_user.id).first()
        return None

    def __str__(self):
        return f"{self.name} ({self.type})"

class Message(models.Model):
    chat = models.ForeignKey(Chat, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    read_by = models.ManyToManyField(User, related_name='read_messages')


    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = 'Messages'

    def __str__(self):
        return f"Message from {self.sender} at {self.timestamp}"
    

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
