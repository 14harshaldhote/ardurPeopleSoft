from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.utils.timezone import now
from django.conf import settings
from django.dispatch import receiver
from datetime import time, timedelta, date
from datetime import datetime
from django.db import transaction
from django.utils.timezone import localtime
from django.db import transaction




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

class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    login_time = models.DateTimeField(default=timezone.now)  # Stored in UTC
    logout_time = models.DateTimeField(null=True, blank=True)
    working_hours = models.DurationField(null=True, blank=True)
    idle_time = models.DurationField(default=timedelta(0))
    last_activity = models.DateTimeField(default=timezone.now)  # Stored in UTC
    location = models.CharField(max_length=50, null=True, blank=True)
    session_duration = models.FloatField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    # Define constants at the model level
    IDLE_THRESHOLD_MINUTES = 5
    SESSION_TIMEOUT_MINUTES = 30
    OFFICE_IPS = ['116.75.62.90']

    class Meta:
        indexes = [
            models.Index(fields=['user', 'login_time']),
            models.Index(fields=['is_active']),
        ]

    @staticmethod
    def generate_session_key():
        """Generate a unique session key"""
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=40))
    @staticmethod
    def get_current_time_utc():
        """Get current time in UTC for database operations"""
        # Django's timezone.now() returns timezone-aware UTC time by default
        # When USE_TZ=True, Django stores datetime in UTC regardless of TIME_ZONE setting
        return timezone.now()

    @staticmethod
    def convert_to_local_time(utc_time):
        """Convert UTC time to local timezone (e.g., IST)"""
        if utc_time is None:
            return None
        from django.utils.timezone import localtime
        return localtime(utc_time)

    def get_login_time_local(self):
        """Get login time in local timezone"""
        return self.convert_to_local_time(self.login_time)

    def get_last_activity_local(self):
        """Get last activity time in local timezone"""
        return self.convert_to_local_time(self.last_activity)
    
    def get_logout_time_local(self):
        """Get logout time in local timezone"""
        return self.convert_to_local_time(self.logout_time)

    @classmethod
    def get_or_create_session(cls, user, session_key=None, ip_address=None, user_agent=None):
        """Get existing active session or create new one"""
        from django.db import transaction
        
        with transaction.atomic():
            current_time = cls.get_current_time_utc()  # Get current UTC time
            
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
                        user_agent=user_agent,
                        login_time=current_time,
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
                user_agent=user_agent,
                login_time=current_time,
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
        return 'Office' if ip in self.OFFICE_IPS else 'Home'

    def update_activity(self, current_time=None, is_idle=False):
        """Update the last activity timestamp and calculate idle time"""
        from django.db import transaction
        
        with transaction.atomic():
            current_time = current_time or self.get_current_time_utc()
            
            # Calculate time since last activity
            time_since_last_activity = current_time - self.last_activity
            
            # Only update idle time if the frontend reports user as idle
            if is_idle:
                from django.db.models import F
                UserSession.objects.filter(pk=self.pk).update(
                    idle_time=F('idle_time') + time_since_last_activity,
                    last_activity=current_time
                )
                self.refresh_from_db()
            else:
                # If not idle, just update last_activity
                self.last_activity = current_time
                self.save(update_fields=['last_activity'])
            
            return self

    def end_session(self, logout_time=None, is_idle=False):
        """End the current session"""
        if not self.is_active:
            return self
        
        with transaction.atomic():
            logout_time = logout_time or self.get_current_time_utc()
            
            # Calculate final idle time
            time_since_last_activity = logout_time - self.last_activity
            
            # Only add to idle time if the user was reported as idle
            if is_idle:
                from django.db.models import F
                UserSession.objects.filter(pk=self.pk).update(
                    idle_time=F('idle_time') + time_since_last_activity
                )
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
    
    def get_session_duration_display(self):
        """Get formatted session duration"""
        if self.session_duration is None:
            return "Session active"
        
        hours = int(self.session_duration // 60)
        minutes = int(self.session_duration % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    
    def get_total_working_hours_display(self):
        """Get formatted working hours"""
        if self.working_hours is None:
            if self.is_active:
                # Calculate working hours for active session
                current_time = self.get_current_time_utc()
                total_duration = current_time - self.login_time
                working_hours = total_duration - self.idle_time
                total_seconds = working_hours.total_seconds()
            else:
                return "N/A"
        else:
            total_seconds = self.working_hours.total_seconds()
            
        # Ensure we don't show negative time
        total_seconds = max(0, total_seconds)
        
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        
        return f"{hours}h {minutes}m"
            
    def save(self, *args, **kwargs):
        # Set location if not already set for new sessions
        if not self.pk and not self.location:
            self.location = self.determine_location()
            
        # Ensure all times are timezone aware
        if self.login_time and timezone.is_naive(self.login_time):
            self.login_time = timezone.make_aware(self.login_time)
            
        if self.last_activity and timezone.is_naive(self.last_activity):
            self.last_activity = timezone.make_aware(self.last_activity)
            
        if self.logout_time and timezone.is_naive(self.logout_time):
            self.logout_time = timezone.make_aware(self.logout_time)
            
        super().save(*args, **kwargs)

'''----------------------------------- LEAVE AREA -----------------------------------'''
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import User

class LeavePolicy(models.Model):
    """
    Model to define leave policies based on user groups/roles
    """
    name = models.CharField(max_length=100)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='leave_policies')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} for {self.group.name}"

class LeaveType(models.Model):
    """
    Dynamic leave types that can be created by HR
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    is_paid = models.BooleanField(default=True)
    requires_approval = models.BooleanField(default=True)
    requires_documentation = models.BooleanField(default=False)
    count_weekends = models.BooleanField(default=False)
    can_be_half_day = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class LeaveAllocation(models.Model):
    """
    Allocation of different leave types for specific policies
    """
    policy = models.ForeignKey(LeavePolicy, on_delete=models.CASCADE, related_name='allocations')
    leave_type = models.ForeignKey(LeaveType, on_delete=models.CASCADE)
    annual_days = models.DecimalField(max_digits=5, decimal_places=1)
    carry_forward_limit = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    max_consecutive_days = models.IntegerField(default=0)  # 0 means no limit
    advance_notice_days = models.IntegerField(default=0)  # How many days in advance leave should be requested
    
    class Meta:
        unique_together = ('policy', 'leave_type')
        
    def __str__(self):
        return f"{self.leave_type.name} allocation for {self.policy.name}"

class UserLeaveBalance(models.Model):
    """
    Tracks individual user's leave balances
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leave_balances')
    leave_type = models.ForeignKey(LeaveType, on_delete=models.CASCADE)
    year = models.IntegerField()
    allocated = models.DecimalField(max_digits=5, decimal_places=1)
    used = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    carried_forward = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    additional = models.DecimalField(max_digits=5, decimal_places=1, default=0)  # For comp-offs or special additions
    
    class Meta:
        unique_together = ('user', 'leave_type', 'year')
        
    @property
    def available(self):
        return self.allocated + self.carried_forward + self.additional - self.used
    
    def __str__(self):
        return f"{self.user.username}'s {self.leave_type.name} balance for {self.year}"
        
class LeaveRequest(models.Model):
    """
    Enhanced leave request model with dynamic leave types
    """
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'), 
        ('Cancelled', 'Cancelled')
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leave_requests')
    leave_type = models.ForeignKey(LeaveType, on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    half_day = models.BooleanField(default=False)
    leave_days = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(User, related_name='leave_approvals', on_delete=models.SET_NULL, null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    suggested_dates = models.JSONField(null=True, blank=True)
    documentation = models.FileField(upload_to='leave_docs/', null=True, blank=True)
    is_retroactive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    _balance_updated = False  # Flag to track if balance has been updated
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'start_date', 'status']),
        ]
    
    def clean(self):
        if not self.user_id:
            raise ValidationError("User is required")
            
        # Check if end date is after start date
        if self.start_date > self.end_date:
            raise ValidationError("End date must be after start date")
        
        # Check if leave type allows half day
        if self.half_day and not self.leave_type.can_be_half_day:
            raise ValidationError(f"{self.leave_type.name} cannot be taken as half day")
        
        # Check for documentation if required
        if self.leave_type.requires_documentation and not self.documentation:
            raise ValidationError(f"{self.leave_type.name} requires supporting documentation")
        
        # Check for advance notice requirement
        user_policy = self.get_user_policy()
        if user_policy:
            try:
                allocation = LeaveAllocation.objects.get(policy=user_policy, leave_type=self.leave_type)
                if allocation.advance_notice_days > 0 and not self.is_retroactive:
                    min_request_date = timezone.now().date() + timedelta(days=allocation.advance_notice_days)
                    if self.start_date < min_request_date:
                        raise ValidationError(
                            f"{self.leave_type.name} requires {allocation.advance_notice_days} days advance notice"
                        )
                
                # Check consecutive days limit
                if allocation.max_consecutive_days > 0:
                    days_requested = (self.end_date - self.start_date).days + 1
                    if days_requested > allocation.max_consecutive_days:
                        raise ValidationError(
                            f"You can only take {allocation.max_consecutive_days} consecutive days of {self.leave_type.name}"
                        )
            except LeaveAllocation.DoesNotExist:
                pass
        
        # Check for overlapping leaves
        overlapping_leaves = LeaveRequest.objects.filter(
            status='Approved',
            start_date__lte=self.end_date,
            end_date__gte=self.start_date,
            user=self.user
        ).exclude(id=self.id)
        
        if overlapping_leaves.exists():
            raise ValidationError("You already have approved leave during this period")
        
        # Check leave balance
        if not self.has_sufficient_balance():
            raise ValidationError(f"Insufficient {self.leave_type.name} balance")
    
    def get_user_policy(self):
        """Get the applicable leave policy for this user"""
        if not self.user_id:
            return None
            
        user_groups = self.user.groups.all()
        if not user_groups:
            return None
        
        # Get the first active policy that matches any of user's groups
        try:
            return LeavePolicy.objects.filter(
                group__in=user_groups,
                is_active=True
            ).first()
        except LeavePolicy.DoesNotExist:
            return None
    
    def calculate_leave_days(self):
        """Calculate actual leave days based on leave type configuration"""
        if not (self.start_date and self.end_date):
            return 0
            
        total_days = 0
        current_date = self.start_date
        
        while current_date <= self.end_date:
            # Skip weekends unless leave type counts weekends
            is_weekend = current_date.weekday() >= 5  # Saturday or Sunday
            
            if not is_weekend or self.leave_type.count_weekends:
                if self.half_day:
                    total_days += 0.5
                else:
                    total_days += 1.0
                    
            current_date += timedelta(days=1)
            
        return total_days

    def has_sufficient_balance(self):
        """Check if user has sufficient leave balance"""
        if not self.user_id:
            print("DEBUG: has_sufficient_balance - no user_id")
            return False
            
        # Skip balance check for unpaid leave types
        if not self.leave_type.is_paid:
            print(f"DEBUG: has_sufficient_balance - leave type not paid, returning True")
            return True
            
        year = self.start_date.year
        try:
            balance = UserLeaveBalance.objects.get(
                user=self.user,
                leave_type=self.leave_type,
                year=year
            )
            days_needed = self.calculate_leave_days()
            has_balance = balance.available >= days_needed
            print(f"DEBUG: has_sufficient_balance - available: {balance.available}, needed: {days_needed}, result: {has_balance}")
            return has_balance
        except UserLeaveBalance.DoesNotExist:
            print(f"DEBUG: has_sufficient_balance - no balance record found")
            return False
    
    def auto_convert_leave_type(self):
        """Try to convert to Loss of Pay if insufficient balance"""
        # Find Loss of Pay leave type
        try:
            loss_of_pay = LeaveType.objects.get(name='Loss of Pay', is_paid=False)
            self.leave_type = loss_of_pay
            return True
        except LeaveType.DoesNotExist:
            return False
    
    def update_leave_balance(self):
        """Update leave balance when leave is approved - tracks ALL leave types (paid and unpaid)"""
        print(f"DEBUG: Updating leave balance for user {self.user_id}, leave type {self.leave_type}")
        if not self.user_id:
            print(f"DEBUG: Skipping balance update - no user_id")
            return

        # IMPORTANT: Removed the check for is_paid - we track ALL leave types now
        # This allows tracking of unpaid leave like Loss of Pay/Leave Without Pay
        year = self.start_date.year
        print(f"DEBUG: Looking for balance record for year {year}")
        
        # Ensure leave_days is a Decimal for arithmetic operations
        from decimal import Decimal
        leave_days_decimal = Decimal(str(self.leave_days))
        
        try:
            balance = UserLeaveBalance.objects.get(
                user=self.user,
                leave_type=self.leave_type,
                year=year
            )
            print(f"DEBUG: Found balance - current used: {balance.used}, adding: {leave_days_decimal}")
            
            # Use the Decimal version for the addition
            balance.used = balance.used + leave_days_decimal
            balance.save()
            
            print(f"DEBUG: Updated balance - new used total: {balance.used}")
            self._balance_updated = True
        except UserLeaveBalance.DoesNotExist:
            print(f"DEBUG: No balance record found for user {self.user_id}, leave type {self.leave_type}, year {year}")
            # Try to create a balance record for this user
            policy = self.get_user_policy()
            if policy:
                try:
                    allocation = LeaveAllocation.objects.get(
                        policy=policy, 
                        leave_type=self.leave_type
                    )
                    # Create a new balance record
                    balance = UserLeaveBalance.objects.create(
                        user=self.user,
                        leave_type=self.leave_type,
                        year=year,
                        allocated=allocation.annual_days,
                        used=leave_days_decimal,  # Use Decimal version
                        carried_forward=0,
                        additional=0
                    )
                    print(f"DEBUG: Created new balance record with {allocation.annual_days} days and used {leave_days_decimal}")
                    self._balance_updated = True
                except LeaveAllocation.DoesNotExist:
                    # For unpaid leave types that might not have allocations
                    # We create a record with zero allocation but still track usage
                    print(f"DEBUG: No allocation found for leave type {self.leave_type} in user's policy")
                    balance = UserLeaveBalance.objects.create(
                        user=self.user,
                        leave_type=self.leave_type,
                        year=year,
                        allocated=0,  # No allocation for unpaid leave
                        used=leave_days_decimal,  # Use Decimal version
                        carried_forward=0,
                        additional=0
                    )
                    print(f"DEBUG: Created tracking-only balance record with 0 allocation and {leave_days_decimal} used")
                    self._balance_updated = True
            else:
                print(f"DEBUG: No active policy found for user {self.user_id}")
                # Even without a policy, we might want to create a record to track usage
                balance = UserLeaveBalance.objects.create(
                    user=self.user,
                    leave_type=self.leave_type,
                    year=year,
                    allocated=0,
                    used=leave_days_decimal,  # Use Decimal version
                    carried_forward=0,
                    additional=0
                )
                print(f"DEBUG: Created default tracking record with 0 allocation and {leave_days_decimal} used")
                self._balance_updated = True
            
    def revert_leave_balance(self):
        """Revert leave balance when leave is cancelled/rejected"""
        if not self.user_id or self.status != 'Approved':
            return
        
        # REMOVED: condition for is_paid - we revert all leave types
        year = self.start_date.year
        
        # Ensure leave_days is a Decimal for arithmetic operations
        from decimal import Decimal
        leave_days_decimal = Decimal(str(self.leave_days))
        
        try:
            balance = UserLeaveBalance.objects.get(
                user=self.user,
                leave_type=self.leave_type,
                year=year
            )
            
            # Use the Decimal version for the subtraction
            balance.used = balance.used - leave_days_decimal
            balance.save()
            
            print(f"DEBUG: Reverted balance - removed {leave_days_decimal} days, new used total: {balance.used}")
        except UserLeaveBalance.DoesNotExist:
            print(f"DEBUG: No balance record found to revert for {self.user_id}, {self.leave_type}")
            pass
    

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        previous_status = None
        old_leave_days = 0

        if not self.user_id:
            raise ValidationError("User is required")

        # Add debugging info
        print(f"DEBUG: save() called for leave request ID: {self.id if not is_new else 'new'}")
        print(f"DEBUG: Current status: {self.status}, User: {self.user_id}, Leave type: {self.leave_type}")
        print(f"DEBUG: Leave type is_paid: {self.leave_type.is_paid}")

        # Convert half_day string to boolean if needed
        if isinstance(self.half_day, str):
            self.half_day = self.half_day.lower() == 'true'

        # Calculate leave days
        self.leave_days = self.calculate_leave_days()
        print(f"DEBUG: Calculated leave days: {self.leave_days}")

        if not is_new:
            try:
                previous = LeaveRequest.objects.get(id=self.id)
                previous_status = previous.status
                old_leave_days = previous.leave_days
                print(f"DEBUG: Previous status: {previous_status}, Old leave days: {old_leave_days}")
            except LeaveRequest.DoesNotExist:
                print("DEBUG: Could not find previous leave request")
                pass

        try:
            with transaction.atomic():
                super().save(*args, **kwargs)
                
                print(f"DEBUG: After save, status: {self.status}")

                if self.status == 'Approved':
                    print(f"DEBUG: Request is approved, is_new: {is_new}, previous_status: {previous_status}")
                    if is_new or previous_status != 'Approved':
                        # Always update balance for approved requests
                        # REMOVED CONDITION: if self.leave_type.is_paid:
                        # We now track ALL leave types, paid or unpaid
                        print("DEBUG: About to update leave balance")
                        self.update_leave_balance()
                        print("DEBUG: Leave balance update completed")
                        self.update_attendance()
                    elif previous_status == 'Approved' and self.leave_days != old_leave_days:
                        print(f"DEBUG: Leave days changed from {old_leave_days} to {self.leave_days}")
                        # Handle case where leave days changed for an already approved request
                        try:
                            balance = UserLeaveBalance.objects.get(
                                user=self.user,
                                leave_type=self.leave_type,
                                year=self.start_date.year
                            )
                            # Adjust the difference
                            balance.used = balance.used - old_leave_days + self.leave_days
                            balance.save()
                            print(f"DEBUG: Updated balance for changed leave days. New used: {balance.used}")
                        except UserLeaveBalance.DoesNotExist:
                            print("DEBUG: No balance record found for adjustment")
                            self.update_leave_balance()  # Try to create and update the balance

                elif previous_status == 'Approved' and self.status != 'Approved':
                    print("DEBUG: Leave request was approved before but no longer approved, reverting balance")
                    self.revert_leave_balance()

                # For balance check, we still respect is_paid for determining if sufficient balance
                if is_new and self.leave_type.is_paid and not self.has_sufficient_balance():
                    print("DEBUG: Insufficient balance, attempting auto-convert")
                    converted = self.auto_convert_leave_type()
                    if converted:
                        print(f"DEBUG: Converted to leave type: {self.leave_type}")
        except Exception as e:
            print(f"DEBUG: Exception occurred in save method: {str(e)}")
            raise
    
    
    def update_attendance(self):
        """Update attendance records for approved leave period"""
        if not self.user_id:
            return
            
        current_date = self.start_date
        while current_date <= self.end_date:
            is_weekend = current_date.weekday() >= 5  # Saturday or Sunday
            
            # Skip weekends unless leave type counts weekends
            if not is_weekend or self.leave_type.count_weekends:
                defaults = {
                    'status': 'On Leave',
                    'leave_type': self.leave_type.name,
                    'is_half_day': self.half_day,
                    'remarks': f"Auto-marked by leave system: {self.leave_type.name}"
                }
                    
                Attendance.objects.update_or_create(
                    user=self.user,
                    date=current_date,
                    defaults=defaults
                )
            current_date += timedelta(days=1)

class CompOffRequest(models.Model):
    """
    Model to track comp-off requests and approvals
    """
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected')
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comp_off_requests')
    worked_date = models.DateField()
    reason = models.TextField()
    hours_worked = models.DecimalField(max_digits=4, decimal_places=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(User, related_name='comp_off_approvals', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        
        # If approved, update the user's comp-off balance
        if self.status == 'Approved':
            self.update_comp_off_balance()
    
    def update_comp_off_balance(self):
        """Update user's comp-off balance when request is approved"""
        # Find comp-off leave type
        try:
            comp_off_type = LeaveType.objects.get(name='Comp Off')
            year = self.worked_date.year
            
            # Calculate days - typical 8 hour workday
            days_earned = self.hours_worked / 8.0
            
            balance, created = UserLeaveBalance.objects.get_or_create(
                user=self.user,
                leave_type=comp_off_type,
                year=year,
                defaults={'allocated': 0}
            )
            
            balance.additional += days_earned
            balance.save()
            
            # Update attendance record
            Attendance.objects.update_or_create(
                user=self.user,
                date=self.worked_date,
                defaults={
                    'status': 'Comp Off',
                    'is_weekend': True if self.worked_date.weekday() >= 5 else False,
                    'total_hours': self.hours_worked,
                    'overtime_hours': self.hours_worked,
                    'is_overtime_approved': True,
                    'remarks': f"Comp-off approved for {self.hours_worked} hours"
                }
            )
        except LeaveType.DoesNotExist:
            pass

        

'''---------- ATTENDANCE AREA ----------'''

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
from datetime import timedelta, time
import calendar
from django.conf import settings
from decimal import Decimal
import logging

# Configure logger
logger = logging.getLogger(__name__)

class Attendance(models.Model):
    """
    Attendance tracking model integrated with user sessions, leave and shift systems
    """
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
        ('Not Marked', 'Not Marked')
    ]

    LOCATION_CHOICES = [
        ('Office', 'Office'),
        ('Home', 'Home'),
        ('Remote', 'Remote'),
        ('Other', 'Other')
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Not Marked')
    is_half_day = models.BooleanField(default=False)
    leave_type = models.CharField(max_length=50, null=True, blank=True)
    clock_in_time = models.DateTimeField(null=True, blank=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)
    breaks = models.JSONField(default=list)
    total_hours = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    expected_hours = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    is_weekend = models.BooleanField(default=False)
    is_holiday = models.BooleanField(default=False)
    holiday_name = models.CharField(max_length=100, blank=True, null=True)
    location = models.CharField(max_length=50, choices=LOCATION_CHOICES, default='Office')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.JSONField(null=True, blank=True)
    shift = models.ForeignKey('ShiftMaster', on_delete=models.SET_NULL, null=True, blank=True)
    late_minutes = models.IntegerField(default=0)
    early_departure_minutes = models.IntegerField(default=0)
    left_early = models.BooleanField(default=False)
    last_modified = models.DateTimeField(auto_now=True)
    modified_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='attendance_modifications')
    regularization_reason = models.TextField(null=True, blank=True)
    regularization_status = models.CharField(max_length=20, choices=[
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected')
    ], null=True, blank=True)
    requested_status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES,
        null=True, 
        blank=True,
        help_text="Status requested by employee during regularization"
    )
    
    # Session tracking
    first_session = models.ForeignKey('UserSession', on_delete=models.SET_NULL, null=True, blank=True, related_name='first_session_attendance')
    last_session = models.ForeignKey('UserSession', on_delete=models.SET_NULL, null=True, blank=True, related_name='last_session_attendance')
    total_sessions = models.IntegerField(default=0)
    idle_time = models.DurationField(default=timedelta(0))
    
    overtime_hours = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    is_overtime_approved = models.BooleanField(default=False)
    # Additional fields for the Attendance model:
    original_clock_in_time = models.DateTimeField(null=True, blank=True)
    original_clock_out_time = models.DateTimeField(null=True, blank=True)
    original_status = models.CharField(max_length=20, null=True, blank=True)
    is_employee_notified = models.BooleanField(default=False)
    is_hr_notified = models.BooleanField(default=False)
    regularization_attempts = models.IntegerField(default=0)
    last_regularization_date = models.DateTimeField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)
    class Meta:
        unique_together = ('user', 'date')
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date', 'status']),
        ]
        ordering = ['-date', 'user']
    
    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.status}"
    
    def save(self, *args, **kwargs):
        logger.debug(f"save() called for {self.user.username} - {self.date}")

        # Auto-calculate total hours if clock-in and clock-out are provided
        if self.clock_in_time and self.clock_out_time and self.clock_out_time > self.clock_in_time:
            logger.debug(f"Calculating total hours for {self.user.username}")
            # Calculate duration in hours with 2 decimal precision
            duration = self.clock_out_time - self.clock_in_time
            hours = duration.total_seconds() / 3600
            self.total_hours = round(Decimal(str(hours)), 2)
            
            # Subtract idle time if present
            if self.idle_time:
                logger.debug(f"Subtracting idle time: {self.idle_time}")
                idle_hours = self.idle_time.total_seconds() / 3600
                self.total_hours = max(0, self.total_hours - round(Decimal(str(idle_hours)), 2))
        
        # Calculate overtime based on shift if present
        if self.shift and self.total_hours and self.total_hours > self.shift.shift_duration:
            logger.debug(f"Calculating overtime for {self.user.username}")
            self.overtime_hours = self.total_hours - Decimal(str(self.shift.shift_duration))
        
        # Mark weekend based on date
        weekday = self.date.weekday()
        is_weekend = False
        
        if self.shift:
            logger.debug(f"Checking shift weekend rules for {self.user.username}")
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            current_day = day_names[weekday]
            
            if self.shift.work_days == 'Weekdays':
                is_weekend = weekday >= 5  # Saturday/Sunday
            elif self.shift.work_days == 'All Days':
                is_weekend = False  # All days are working
            elif self.shift.work_days == 'Custom' and self.shift.custom_work_days:
                custom_days = [day.strip() for day in self.shift.custom_work_days.split(',')]
                is_weekend = current_day not in custom_days
        else:
            # Default weekend check if no shift is assigned
            logger.debug("No shift assigned, using default weekend rules")
            is_weekend = weekday >= 5
            
        self.is_weekend = is_weekend
        
        # Check for holidays
        try:
            logger.debug("Checking for holidays")
            holiday = Holiday.objects.filter(
                Q(date=self.date) | 
                (Q(recurring_yearly=True) & 
                 Q(date__day=self.date.day, date__month=self.date.month))
            ).first()
            
            if holiday:
                logger.debug(f"Holiday found: {holiday.name}")
                self.is_holiday = True
                self.holiday_name = holiday.name
                if not self.is_on_leave():  # Don't override leave status
                    self.status = 'Holiday'
        except Exception as e:
            logger.error(f"Error checking holidays: {e}")
        
        # Set weekend status if not on leave and is a weekend
        if not self.is_on_leave() and self.is_weekend and self.status not in ['Present', 'Present & Late', 'Work From Home', 'Comp Off']:
            logger.debug("Setting weekend status")
            self.status = 'Weekend'
        
        # Set late status if clock-in time is after shift start time + grace period
        if self.clock_in_time and self.shift and self.status not in ['On Leave', 'Holiday', 'Weekend']:
            logger.debug("Checking late status")
            # Create datetime objects for comparison
            clock_in_time = self.clock_in_time.time()
            shift_start = self.shift.start_time
            
            # Default grace period of 10 minutes
            grace_minutes = 10
            if hasattr(self.shift, 'grace_period'):
                grace_period = self.shift.grace_period
                grace_minutes = grace_period.total_seconds() // 60
            
            # Calculate shift start time with grace period as minutes since midnight
            shift_start_minutes = shift_start.hour * 60 + shift_start.minute
            grace_end_minutes = shift_start_minutes + grace_minutes
            
            # Calculate clock-in time as minutes since midnight
            clock_in_minutes = clock_in_time.hour * 60 + clock_in_time.minute
            
            if clock_in_minutes > grace_end_minutes:
                logger.debug(f"Late by {clock_in_minutes - shift_start_minutes} minutes")
                self.late_minutes = clock_in_minutes - shift_start_minutes
                
                # If very late (more than half the shift duration), mark as half day
                shift_duration_minutes = self.shift.shift_duration * 60
                if self.late_minutes > (shift_duration_minutes / 2) and not self.is_on_leave():
                    logger.debug("Marking as half day due to late arrival")
                    self.status = 'Half Day'
                else:
                    # Only mark as late if they're not already marked otherwise
                    self.status = 'Present & Late'
            elif not self.is_on_leave() and not self.is_holiday and not self.is_weekend:
                # They clocked in on time, mark as present if not overridden by another status
                logger.debug("On-time attendance, marking as present")
                self.status = 'Present'
        
        # Set early departure status if clock-out time is before shift end time
        if self.clock_out_time and self.shift:
            logger.debug("Checking early departure")
            clock_out_time = self.clock_out_time.time()
            shift_end = self.shift.end_time
            
            # Calculate as minutes since midnight
            shift_end_minutes = shift_end.hour * 60 + shift_end.minute
            clock_out_minutes = clock_out_time.hour * 60 + clock_out_time.minute
            
            if clock_out_minutes < shift_end_minutes:
                logger.debug(f"Left early by {shift_end_minutes - clock_out_minutes} minutes")
                self.left_early = True
                self.early_departure_minutes = shift_end_minutes - clock_out_minutes
                
                # If left very early, mark as half day
                shift_duration_minutes = self.shift.shift_duration * 60
                if self.early_departure_minutes > (shift_duration_minutes / 2) and not self.is_on_leave():
                    logger.debug("Marking as half day due to early departure")
                    self.status = 'Half Day'
        
        # Set present status if total hours meet minimum threshold and not marked otherwise
        if (self.total_hours and self.total_hours >= Decimal('4.0') and 
            self.status not in ['Present & Late', 'On Leave', 'Holiday', 'Weekend', 'Half Day', 'Comp Off'] and
            not self.is_on_leave()):
            logger.debug("Marking as present based on total hours")
            self.status = 'Present'
        
         # Check if previously marked as half day due to early departure but now returned
        if self.status == 'Half Day' and self.left_early and self.total_hours:
            # If they've now completed at least half the shift duration, mark as present
            if self.shift and self.total_hours >= (Decimal(str(self.shift.shift_duration)) / 2):
                logger.debug(f"User returned after early departure and completed enough hours")
                self.left_early = False
                self.early_departure_minutes = 0
                
                # Set appropriate present status
                if self.late_minutes > 0:
                    self.status = 'Present & Late'
                else:
                    self.status = 'Present'
        
        super().save(*args, **kwargs)
        logger.debug(f"save() completed for {self.user.username} - {self.date}")
    
    def is_on_leave(self):
        """Helper method to check if user is on leave"""
        logger.debug(f"is_on_leave() called for {self.user.username}")
        return self.status == 'On Leave' or (self.leave_type is not None and self.leave_type != '')

    @classmethod
    def create_attendance(cls, user, clock_in_time, location='Office', ip_address=None, device_info=None):
        """
        Create a new attendance record when a user logs in
        """
        logger.info(f"Creating attendance for {user.username} at {clock_in_time}")
        
        # Ensure we're using local time
        if timezone.is_naive(clock_in_time):
            clock_in_time = timezone.make_aware(clock_in_time)
        
        # Get the date from the clock_in_time
        attendance_date = clock_in_time.date()
        
        # Check if an attendance record exists for today
        attendance, created = cls.objects.get_or_create(
            user=user,
            date=attendance_date,
            defaults={
                'clock_in_time': clock_in_time,
                'location': location,
                'ip_address': ip_address,
                'device_info': device_info,
            }
        )
        
        if not created:
            logger.debug(f"Attendance record already exists for {user.username} on {attendance_date}")
            # Only update clock_in_time if it's earlier than the existing one
            if attendance.clock_in_time is None or clock_in_time < attendance.clock_in_time:
                attendance.clock_in_time = clock_in_time
                attendance.save(update_fields=['clock_in_time'])
        
        # Try to get the user's shift
        try:
            current_shift = ShiftAssignment.get_user_current_shift(user, attendance_date)
            if current_shift:
                attendance.shift = current_shift
                attendance.expected_hours = Decimal(str(current_shift.shift_duration))
                
                # Determine if user is late based on shift start time
                clock_in_time_obj = clock_in_time.time()
                shift_start = current_shift.start_time
                
                # Default grace period of 10 minutes
                grace_minutes = 10
                if hasattr(current_shift, 'grace_period'):
                    grace_period = current_shift.grace_period
                    grace_minutes = grace_period.total_seconds() // 60
                
                # Calculate comparison values in minutes since midnight
                shift_start_minutes = shift_start.hour * 60 + shift_start.minute
                grace_end_minutes = shift_start_minutes + grace_minutes
                clock_in_minutes = clock_in_time_obj.hour * 60 + clock_in_time_obj.minute
                
                if clock_in_minutes > grace_end_minutes:
                    logger.info(f"User {user.username} is late by {clock_in_minutes - shift_start_minutes} minutes")
                    attendance.late_minutes = clock_in_minutes - shift_start_minutes
                    attendance.status = 'Present & Late'
                else:
                    logger.info(f"User {user.username} is present on time")
                    attendance.status = 'Present'
                
                # Check for leave or holidays
                is_leave = False
                is_holiday = False
                
                # Check for approved leave
                try:
                    leave_request = LeaveRequest.objects.filter(
                        user=user,
                        status='Approved',
                        start_date__lte=attendance_date,
                        end_date__gte=attendance_date
                    ).first()
                    
                    if leave_request:
                        logger.info(f"User {user.username} is on {leave_request.leave_type.name} leave")
                        attendance.leave_type = leave_request.leave_type.name
                        attendance.is_half_day = leave_request.half_day
                        attendance.status = 'Half Day' if leave_request.half_day else 'On Leave'
                        is_leave = True
                except Exception as e:
                    logger.error(f"Error checking leave status: {e}")
                
                # Check for holidays
                if not is_leave:
                    try:
                        holiday = Holiday.objects.filter(
                            Q(date=attendance_date) | 
                            (Q(recurring_yearly=True) & 
                            Q(date__day=attendance_date.day, date__month=attendance_date.month))
                        ).first()
                        
                        if holiday:
                            logger.info(f"Today is a holiday: {holiday.name}")
                            attendance.is_holiday = True
                            attendance.holiday_name = holiday.name
                            attendance.status = 'Holiday'
                            is_holiday = True
                    except Exception as e:
                        logger.error(f"Error checking holidays: {e}")
                
                # Check for weekend
                if not is_leave and not is_holiday:
                    weekday = attendance_date.weekday()
                    is_weekend = False
                    
                    if current_shift.work_days == 'Weekdays':
                        is_weekend = weekday >= 5  # Saturday/Sunday
                    elif current_shift.work_days == 'All Days':
                        is_weekend = False  # All days are working
                    elif current_shift.work_days == 'Custom' and current_shift.custom_work_days:
                        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                        current_day = day_names[weekday]
                        custom_days = [day.strip() for day in current_shift.custom_work_days.split(',')]
                        is_weekend = current_day not in custom_days
                    
                    if is_weekend:
                        logger.info(f"Today is a weekend for user {user.username}")
                        attendance.is_weekend = True
                        attendance.status = 'Weekend'
                
                attendance.save()
            else:
                # No shift assigned, just mark as present
                logger.warning(f"No shift assigned for user {user.username}")
                attendance.status = 'Present'
                attendance.save()

        except Exception as e:
            logger.error(f"Error getting shift for user {user.username}: {e}")
            # If there was an error getting the shift, just mark as present
            attendance.status = 'Present'
            attendance.save()
        
        return attendance

    

    @classmethod
    def clock_out(cls, user, clock_out_time):
        """
        Update an attendance record when a user logs out
        """
        logger.info(f"Clock out for {user.username} at {clock_out_time}")
        
        # Ensure we're using local time
        if timezone.is_naive(clock_out_time):
            clock_out_time = timezone.make_aware(clock_out_time)
        
        # Get attendance record for today
        attendance_date = clock_out_time.date()
        try:
            attendance = cls.objects.get(user=user, date=attendance_date)
            
            # Update clock out time
            attendance.clock_out_time = clock_out_time
            
            # Calculate total hours
            if attendance.clock_in_time and attendance.clock_out_time > attendance.clock_in_time:
                duration = attendance.clock_out_time - attendance.clock_in_time
                hours = duration.total_seconds() / 3600
                attendance.total_hours = round(Decimal(str(hours)), 2)
                
                # Subtract idle time if present
                if attendance.idle_time:
                    idle_hours = attendance.idle_time.total_seconds() / 3600
                    attendance.total_hours = max(0, attendance.total_hours - round(Decimal(str(idle_hours)), 2))
            
            # Check for early departure
            if attendance.shift:
                clock_out_time_obj = clock_out_time.time()
                shift_end = attendance.shift.end_time
                
                # Calculate as minutes since midnight
                shift_end_minutes = shift_end.hour * 60 + shift_end.minute
                clock_out_minutes = clock_out_time_obj.hour * 60 + clock_out_time_obj.minute
                
                if clock_out_minutes < shift_end_minutes:
                    logger.info(f"User {user.username} left early by {shift_end_minutes - clock_out_minutes} minutes")
                    attendance.left_early = True
                    attendance.early_departure_minutes = shift_end_minutes - clock_out_minutes
                    
                    # If left very early, mark as half day
                    shift_duration_minutes = attendance.shift.shift_duration * 60
                    if attendance.early_departure_minutes > (shift_duration_minutes / 2) and not attendance.is_on_leave():
                        logger.info("Marking as half day due to early departure")
                        attendance.status = 'Half Day'
            
            attendance.save()
            return attendance
        except cls.DoesNotExist:
            logger.warning(f"No attendance record found for user {user.username} on {attendance_date}")
            return None
        except Exception as e:
            logger.error(f"Error clocking out user {user.username}: {e}")
            return None

    @classmethod
    def record_session_activity(cls, user_session):
        """
        Record or update attendance based on user session activity
        """
        logger.debug(f"record_session_activity() called for {user_session.user.username}")
        from decimal import Decimal
        
        # Get today's date in the user's timezone if available, otherwise use server timezone
        if hasattr(user_session, 'timezone'):
            user_tz = timezone.get_current_timezone()
            login_time_local = timezone.localtime(user_session.login_time, user_tz)
            today = login_time_local.date()
        else:
            today = timezone.localtime(user_session.login_time).date()
        
        # Check if an attendance record exists for today
        attendance, created = cls.objects.get_or_create(
            user=user_session.user,
            date=today,
            defaults={
                'status': 'Not Marked',
                'clock_in_time': user_session.login_time,
                'first_session': user_session,
                'last_session': user_session,
                'total_sessions': 1,
                'ip_address': user_session.ip_address,
                'device_info': user_session.user_agent,
                'location': 'Office' if hasattr(user_session, 'OFFICE_IPS') and user_session.ip_address in user_session.OFFICE_IPS else 'Remote',
            }
        )
        
        if not created:
            logger.debug("Updating existing attendance record")
            # Update the existing attendance record
            if not attendance.clock_in_time or user_session.login_time < attendance.clock_in_time:
                attendance.clock_in_time = user_session.login_time
                attendance.first_session = user_session
            
            # Always update the last session and clock-out time
            attendance.last_session = user_session
            
            # Only update clock_out_time if user has actually logged out
            if user_session.logout_time:
                attendance.clock_out_time = user_session.logout_time
            elif user_session.last_activity and not user_session.is_active:
                # Use last activity as checkout only if session is inactive
                attendance.clock_out_time = user_session.last_activity
            
            # Increment session count
            attendance.total_sessions += 1
            
            # Accumulate idle time
            if hasattr(user_session, 'idle_time') and user_session.idle_time:
                logger.debug(f"Adding idle time: {user_session.idle_time}")
                if attendance.idle_time:
                    attendance.idle_time += user_session.idle_time
                else:
                    attendance.idle_time = user_session.idle_time
            
            # Update IP and device info if needed
            if not attendance.ip_address:
                attendance.ip_address = user_session.ip_address
            
            if not attendance.device_info and hasattr(user_session, 'user_agent'):
                attendance.device_info = user_session.user_agent
            
            # Update location based on IP
            if hasattr(user_session, 'OFFICE_IPS') and user_session.ip_address in user_session.OFFICE_IPS and attendance.location != 'Office':
                attendance.location = 'Office'
        
        # Get the user's current shift
        try:
            logger.debug("Getting current shift")
            current_shift = ShiftAssignment.get_user_current_shift(user_session.user, today)
            if current_shift:
                attendance.shift = current_shift
                attendance.expected_hours = Decimal(str(current_shift.shift_duration))
                
                # Check for late arrival
                if attendance.status not in ['On Leave', 'Holiday', 'Weekend']:
                    clock_in_time = attendance.clock_in_time.time()
                    shift_start = current_shift.start_time
                    
                    # Default grace period of 10 minutes
                    grace_minutes = 10
                    if hasattr(current_shift, 'grace_period'):
                        grace_period = current_shift.grace_period
                        grace_minutes = grace_period.total_seconds() // 60
                    
                    # Calculate shift start time with grace period
                    shift_start_minutes = shift_start.hour * 60 + shift_start.minute
                    grace_end_minutes = shift_start_minutes + grace_minutes
                    
                    # Calculate clock-in time
                    clock_in_minutes = clock_in_time.hour * 60 + clock_in_time.minute
                    
                    if clock_in_minutes > grace_end_minutes:
                        logger.info(f"User {user_session.user.username} is late by {clock_in_minutes - shift_start_minutes} minutes")
                        attendance.late_minutes = clock_in_minutes - shift_start_minutes
                        attendance.status = 'Present & Late'
                    else:
                        logger.info(f"User {user_session.user.username} is present on time")
                        attendance.status = 'Present'
        except Exception as e:
            logger.error(f"Error getting current shift: {e}")
        
        # Check for leave status
        try:
            logger.debug("Checking leave status")
            leave_request = LeaveRequest.objects.filter(
                user=user_session.user,
                status='Approved',
                start_date__lte=today,
                end_date__gte=today
            ).first()
            
            if leave_request:
                logger.info(f"Leave found: {leave_request.leave_type.name}")
                attendance.leave_type = leave_request.leave_type.name
                attendance.is_half_day = leave_request.half_day
                
                if leave_request.half_day:
                    attendance.status = 'Half Day'
                else:
                    attendance.status = 'On Leave'
        except Exception as e:
            logger.error(f"Error checking leave status: {e}")
        
        # Calculate total hours if complete
        if attendance.clock_in_time and attendance.clock_out_time and attendance.clock_out_time > attendance.clock_in_time:
            logger.debug("Calculating total hours")
            duration = attendance.clock_out_time - attendance.clock_in_time
            hours = duration.total_seconds() / 3600
            attendance.total_hours = round(Decimal(str(hours)), 2)
            
            # Subtract idle time
            if attendance.idle_time:
                logger.debug(f"Subtracting idle time: {attendance.idle_time}")
                idle_hours = attendance.idle_time.total_seconds() / 3600
                attendance.total_hours = max(Decimal('0'), attendance.total_hours - Decimal(str(idle_hours)))
                
        # Check if status was half day due to early departure
        if attendance.status == 'Half Day' and attendance.left_early and attendance.total_hours:
            # If they've now completed at least half the shift duration, mark as present
            if attendance.shift and attendance.total_hours >= (Decimal(str(attendance.shift.shift_duration)) / 2):
                logger.debug(f"User {user_session.user.username} returned after early departure and completed enough hours")
                attendance.left_early = False
                attendance.early_departure_minutes = 0
                
                # Set appropriate present status
                if attendance.late_minutes > 0:
                    attendance.status = 'Present & Late'
                else:
                    attendance.status = 'Present'
                # Save the record

        attendance.save()
        logger.debug(f"record_session_activity() completed for {user_session.user.username}")
        return attendance        

    @classmethod
    def auto_mark_attendance(cls):
        """
        Automatically mark attendance for all users based on their sessions and leave
        """
        today = timezone.localtime(timezone.now()).date()
        
        # Get all active users
        from django.contrib.auth import get_user_model
        User = get_user_model()
        users = User.objects.filter(is_active=True)
        
        for user in users:
            # Check if attendance already marked
            attendance = cls.objects.filter(user=user, date=today).first()
            
            if not attendance:
                # Get user sessions for today
                sessions = UserSession.objects.filter(
                    user=user,
                    login_time__date=today
                ).order_by('login_time')
                
                if sessions.exists():
                    # Create attendance from sessions
                    first_session = sessions.first()
                    cls.record_session_activity(first_session)
                else:
                    # Check if user is on leave
                    try:
                        leave_request = LeaveRequest.objects.filter(
                            user=user,
                            status='Approved',
                            start_date__lte=today,
                            end_date__gte=today
                        ).first()
                        
                        if leave_request:
                            # Create attendance record for leave
                            cls.objects.create(
                                user=user,
                                date=today,
                                status='On Leave' if not leave_request.half_day else 'Half Day',
                                is_half_day=leave_request.half_day,
                                leave_type=leave_request.leave_type.name,
                                regularization_reason=f"Auto-marked by leave system: {leave_request.leave_type.name}"
                            )
                        else:
                            # Check if today is a holiday or weekend
                            weekday = today.weekday()
                            is_weekend = False
                            
                            # Get user's current shift
                            current_shift = None
                            try:
                                current_shift = ShiftAssignment.get_user_current_shift(user, today)
                            except:
                                pass
                            
                            # Override weekend based on shift if available
                            if current_shift:
                                day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                                current_day = day_names[weekday]
                                
                                if current_shift.work_days == 'Weekdays':
                                    is_weekend = weekday >= 5  # Saturday/Sunday
                                elif current_shift.work_days == 'All Days':
                                    is_weekend = False  # All days are working
                                elif current_shift.work_days == 'Custom' and current_shift.custom_work_days:
                                    custom_days = [day.strip() for day in current_shift.custom_work_days.split(',')]
                                    is_weekend = current_day not in custom_days
                            else:
                                # Default weekend check if no shift is assigned
                                is_weekend = weekday >= 5
                            
                            # Check for holiday
                            is_holiday = False
                            holiday_name = None
                            try:
                                holiday = Holiday.objects.filter(
                                    Q(date=today) | 
                                    (Q(recurring_yearly=True) & 
                                     Q(date__day=today.day, date__month=today.month))
                                ).first()
                                
                                if holiday:
                                    print(f"Holiday found: {holiday.name}")
                                    is_holiday = True
                                    holiday_name = holiday.name
                            except:
                                print("Error checking holiday")
                                pass
                            
                            if is_holiday:
                                print("Creating holiday attendance")
                                # Create holiday attendance
                                cls.objects.create(
                                    user=user,
                                    date=today,
                                    status='Holiday',
                                    is_holiday=True,
                                    holiday_name=holiday_name,
                                    shift=current_shift,
                                    regularization_reason=f"Holiday: {holiday_name}"
                                )
                            elif is_weekend:
                                print("Creating weekend attendance")
                                # Create weekend attendance
                                cls.objects.create(
                                    user=user,
                                    date=today,
                                    status='Weekend',
                                    is_weekend=True,
                                    shift=current_shift,
                                    regularization_reason="Weekend"
                                )
                            else:
                                print("Marking as absent")
                                # Mark as absent if it's a workday
                                cls.objects.create(
                                    user=user,
                                    date=today,
                                    status='Absent',
                                    shift=current_shift,
                                    regularization_reason="Auto-marked as absent (no activity)"
                                )
                    except Exception as e:
                        print(f"Error auto-marking attendance for {user.username}: {str(e)}")
            else:
                print(f"Existing attendance found for {user.username}")
                # Update existing attendance if needed
                if attendance.status == 'Not Marked':
                    print("Updating not marked attendance")
                    # Get all sessions for the day
                    sessions = UserSession.objects.filter(
                        user=user,
                        login_time__date=today
                    ).order_by('login_time')
                    
                    if sessions.exists():
                        print(f"Found {sessions.count()} sessions")
                        # Update attendance with session data
                        first_session = sessions.first()
                        last_session = sessions.order_by('-login_time').first()
                        
                        attendance.first_session = first_session
                        attendance.last_session = last_session
                        attendance.total_sessions = sessions.count()
                        
                        # Set clock in/out times
                        attendance.clock_in_time = first_session.login_time
                        
                        # Only update clock_out_time if user has actually logged out
                        if last_session.logout_time:
                            attendance.clock_out_time = last_session.logout_time
                        elif last_session.last_activity and not last_session.is_active:
                            attendance.clock_out_time = last_session.last_activity
                        
                        # Calculate total hours only if session is complete
                        if attendance.clock_in_time and attendance.clock_out_time:
                            print("Calculating total hours")
                            duration = attendance.clock_out_time - attendance.clock_in_time
                            hours = duration.total_seconds() / 3600
                            attendance.total_hours = round(Decimal(str(hours)), 2)
                        
                        # Calculate idle time if available
                        idle_time = timedelta(0)
                        for session in sessions:
                            if hasattr(session, 'idle_time') and session.idle_time:
                                idle_time += session.idle_time
                        
                        if idle_time:
                            print(f"Adding idle time: {idle_time}")
                            attendance.idle_time = idle_time
                            if attendance.total_hours:
                                idle_hours = idle_time.total_seconds() / 3600
                                attendance.total_hours = max(Decimal('0'), attendance.total_hours - Decimal(str(idle_hours)))
                        
                        attendance.save()
        
        print("auto_mark_attendance() completed")
        return True
    @classmethod
    def get_monthly_report(cls, user, year, month):
        """
        Generate monthly attendance report for a user
        """
        from calendar import monthrange
        
        # Get days in month
        days_in_month = monthrange(year, month)[1]
        start_date = timezone.datetime(year, month, 1).date()
        end_date = timezone.datetime(year, month, days_in_month).date()
        
        # Fetch all attendance records for the month
        records = cls.objects.filter(
            user=user,
            date__gte=start_date,
            date__lte=end_date
        ).order_by('date')
        
        # Create a dict with all days in the month
        report = {
            'user': user,
            'year': year,
            'month': month,
            'days': {},
            'summary': {
                'present': 0,
                'present_late': 0,
                'absent': 0,
                'late': 0,
                'half_day': 0,
                'on_leave': 0,
                'holiday': 0,
                'weekend': 0,
                'work_from_home': 0,
                'comp_off': 0,
                'not_marked': 0,
                'total_hours': Decimal('0'),
                'overtime_hours': Decimal('0'),
                'leave_days_used': Decimal('0'),
                'total_present': 0,
                'leave_request_count': 0,
                'approved_leave_count': 0
            }
        }
        
        # Initialize days
        for day in range(1, days_in_month + 1):
            current_date = timezone.datetime(year, month, day).date()
            weekday = current_date.weekday()
            is_weekend = weekday >= 5  # Saturday or Sunday
            
            # Default record for the day
            report['days'][day] = {
                'date': current_date,
                'weekday': current_date.strftime('%A'),
                'status': 'Not Marked',
                'is_weekend': is_weekend,
                'is_holiday': False,
                'holiday_name': None,
                'clock_in_time': None,
                'clock_out_time': None,
                'total_hours': Decimal('0'),
                'overtime_hours': Decimal('0'),
                'late_minutes': 0,
                'early_departure_minutes': 0,
                'leave_type': None,
                'is_half_day': False,
                'remarks': None,
                'idle_time': None
            }
        
        # Fill in actual attendance records
        for record in records:
            day = record.date.day
            report['days'][day].update({
                'status': record.status,
                'is_weekend': record.is_weekend,
                'is_holiday': record.is_holiday,
                'holiday_name': record.holiday_name,
                'clock_in_time': record.clock_in_time,
                'clock_out_time': record.clock_out_time,
                'total_hours': record.total_hours or Decimal('0'),
                'overtime_hours': record.overtime_hours,
                'late_minutes': record.late_minutes,
                'early_departure_minutes': record.early_departure_minutes,
                'leave_type': record.leave_type,
                'is_half_day': record.is_half_day,
                'remarks': record.regularization_reason,
                'location': record.location,
                'idle_time': record.idle_time
            })
            
            # Update summary counters
            status_key = record.status.lower().replace(' & ', '_').replace(' ', '_')
            if status_key in report['summary']:
                report['summary'][status_key] += 1
            
            if record.total_hours:
                report['summary']['total_hours'] += record.total_hours
            
            report['summary']['overtime_hours'] += record.overtime_hours
            
            if record.leave_type:
                # Count half days as 0.5
                leave_days = Decimal('0.5') if record.is_half_day else Decimal('1.0')
                report['summary']['leave_days_used'] += leave_days

            # Update total present count
            if record.status in ['Present', 'Present & Late', 'Work From Home']:
                report['summary']['total_present'] += 1

            # Update leave request counts
            if record.regularization_status == 'Pending':
                report['summary']['leave_request_count'] += 1
            elif record.regularization_status == 'Approved':
                report['summary']['approved_leave_count'] += 1
        
        return report

# class Attendance(models.Model):
#     STATUS_CHOICES = [
#         ('Present', 'Present'),
#         ('Present & Late', 'Present & Late'), 
#         ('Absent', 'Absent'),
#         ('Late', 'Late'),
#         ('Half Day', 'Half Day'),
#         ('On Leave', 'On Leave'),
#         ('Work From Home', 'Work From Home'),
#         ('Weekend', 'Weekend'),
#         ('Holiday', 'Holiday'),
#         ('Comp Off', 'Comp Off'),
#         ('Not Marked', 'Not Marked')
#     ]

#     LOCATION_CHOICES = [
#         ('Office', 'Office'),
#         ('Home', 'Home'),
#         ('Remote', 'Remote'), 
#         ('Other', 'Other')
#     ]

#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     date = models.DateField()
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Not Marked')
#     is_half_day = models.BooleanField(default=False)
#     leave_type = models.CharField(max_length=50, null=True, blank=True)
#     clock_in_time = models.DateTimeField(null=True, blank=True)
#     clock_out_time = models.DateTimeField(null=True, blank=True)
#     breaks = models.JSONField(default=list)
#     total_hours = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
#     expected_hours = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
#     is_weekend = models.BooleanField(default=False)
#     is_holiday = models.BooleanField(default=False)
#     location = models.CharField(max_length=50, choices=LOCATION_CHOICES, default='Office')
#     ip_address = models.GenericIPAddressField(null=True, blank=True)
#     device_info = models.JSONField(null=True, blank=True)
#     shift = models.ForeignKey('ShiftMaster', on_delete=models.SET_NULL, null=True, blank=True)
#     late_minutes = models.IntegerField(default=0)
#     last_modified = models.DateTimeField(auto_now=True)
#     modified_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='attendance_modifications')
#     regularization_reason = models.TextField(null=True, blank=True)
#     regularization_status = models.CharField(max_length=20, choices=[
#         ('Pending', 'Pending'),
#         ('Approved', 'Approved'),
#         ('Rejected', 'Rejected')
#     ], null=True, blank=True)
#     user_session = models.ForeignKey('UserSession', on_delete=models.SET_NULL, null=True, blank=True)
#     overtime_hours = models.DecimalField(max_digits=5, decimal_places=2, default=0)
#     is_overtime_approved = models.BooleanField(default=False)
#     remarks = models.TextField(null=True, blank=True)

#     class Meta:
#         unique_together = ['user', 'date']
#         indexes = [
#             models.Index(fields=['user', 'date', 'status']),
#             models.Index(fields=['shift']),
#             models.Index(fields=['date']),
#             models.Index(fields=['user', 'status']),
#         ]

#     def __str__(self):
#         return f"{self.user.username} - {self.date} - {self.status}"

#     def check_late_arrival(self):
#         """Check if user arrived late based on shift timing"""
#         if not self.clock_in_time:
#             self.status = 'Not Marked'
#             return

#         try:
#             # Get user's shift if not set
#             if not self.shift:
#                 from .models import ShiftAssignment
#                 self.shift = ShiftAssignment.get_user_current_shift(self.user, self.date)
#                 if not self.shift:
#                     self.status = 'Present'
#                     return

#             # Convert clock_in_time to local timezone (IST)
#             user_clock_in = timezone.localtime(self.clock_in_time)
            
#             # Get the date in local timezone to properly handle day boundaries
#             local_date = timezone.localtime(timezone.make_aware(
#                 datetime.combine(self.date, time(0, 0)),
#                 timezone.get_current_timezone()
#             )).date()
            
#             # Create shift start time in local timezone
#             local_shift_start = timezone.make_aware(
#                 datetime.combine(local_date, self.shift.start_time),
#                 timezone.get_current_timezone()
#             )
            
#             # Add grace period
#             grace_period = getattr(self.shift, 'grace_period', timedelta(minutes=10))
#             latest_allowed_time = local_shift_start + grace_period
            
#             # Compare clock in time with allowed time - now both are in local timezone
#             if user_clock_in > latest_allowed_time:
#                 self.status = 'Present & Late'
#                 # Calculate late minutes
#                 late_duration = user_clock_in - latest_allowed_time
#                 self.late_minutes = int(late_duration.total_seconds() // 60)
#             else:
#                 self.status = 'Present'

#         except Exception as e:
#             import traceback
#             print(f"Error checking late arrival: {str(e)}")
#             print(f"Traceback: {traceback.format_exc()}")
#             self.status = 'Present'

#     def check_early_departure(self):
#         """Check if user left early based on shift timing"""
#         if not (self.clock_in_time and self.clock_out_time) or not self.shift:
#             return False
        
#         try:
#             # Convert clock_out_time to user's timezone
#             user_clock_out = timezone.localtime(self.clock_out_time)
            
#             # Get shift end time for the date in user's timezone
#             shift_end = timezone.make_aware(
#                 timezone.datetime.combine(self.date, self.shift.end_time),
#                 timezone.get_current_timezone()
#             )
            
#             # Consider grace period for leaving early (10 minutes)
#             early_leave_threshold = shift_end - timedelta(minutes=10)
            
#             if user_clock_out < early_leave_threshold:
#                 early_minutes = int((shift_end - user_clock_out).total_seconds() // 60)
#                 self.remarks = f"{self.remarks or ''} Left early by {early_minutes} minutes."
#                 return True
#             return False
#         except Exception as e:
#             print(f"Error checking early departure: {str(e)}")
#             return False

#     def calculate_hours(self):
#         """Calculate total working hours excluding breaks"""
#         if not (self.clock_in_time and self.clock_out_time):
#             return None

#         try:
#             # Convert times to user's timezone
#             user_clock_in = timezone.localtime(self.clock_in_time)
#             user_clock_out = timezone.localtime(self.clock_out_time)

#             # Calculate total duration
#             total_time = (user_clock_out - user_clock_in).total_seconds() / 3600

#             # Subtract break time
#             break_time = self.calculate_break_time()
#             total_worked = total_time - break_time

#             # Calculate overtime if applicable
#             regular_hours = self.expected_hours or (self.shift.expected_hours() if self.shift else 8.0)
#             if total_worked > float(regular_hours):
#                 self.overtime_hours = round(total_worked - float(regular_hours), 2)
#             else:
#                 self.overtime_hours = 0

#             return round(total_worked, 2)

#         except Exception as e:
#             import traceback
#             print(f"Error calculating hours: {str(e)}")
#             print(f"Traceback: {traceback.format_exc()}")
#             return None

#     def calculate_break_time(self):
#         """Calculate total break time in hours"""
#         break_time = 0
#         if not self.breaks:
#             return break_time

#         try:
#             if isinstance(self.breaks, list):
#                 for break_data in self.breaks:
#                     start = break_data.get('start')
#                     end = break_data.get('end')

#                     # Convert string times to datetime if needed
#                     if isinstance(start, str):
#                         try:
#                             start = timezone.datetime.fromisoformat(start)
#                         except ValueError:
#                             continue
#                     if isinstance(end, str):
#                         try:
#                             end = timezone.datetime.fromisoformat(end)
#                         except ValueError:
#                             continue

#                     # Convert to user's timezone
#                     start = timezone.localtime(start)
#                     end = timezone.localtime(end)

#                     if start and end and end > start:
#                         break_time += (end - start).total_seconds() / 3600

#         except Exception as e:
#             print(f"Error calculating break time: {str(e)}")

#         return break_time

#     def ensure_timezone_aware(self, datetime_obj):
#         """Ensure datetime is timezone aware"""
#         if datetime_obj and timezone.is_naive(datetime_obj):
#             return timezone.make_aware(datetime_obj)
#         return datetime_obj

#     def check_weekend_holiday(self):
#         """Check if the date is a weekend or holiday"""
#         try:
#             # Check for holiday
#             from .models import Holiday
#             is_holiday = Holiday.is_holiday(self.date)
#             if is_holiday:
#                 self.status = 'Holiday'
#                 self.is_holiday = True
#                 return True
                
#             # Check for weekend based on shift settings
#             is_weekend = self.date.weekday() >= 5  # Saturday or Sunday
            
#             if is_weekend and self.shift:
#                 if self.shift.work_days == 'Custom':
#                     weekday = calendar.day_name[self.date.weekday()]
#                     if weekday not in self.shift.custom_work_days.split(','):
#                         self.status = 'Weekend'
#                         self.is_weekend = True
#                         return True
#                 elif self.shift.work_days == 'Weekdays':  # Monday to Friday
#                     self.status = 'Weekend'
#                     self.is_weekend = True
#                     return True
#                 # For 'All Days' work pattern, don't mark as weekend
#             elif is_weekend:
#                 self.status = 'Weekend'
#                 self.is_weekend = True
#                 return True
            
#             return False
#         except Exception as e:
#             print(f"Error checking weekend/holiday: {str(e)}")
#             return False

#     def check_half_day(self):
#         """Determine if attendance should be marked as half day"""
#         if not (self.clock_in_time and self.clock_out_time) or self.total_hours is None:
#             return False
        
#         try:
#             # Get expected hours from shift or default to 8 hours
#             expected_hours = float(self.expected_hours or (self.shift.shift_duration if self.shift else 8.0))
            
#             # Half day threshold is half of expected hours
#             half_day_threshold = expected_hours / 2
            
#             # If worked less than half of expected hours but more than 0, mark as half day
#             if 0 < float(self.total_hours) < half_day_threshold:
#                 self.status = 'Half Day'
#                 self.is_half_day = True
#                 return True
#             return False
#         except Exception as e:
#             print(f"Error checking half day: {str(e)}")
#             return False

#     def handle_wfh(self):
#         """Handle Work From Home attendance"""
#         # If location is set to Home, mark as WFH
#         if self.location == 'Home' and self.clock_in_time:
#             self.status = 'Work From Home'
#             return True
#         return False

#     def determine_attendance_status(self):
#         """Determine final attendance status based on various factors"""
#         # Priority order for status determination
        
#         # 1. Check for approved leave
#         from .models import Leave
#         leave = Leave.objects.filter(
#             user=self.user,
#             start_date__lte=self.date,
#             end_date__gte=self.date,
#             status='Approved'
#         ).first()
        
#         if leave:
#             self.status = 'On Leave'
#             self.leave_type = leave.leave_type
#             self.is_half_day = leave.half_day
#             return
        
#         # 2. Check for holiday/weekend
#         if self.check_weekend_holiday():
#             return
        
#         # 3. If no clock in recorded, mark as Not Marked
#         if not self.clock_in_time:
#             self.status = 'Not Marked'
#             return
        
#         # 4. Handle Work From Home
#         if self.handle_wfh():
#             return
        
#         # 5. Check for half day
#         if self.check_half_day():
#             return
        
#         # 6. Check for late arrival
#         self.check_late_arrival()
        
#         # 7. Check for early departure (doesn't change status, just adds remarks)
#         self.check_early_departure()
        
#         # If we've made it here without setting a status, default to Present
#         if not self.status or self.status == 'Not Marked':
#             self.status = 'Present'

#     def clean(self):
#         """Validate attendance data"""
#         if self.clock_in_time and self.clock_out_time:
#             if self.clock_out_time < self.clock_in_time:
#                 raise ValidationError("Clock out must be after clock in")

#         if self.breaks:
#             try:
#                 for break_data in self.breaks:
#                     start = break_data.get('start')
#                     end = break_data.get('end')
#                     if start and end:
#                         if isinstance(start, str):
#                             start = timezone.datetime.fromisoformat(start)
#                         if isinstance(end, str):
#                             end = timezone.datetime.fromisoformat(end)
#                         if end <= start:
#                             raise ValidationError("Break end time must be after start time")
#             except Exception as e:
#                 raise ValidationError(f"Invalid break data: {str(e)}")

#     def mark_comp_off(self, approved_by=None, reason=None):
#         """Mark attendance as Comp Off"""
#         try:
#             # Only allow marking comp off for non-holiday, non-weekend days
#             if self.is_holiday or self.is_weekend:
#                 return False, "Cannot mark Comp Off for weekends or holidays"
            
#             # Check if user has comp off balance
#             from .models import Leave
#             comp_off_balance = float(Leave.get_comp_off_balance(self.user))
            
#             if comp_off_balance <= 0:
#                 return False, "Insufficient Comp Off balance"
            
#             # Mark as Comp Off
#             self.status = 'Comp Off'
#             self.remarks = f"{self.remarks or ''} Comp Off used. Reason: {reason or 'Not specified'}. Approved by: {approved_by.get_full_name() if approved_by else 'System'}"
            
#             self.save()
#             return True, "Successfully marked as Comp Off"
        
#         except Exception as e:
#             return False, f"Error marking Comp Off: {str(e)}"

#     def save(self, recalculate=False, *args, **kwargs):
#         try:
#             # Ensure timezone awareness
#             self.clock_in_time = self.ensure_timezone_aware(self.clock_in_time)
#             self.clock_out_time = self.ensure_timezone_aware(self.clock_out_time)

#             # Handle breaks timezone awareness
#             if self.breaks and isinstance(self.breaks, list):
#                 for i, break_data in enumerate(self.breaks):
#                     start = break_data.get('start')
#                     end = break_data.get('end')
#                     if isinstance(start, str):
#                         try:
#                             start = timezone.datetime.fromisoformat(start)
#                             self.breaks[i]['start'] = self.ensure_timezone_aware(start)
#                         except (ValueError, TypeError):
#                             self.breaks[i]['start'] = None
#                     if isinstance(end, str):
#                         try:
#                             end = timezone.datetime.fromisoformat(end)
#                             self.breaks[i]['end'] = self.ensure_timezone_aware(end)
#                         except (ValueError, TypeError):
#                             self.breaks[i]['end'] = None

#             # Set basic flags
#             self.is_weekend = self.date.weekday() >= 5
#             self.is_holiday = self.check_if_holiday()

#             # Get shift if not set
#             if not self.shift_id:
#                 from .models import ShiftAssignment
#                 self.shift = ShiftAssignment.get_user_current_shift(self.user, self.date)

#             # Set expected hours from shift
#             if self.shift:
#                 self.expected_hours = self.shift.shift_duration

#             # Calculate total hours if clock in/out times exist
#             if self.clock_in_time and self.clock_out_time:
#                 self.total_hours = self.calculate_hours()

#             # Determine final attendance status
#             if recalculate or not self.status or self.status == 'Not Marked':
#                 self.determine_attendance_status()

#             # Check for early departure (doesn't change status, just adds remarks)
#             self.check_early_departure()

#             super().save(*args, **kwargs)

#         except Exception as e:
#             import traceback
#             print(f"Error saving attendance: {str(e)}")
#             print(f"Traceback: {traceback.format_exc()}")
#             # Still try to save basic data
#             super().save(*args, **kwargs)

#     def check_if_holiday(self):
#         """Check if date is a holiday"""
#         from .models import Holiday
#         return Holiday.is_holiday(self.date)

#     @classmethod
#     def determine_shift_date(cls, user, clock_in_time):
#         """Determine the shift date and get shift for clock in time"""
#         try:
#             # Convert clock_in_time to user's timezone
#             user_clock_in = timezone.localtime(clock_in_time)
#             attendance_date = user_clock_in.date()
            
#             from .models import ShiftAssignment
#             shift = ShiftAssignment.get_user_current_shift(user, attendance_date)
            
#             # Handle overnight shifts
#             if shift and shift.start_time > shift.end_time:
#                 # If clock in is before midnight, use current date
#                 # If clock in is after midnight, use previous date
#                 if user_clock_in.time() < shift.end_time:
#                     attendance_date = attendance_date - timedelta(days=1)
            
#             return attendance_date, shift
            
#         except Exception as e:
#             print(f"Error in determine_shift_date: {str(e)}")
#             return clock_in_time.date(), None

#     @classmethod
#     def create_attendance(cls, user, clock_in_time, location="Office", ip_address=None, device_info=None):
#         """Create new attendance record"""
#         try:
#             # Get active user session
#             from .models import UserSession
#             user_session = UserSession.objects.filter(
#                 user=user,
#                 is_active=True,
#                 login_time__date=clock_in_time.date()
#             ).first()

#             # Determine shift date and get shift
#             shift_date, shift = cls.determine_shift_date(user, clock_in_time)

#             # Check for existing leave
#             from .models import Leave
#             existing_leave = Leave.objects.filter(
#                 user=user,
#                 start_date__lte=shift_date,
#                 end_date__gte=shift_date,
#                 status='Approved'
#             ).first()

#             # Check holiday and weekend status
#             from .models import Holiday
#             is_holiday = Holiday.is_holiday(shift_date)
#             is_weekend = shift_date.weekday() >= 5
            
#             # Check if it's a working day based on shift
#             is_working_day = True
#             if shift:
#                 if shift.work_days == 'Custom':
#                     weekday = calendar.day_name[shift_date.weekday()]
#                     is_working_day = weekday in shift.custom_work_days.split(',')
#                 elif shift.work_days != 'All Days':
#                     is_working_day = not is_weekend

#             # Determine initial status
#             if existing_leave:
#                 initial_status = 'On Leave'
#                 leave_type = existing_leave.leave_type
#                 is_half_day = existing_leave.half_day
#             elif is_holiday:
#                 initial_status = 'Holiday'
#                 leave_type = None
#                 is_half_day = False
#             elif is_weekend and not is_working_day:
#                 initial_status = 'Weekend'
#                 leave_type = None
#                 is_half_day = False
#             elif location == 'Home':
#                 initial_status = 'Work From Home'
#                 leave_type = None
#                 is_half_day = False
#             else:
#                 initial_status = 'Present'
#                 leave_type = None
#                 is_half_day = False

#             # Create or update attendance
#             attendance, created = cls.objects.get_or_create(
#                 user=user,
#                 date=shift_date,
#                 defaults={
#                     'clock_in_time': clock_in_time,
#                     'status': initial_status,
#                     'location': location,
#                     'ip_address': ip_address,
#                     'device_info': device_info,
#                     'shift': shift,
#                     'expected_hours': shift.shift_duration if shift else 8.0,
#                     'is_weekend': is_weekend,
#                     'is_holiday': is_holiday,
#                     'leave_type': leave_type,
#                     'is_half_day': is_half_day,
#                     'user_session': user_session
#                 }
#             )

#             if not created and not attendance.clock_in_time:
#                 attendance.clock_in_time = clock_in_time
#                 attendance.location = location
#                 attendance.ip_address = ip_address
#                 attendance.device_info = device_info
#                 attendance.shift = shift
#                 attendance.user_session = user_session
#                 if attendance.status not in ['On Leave', 'Holiday']:
#                     attendance.status = initial_status
#                 attendance.save(recalculate=True)

#             return attendance

#         except Exception as e:
#             import traceback
#             print(f"Error creating attendance: {str(e)}")
#             print(f"Traceback: {traceback.format_exc()}")
#             # Fallback to basic attendance creation
#             return cls.objects.create(
#                 user=user,
#                 date=clock_in_time.date(),
#                 clock_in_time=clock_in_time,
#                 status='Present',
#                 location=location,
#                 ip_address=ip_address,
#                 device_info=device_info
#             )

#     @classmethod
#     def clock_out(cls, user, clock_out_time, breaks=None):
#         """Record clock out time for user"""
#         try:
#             # Convert clock_out_time to user's timezone
#             user_clock_out = timezone.localtime(clock_out_time)
#             today = user_clock_out.date()
            
#             # Get current date's attendance
#             attendance = cls.objects.filter(
#                 user=user,
#                 date=today,
#                 clock_in_time__isnull=False,
#                 clock_out_time__isnull=True
#             ).first()

#             # For overnight shifts, also check previous day
#             if not attendance:
#                 yesterday = today - timedelta(days=1)
#                 attendance = cls.objects.filter(
#                     user=user,
#                     date=yesterday,
#                     clock_in_time__isnull=False,
#                     clock_out_time__isnull=True
#                 ).first()

#             if attendance:
#                 attendance.clock_out_time = clock_out_time
#                 if breaks:
#                     attendance.breaks = breaks
#                 attendance.save(recalculate=True)
#                 return attendance
#             else:
#                 print(f"No active attendance found for user {user} to clock out.")
#                 return None

#         except Exception as e:
#             import traceback
#             print(f"Error in clock_out: {str(e)}")
#             print(f"Traceback: {traceback.format_exc()}")
#             return None

#     @classmethod
#     def get_attendance_summary(cls, user, year=None, month=None):
#         """Get monthly attendance summary"""
#         if not year:
#             year = timezone.now().year
#         if not month:
#             month = timezone.now().month

#         start_date = timezone.datetime(year, month, 1).date()
#         if month == 12:
#             end_date = timezone.datetime(year + 1, 1, 1).date() - timedelta(days=1)
#         else:
#             end_date = timezone.datetime(year, month + 1, 1).date() - timedelta(days=1)

#         from .models import ShiftAssignment
#         shift = ShiftAssignment.get_user_current_shift(user)
#         attendances = cls.objects.filter(
#             user=user,
#             date__range=(start_date, end_date)
#         )

#         working_days = 0
#         current_date = start_date
#         from .models import Holiday
#         while current_date <= end_date:
#             if shift:
#                 if shift.work_days == 'Custom':
#                     weekday = calendar.day_name[current_date.weekday()]
#                     if weekday in shift.custom_work_days.split(',') and not Holiday.is_holiday(current_date):
#                         working_days += 1
#                 elif shift.work_days == 'All Days' or (shift.work_days != 'Custom' and current_date.weekday() < 5):
#                     if not Holiday.is_holiday(current_date):
#                         working_days += 1
#             else:
#                 if current_date.weekday() < 5 and not Holiday.is_holiday(current_date):
#                     working_days += 1
#             current_date += timedelta(days=1)

#         summary = {
#             'year': year,
#             'month': month,
#             'month_name': calendar.month_name[month],
#             'working_days': working_days,
#             'present_days': attendances.filter(status='Present').count(),
#             'late_days': attendances.filter(status__in=['Late', 'Present & Late']).count(),
#             'wfh_days': attendances.filter(status='Work From Home').count(),
#             'absent_days': attendances.filter(status='Not Marked').count(),
#             'half_days': attendances.filter(is_half_day=True).count(),
#             'leave_days': attendances.filter(status='On Leave').count(),
#             'comp_off_days': attendances.filter(status='Comp Off').count(),
#             'total_hours': sum(att.total_hours or 0 for att in attendances),
#             'overtime_hours': sum(att.overtime_hours or 0 for att in attendances),
#             'avg_hours': attendances.filter(total_hours__isnull=False).aggregate(models.Avg('total_hours'))['total_hours__avg'] or 0,
#             'max_hours': attendances.filter(total_hours__isnull=False).aggregate(models.Max('total_hours'))['total_hours__max'] or 0,
#             'attendance_percentage': 0
#         }

#         if working_days > 0:
#             present_equivalent = (
#                 summary['present_days'] +
#                 summary['late_days'] +
#                 summary['wfh_days'] +
#                 (summary['half_days'] * 0.5) +
#                 summary['leave_days'] +
#                 summary['comp_off_days']
#             )
#             summary['attendance_percentage'] = round((present_equivalent / working_days) * 100, 2)

#         return summary

#     @classmethod
#     def get_annual_report(cls, user, year):
#         """Get annual attendance report"""
#         annual_data = []
#         for month in range(1, 13):
#             monthly_summary = cls.get_attendance_summary(user, year, month)
#             annual_data.append(monthly_summary)

#         yearly_totals = {
#             'working_days': sum(month['working_days'] for month in annual_data),
#             'present_days': sum(month['present_days'] for month in annual_data),
#             'late_days': sum(month['late_days'] for month in annual_data),
#             'wfh_days': sum(month['wfh_days'] for month in annual_data),
#             'absent_days': sum(month['absent_days'] for month in annual_data),
#             'half_days': sum(month['half_days'] for month in annual_data),
#             'leave_days': sum(month['leave_days'] for month in annual_data),
#             'comp_off_days': sum(month.get('comp_off_days', 0) for month in annual_data),
#             'total_hours': sum(month['total_hours'] for month in annual_data),
#             'overtime_hours': sum(month['overtime_hours'] for month in annual_data),
#         }

#         if yearly_totals['working_days'] > 0:
#             present_equivalent = (
#                 yearly_totals['present_days'] +
#                 yearly_totals['late_days'] +
#                 yearly_totals['wfh_days'] +
#                 (yearly_totals['half_days'] * 0.5) +
#                 yearly_totals['leave_days'] +
#                 yearly_totals['comp_off_days']
#             )
#             yearly_totals['attendance_percentage'] = round((present_equivalent / yearly_totals['working_days']) * 100, 2)
#         else:
#             yearly_totals['attendance_percentage'] = 0

#         return {
#             'year': year,
#             'monthly_data': annual_data,
#             'yearly_totals': yearly_totals
#         }


'''-------------------------------------------- SUPPORT AREA ---------------------------------------'''
import uuid
from django.db import models
from django.utils.timezone import now
from django.contrib.auth import get_user_model

from django.db import models
from django.utils.timezone import now
import uuid
from django.contrib.auth.models import User

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

    class AssignedGroup(models.TextChoices):
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
    assigned_group = models.CharField(max_length=50, choices=AssignedGroup.choices, null=True, blank=True)
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
    
    def save(self, *args, **kwargs):
        # Extract user from kwargs (if present) before passing to super().save()
        user = kwargs.pop('user', None)
        
        # Auto-assign tickets to HR or Admin based on issue type
        if not self.assigned_group:
            hr_issues = [self.IssueType.HR, self.IssueType.ACCESS]
            self.assigned_group = self.AssignedGroup.HR if self.issue_type in hr_issues else self.AssignedGroup.ADMIN
        
        # Track status changes
        if self.pk:
            old_ticket = Support.objects.get(pk=self.pk)
            if old_ticket.status != self.status:
                # Create a status log entry after saving
                self._status_changed = (old_ticket.status, self.status)
            else:
                self._status_changed = None
        else:
            self._status_changed = (None, self.status)
            
        super().save(*args, **kwargs)
        
        # Create status log if needed
        if hasattr(self, '_status_changed') and self._status_changed:
            old_status, new_status = self._status_changed
            StatusLog.objects.create(
                ticket=self,
                old_status=old_status if old_status else '',
                new_status=new_status,
                changed_by=user
            )


class StatusLog(models.Model):
    ticket = models.ForeignKey(Support, on_delete=models.CASCADE, related_name='status_logs')
    old_status = models.CharField(max_length=30, blank=True)
    new_status = models.CharField(max_length=30, choices=Support.Status.choices)
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    changed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ticket.ticket_id}: {self.old_status} -> {self.new_status}"


class TicketComment(models.Model):
    """Model for comments on support tickets"""
    ticket = models.ForeignKey(Support, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_internal = models.BooleanField(default=False, help_text="Internal notes only visible to staff")
    
    class Meta:
        ordering = ['created_at']
    
    def __str__(self):
        return f"Comment on {self.ticket.ticket_id} by {self.user.username}"


class TicketAttachment(models.Model):
    """Model for file attachments on tickets"""
    ticket = models.ForeignKey(Support, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to='ticket_attachments/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=255, blank=True)
    
    def __str__(self):
        return f"Attachment for {self.ticket.ticket_id}"
    
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

def validate_future_date(value):
    """Validate that a date is not in the future."""
    if value > timezone.now().date():
        raise ValidationError('Date cannot be in the future.')


def validate_pan(value):
    """Validate PAN number format."""
    if not value.isalnum() or len(value) != 10:
        raise ValidationError('PAN number must be 10 alphanumeric characters.')
    if not (value[:5].isalpha() and value[5:9].isdigit() and value[9].isalpha()):
        raise ValidationError('PAN number format is invalid. It should be in the format AAAAA0000A.')


def validate_aadhar(value):
    """Validate Aadhar number format."""
    if not value.isdigit() or len(value) != 12:
        raise ValidationError('Aadhar number must be 12 digits.')
  
class UserDetails(models.Model):
    """Enhanced model for storing comprehensive employee information."""
    
    # Employee Status Choices
    EMPLOYMENT_STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'), 
        ('terminated', 'Terminated'),
        ('resigned', 'Resigned'),
        ('suspended', 'Suspended'),
        ('absconding', 'Absconding'),
        ('probation', 'Probation'),
        ('notice_period', 'Notice Period'),
        ('sabbatical', 'Sabbatical'),
        ('long_leave', 'Long Leave')
    ]
    
    # Employee Type Choices
    EMPLOYEE_TYPE_CHOICES = [
        ('full_time', 'Full-Time Employee'),
        ('part_time', 'Part-Time Employee'),
        ('contract', 'Contract Employee'),
        ('intern', 'Intern'),
        ('consultant', 'Consultant'),
        ('probationary', 'Probationary Employee'),
        ('remote', 'Remote Worker')
    ]
    
    # Blood Group Choices
    BLOOD_GROUP_CHOICES = [
        ('A+', 'A+'),
        ('A-', 'A-'),
        ('B+', 'B+'),
        ('B-', 'B-'),
        ('AB+', 'AB+'),
        ('AB-', 'AB-'),
        ('O+', 'O+'),
        ('O-', 'O-'),
    ]
    
    # Gender Choices
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
        ('Prefer not to say', 'Prefer not to say')
    ]
    
    # Marital Status Choices
    MARITAL_STATUS_CHOICES = [
        ('single', 'Single'),
        ('married', 'Married'),
        ('divorced', 'Divorced'),
        ('widowed', 'Widowed'),
        ('separated', 'Separated'),
        ('other', 'Other')
    ]
    
    # Basic User Connection
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE,
        related_name='profile'
    )
    
    # Personal Information
    dob = models.DateField(
        null=True, 
        blank=True, 
        verbose_name="Date of Birth",
        validators=[validate_future_date]
    )
    blood_group = models.CharField(
        max_length=10, 
        choices=BLOOD_GROUP_CHOICES,
        null=True,
        blank=True,
        help_text="Select blood group"
    )
    gender = models.CharField(
        max_length=20,
        choices=GENDER_CHOICES,
        null=True,
        blank=True
    )
    marital_status = models.CharField(
        max_length=20,
        choices=MARITAL_STATUS_CHOICES,
        null=True,
        blank=True
    )

    
    # Contact Information
    contact_number_primary = models.CharField(
        max_length=15,
        null=True,
        blank=True,
        help_text="Primary contact number with country code"
    )

    personal_email = models.EmailField(
        unique=True, 
        null=True, 
        blank=True
    )
    company_email = models.EmailField(
        unique=True,
        null=True,
        blank=True,
        help_text="Official company email"
    )
    
    # Address Information
    current_address_line1 = models.CharField(max_length=255, null=True, blank=True)
    current_address_line2 = models.CharField(max_length=255, null=True, blank=True) 
    current_city = models.CharField(max_length=100, null=True, blank=True)
    current_state = models.CharField(max_length=100, null=True, blank=True)
    current_postal_code = models.CharField(max_length=10, null=True, blank=True)
    current_country = models.CharField(max_length=100, null=True, blank=True)
    
    # Permanent Address
    permanent_address_line1 = models.CharField(max_length=255, null=True, blank=True)
    permanent_address_line2 = models.CharField(max_length=255, null=True, blank=True) 
    permanent_city = models.CharField(max_length=100, null=True, blank=True)
    permanent_state = models.CharField(max_length=100, null=True, blank=True)
    permanent_postal_code = models.CharField(max_length=10, null=True, blank=True)
    permanent_country = models.CharField(max_length=100, null=True, blank=True)
    is_current_same_as_permanent = models.BooleanField(
        default=False,
        help_text="Is current address same as permanent address?"
    )
    
    # Emergency Contact
    emergency_contact_name = models.CharField(max_length=255, null=True, blank=True)
    emergency_contact_number = models.CharField(max_length=15, null=True, blank=True)
    emergency_contact_relationship = models.CharField(max_length=50, null=True, blank=True)
    
    # Secondary Emergency Contact
    secondary_emergency_contact_name = models.CharField(max_length=255, null=True, blank=True)
    secondary_emergency_contact_number = models.CharField(max_length=15, null=True, blank=True)
    secondary_emergency_contact_relationship = models.CharField(max_length=50, null=True, blank=True)
    
    # Employment Information
    employee_type = models.CharField(
        max_length=20,
        choices=EMPLOYEE_TYPE_CHOICES,
        null=True,
        blank=True
    )
    reporting_manager = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='direct_reports'
    )
    hire_date = models.DateField(
        null=True, 
        blank=True,
        help_text="Date when offer was accepted"
    )
    start_date = models.DateField(
        null=True, 
        blank=True,
        help_text="First day of work"
    )
    probation_end_date = models.DateField(
        null=True, 
        blank=True,
        help_text="Date when probation period ends"
    )
    notice_period_days = models.PositiveIntegerField(
        default=30,
        help_text="Notice period in days"
    )
    job_description = models.TextField(null=True, blank=True)
    work_location = models.CharField(max_length=100, null=True, blank=True)
    employment_status = models.CharField(
        max_length=50,
        choices=EMPLOYMENT_STATUS_CHOICES,
        default='probation',
        db_index=True
    )
    exit_date = models.DateField(
        null=True, 
        blank=True,
        help_text="Last working day"
    )
    exit_reason = models.TextField(
        null=True, 
        blank=True,
        help_text="Reason for leaving the company"
    )
    rehire_eligibility = models.BooleanField(
        null=True, 
        blank=True,
        help_text="Eligible for rehire"
    )
    
    # Compensation Details
    salary_currency = models.CharField(
        max_length=3, 
        default='INR',
        help_text="Currency code (e.g., INR, USD)"
    )
    base_salary = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        null=True, 
        blank=True
    )
    salary_frequency = models.CharField(
        max_length=20,
        choices=[
            ('monthly', 'Monthly'),
            ('bi_weekly', 'Bi-Weekly'),
            ('weekly', 'Weekly')
        ],
        default='monthly'
    )
    
    # Government IDs
    pan_number = models.CharField(
        max_length=10, 
        null=True, 
        blank=True, 
        verbose_name="PAN Number",
        validators=[validate_pan]
    )
    aadhar_number = models.CharField(
        max_length=12, 
        null=True, 
        blank=True, 
        verbose_name="Aadhar Number",
        validators=[validate_aadhar]
    )
    passport_number = models.CharField(
        max_length=20, 
        null=True, 
        blank=True
    )
    passport_expiry = models.DateField(
        null=True, 
        blank=True
    )
    
    # Banking Details
    bank_name = models.CharField(max_length=100, null=True, blank=True)
    bank_account_number = models.CharField(max_length=30, null=True, blank=True)
    bank_ifsc = models.CharField(
        max_length=11, 
        null=True, 
        blank=True
    )
    
    # Previous Employment
    previous_company = models.CharField(max_length=255, null=True, blank=True)
    previous_position = models.CharField(max_length=100, null=True, blank=True)
    previous_experience_years = models.PositiveIntegerField(
        null=True, 
        blank=True
    )
    
    # HR Management
    onboarded_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='onboarded_users'
    )
    onboarding_date = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    last_status_change = models.DateTimeField(null=True, blank=True)
    
    # Skills and Competencies
    skills = models.TextField(
        null=True, 
        blank=True,
        help_text="Comma-separated list of skills"
    )
    
    # Additional HR Notes
    confidential_notes = models.TextField(
        null=True, 
        blank=True,
        help_text="Confidential HR notes (visible only to HR)"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "User Detail"
        verbose_name_plural = "User Details"
        indexes = [
            models.Index(fields=['employment_status']),
            models.Index(fields=['employee_type']),
            models.Index(fields=['work_location']),
            models.Index(fields=['hire_date']),
            models.Index(fields=['start_date']),
        ]
        permissions = [
            ("view_confidential_notes", "Can view confidential HR notes"),
            ("view_salary_information", "Can view salary information"),
            ("export_employee_data", "Can export employee data"),
            ("manage_employee_status", "Can change employee status"),
        ]
    
    def save(self, *args, **kwargs):
        # Handle email fields
        if self.company_email == "":
            self.company_email = None
            
        if self.personal_email == "":
            self.personal_email = None
            
        # Update last_status_change when employment status changes
        try:
            if self.pk:
                old_instance = UserDetails.objects.get(pk=self.pk)
                if old_instance.employment_status != self.employment_status:
                    self.last_status_change = timezone.now()
        except UserDetails.DoesNotExist:
            pass
                
        # Handle same address flag
        if self.is_current_same_as_permanent:
            self.permanent_address_line1 = self.current_address_line1
            self.permanent_address_line2 = self.current_address_line2
            self.permanent_city = self.current_city
            self.permanent_state = self.current_state
            self.permanent_postal_code = self.current_postal_code
            self.permanent_country = self.current_country
            
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username}"
    
    @property
    def full_name(self):
        return self.user.get_full_name() or self.user.username
    
    @property
    def age(self):
        if not self.dob:
            return None
        today = timezone.now().date()
        return today.year - self.dob.year - ((today.month, today.day) < (self.dob.month, self.dob.day))
    
    @property
    def employment_duration(self):
        if not self.start_date:
            return None
        
        end_date = self.exit_date if self.exit_date else timezone.now().date()
        delta = end_date - self.start_date
        years = delta.days // 365
        months = (delta.days % 365) // 30
        
        if years > 0:
            return f"{years} year{'s' if years > 1 else ''}, {months} month{'s' if months > 1 else ''}"
        return f"{months} month{'s' if months > 1 else ''}"

    @property
    def status_display(self):
        status_colors = {
            'active': 'success',
            'inactive': 'secondary',
            'terminated': 'danger', 
            'resigned': 'warning',
            'suspended': 'info',
            'absconding': 'dark',
            'probation': 'primary',
            'notice_period': 'warning',
            'sabbatical': 'purple',
            'long_leave': 'orange'
        }
        
        status_text = dict(self.EMPLOYMENT_STATUS_CHOICES).get(self.employment_status)
        status_color = status_colors.get(self.employment_status, 'secondary')
        
        return {'text': status_text, 'color': status_color}
    
    @property
    def is_on_notice(self):
        return self.employment_status == 'notice_period'
    
    @property
    def remaining_notice_period(self):
        if not self.is_on_notice or not self.exit_date:
            return None
        
        today = timezone.now().date()
        if today >= self.exit_date:
            return 0
        
        return (self.exit_date - today).days
    
    @property
    def get_reporting_chain(self):
        """Get the hierarchical reporting chain for this employee."""
        chain = []
        current = self.reporting_manager
        
        while current:
            try:
                manager_profile = UserDetails.objects.get(user=current)
                chain.append({
                    'name': current.get_full_name(),
                    'id': current.id
                })
                current = manager_profile.reporting_manager
            except (UserDetails.DoesNotExist, AttributeError):
                break
                
        return chain

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

# Core financial models for expense tracking, vouchers, bank transactions, and payroll
from django.db import models
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.utils import timezone
import json
from decimal import Decimal


class FinancialParameter(models.Model):
    """
    Dynamic parameter model for financial values that can change over time
    such as tax rates, thresholds, and calculation constants.
    
    Parameters can be global or associated with specific entities.
    """
    VALUE_TYPE_CHOICES = [
        ('decimal', 'Decimal'),  # For precise financial calculations
        ('percentage', 'Percentage'),  # Tax rates, etc.
        ('integer', 'Integer'),  # Whole number values
        ('text', 'Text'),  # Text identifiers or codes
        ('json', 'JSON'),  # Complex structured data
        ('boolean', 'Boolean'),  # Flag values
        ('date', 'Date'),  # Date-based parameters
    ]
    
    CATEGORY_CHOICES = [
        ('tax', 'Tax'),
        ('fee', 'Fee'),
        ('rate', 'Rate'),
        ('threshold', 'Threshold'),
        ('limit', 'Limit'),
        ('rule', 'Rule'),
        ('other', 'Other'),
    ]
    
    # Parameter identification
    key = models.CharField(max_length=100, db_index=True, 
                          help_text="Unique identifier for the parameter")
    name = models.CharField(max_length=255,
                          help_text="Human-readable name")
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='other',
                              help_text="Category for organizing parameters")
    description = models.TextField(blank=True, null=True,
                                 help_text="Detailed description of the parameter's purpose")
    
    # Value storage and typing
    value = models.TextField(help_text="String representation of the parameter value")
    value_type = models.CharField(max_length=20, choices=VALUE_TYPE_CHOICES,
                                help_text="Data type of the parameter")
    
    # Entity association for flexible application
    is_global = models.BooleanField(default=True,
                                  help_text="If True, applies globally; if False, applies to specific entity")
    content_type = models.ForeignKey(
        ContentType, 
        on_delete=models.CASCADE,
        null=True, 
        blank=True,
        help_text="Entity type this parameter is associated with"
    )
    object_id = models.PositiveIntegerField(null=True, blank=True,
                                          help_text="ID of the specific entity")
    entity = GenericForeignKey('content_type', 'object_id')
    
    # Time validity
    valid_from = models.DateField(help_text="Date from which this parameter value is valid")
    valid_to = models.DateField(null=True, blank=True, 
                              help_text="Date until which this parameter value is valid (null = indefinite)")
    
    # Financial period association
    fiscal_year = models.CharField(max_length=9, blank=True, null=True,
                                 help_text="Fiscal year in YYYY-YYYY format")
    fiscal_quarter = models.CharField(max_length=6, blank=True, null=True,
                                    help_text="Fiscal quarter in YYYY-Q# format")
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='created_fin_parameters'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.PROTECT,
        related_name='updated_fin_parameters'
    )
    
    # Approval tracking for financial governance
    is_approved = models.BooleanField(default=False,
                                    help_text="Whether this parameter has been approved for use")
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name='approved_fin_parameters'
    )
    
    class Meta:
        indexes = [
            models.Index(fields=['key'], name='fin_param_key_idx'),
            models.Index(fields=['category'], name='fin_param_cat_idx'),
            models.Index(fields=['content_type', 'object_id'], name='fin_param_entity_idx'),
            models.Index(fields=['valid_from', 'valid_to'], name='fin_param_validity_idx'),
            models.Index(fields=['fiscal_year'], name='fin_param_fiscal_yr_idx'),
        ]
        unique_together = ('key', 'content_type', 'object_id', 'valid_from')
        verbose_name = "Financial Parameter"
        verbose_name_plural = "Financial Parameters"
    
    def __str__(self):
        base = f"{self.name} ({self.key})"
        if self.fiscal_year:
            base += f" - FY{self.fiscal_year}"
        if not self.is_global:
            base += f" for {self.content_type.model}:{self.object_id}"
        return base
    
    def get_typed_value(self):
        """Return the value converted to its appropriate type"""
        if not self.value:
            return None
            
        if self.value_type == 'decimal':
            return Decimal(self.value)
        elif self.value_type == 'percentage':
            return Decimal(self.value) / Decimal('100')
        elif self.value_type == 'integer':
            return int(self.value)
        elif self.value_type == 'boolean':
            return self.value.lower() in ('true', 'yes', '1', 'y')
        elif self.value_type == 'json':
            return json.loads(self.value)
        elif self.value_type == 'date':
            from django.utils.dateparse import parse_date
            return parse_date(self.value)
        # Default to text
        return self.value
    
    @classmethod
    def get_param(cls, key, entity=None, date=None, category=None, fiscal_year=None):
        """
        Get parameter value for a given key and entity
        
        Args:
            key (str): Parameter key
            entity (Model instance, optional): The entity to get specific parameters for
            date (date, optional): Date for which parameter should be valid (defaults to today)
            category (str, optional): Filter by category
            fiscal_year (str, optional): Filter by fiscal year
            
        Returns:
            The typed parameter value or None if not found
        """
        if date is None:
            date = timezone.now().date()
            
        query = cls.objects.filter(
            key=key,
            valid_from__lte=date,
            is_approved=True
        ).filter(
            models.Q(valid_to__isnull=True) | models.Q(valid_to__gte=date)
        )
        
        if category:
            query = query.filter(category=category)
            
        if fiscal_year:
            query = query.filter(fiscal_year=fiscal_year)
        
        # First try to get entity-specific parameter
        if entity is not None:
            content_type = ContentType.objects.get_for_model(entity)
            entity_param = query.filter(
                content_type=content_type,
                object_id=entity.pk,
                is_global=False
            ).order_by('-valid_from').first()
            
            if entity_param:
                return entity_param.get_typed_value()
        
        # Fall back to global parameter
        global_param = query.filter(is_global=True).order_by('-valid_from').first()
        if global_param:
            return global_param.get_typed_value()
            
        return None
    
    @classmethod
    def get_all_params(cls, category=None, entity=None, date=None, fiscal_year=None):
        """Get all parameters for a given category and/or entity"""
        if date is None:
            date = timezone.now().date()
            
        query = cls.objects.filter(
            valid_from__lte=date,
            is_approved=True
        ).filter(
            models.Q(valid_to__isnull=True) | models.Q(valid_to__gte=date)
        )
        
        if category:
            query = query.filter(category=category)
            
        if fiscal_year:
            query = query.filter(fiscal_year=fiscal_year)
            
        # Get all keys to check
        keys = query.values_list('key', flat=True).distinct()
        result = {}
        
        # For each key, get the most specific value
        for key in keys:
            param_value = cls.get_param(
                key=key, 
                entity=entity, 
                date=date, 
                category=category,
                fiscal_year=fiscal_year
            )
            result[key] = param_value
            
        return result
        
    def approve(self, user):
        """Approve this parameter for use"""
        self.is_approved = True
        self.approved_at = timezone.now()
        self.approved_by = user
        self.save(update_fields=['is_approved', 'approved_at', 'approved_by'])
        
    def set_value(self, value):
        """Set the value with appropriate type conversion"""
        if value is None:
            self.value = None
            return
            
        if self.value_type == 'decimal':
            self.value = str(Decimal(str(value)))
        elif self.value_type == 'percentage':
            # Store percentages as their actual percentage value (15% = "15")
            if isinstance(value, Decimal):
                self.value = str(value * Decimal('100'))
            else:
                self.value = str(Decimal(str(value)) * Decimal('100'))
        elif self.value_type == 'integer':
            self.value = str(int(value))
        elif self.value_type == 'boolean':
            self.value = str(bool(value)).lower()
        elif self.value_type == 'json':
            self.value = json.dumps(value)
        elif self.value_type == 'date':
            from django.utils.dateparse import parse_date
            if hasattr(value, 'isoformat'):
                self.value = value.isoformat()
            else:
                self.value = parse_date(value).isoformat()
        else:  # text
            self.value = str(value)


from django.db import models
from django.contrib.auth.models import User

class DailyExpense(models.Model):
    EXPENSE_STATUS = (
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('paid', 'Paid')
    )
    
    EXPENSE_CATEGORIES = (
        ('travel', 'Travel'),
        ('utility', 'Utility'), 
        ('stationery', 'Stationery'),
        ('food', 'Food & Beverages'),
        ('other', 'Other')
    )
    
    expense_id = models.CharField(max_length=50, unique=True)
    department = models.ForeignKey('Department', on_delete=models.PROTECT)
    date = models.DateField()
    category = models.CharField(max_length=20, choices=EXPENSE_CATEGORIES)
    description = models.TextField()
    amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    paid_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='expenses_paid')
    status = models.CharField(max_length=20, choices=EXPENSE_STATUS, default='draft')
    attachments = models.FileField(upload_to='expenses/', null=True, blank=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='expenses_approved')
    approved_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date']

    def __str__(self):
        return f"{self.expense_id} - {self.category} - {self.amount}"

class Voucher(models.Model):
    VOUCHER_TYPES = (
        ('payment', 'Payment'),
        ('receipt', 'Receipt'),
        ('journal', 'Journal')
    )
    VOUCHER_STATUS = (
        ('draft', 'Draft'),
        ('pending_approval', 'Pending Department Head Approval'),
        ('pending_finance', 'Pending Finance Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('posted', 'Posted to Accounts')
    )
    
    voucher_number = models.CharField(max_length=50, unique=True)
    type = models.CharField(max_length=20, choices=VOUCHER_TYPES)
    date = models.DateField()
    reference_no = models.CharField(max_length=100, blank=True, null=True)
    party_name = models.CharField(max_length=255)
    purpose = models.TextField()
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    status = models.CharField(max_length=25, choices=VOUCHER_STATUS, default='draft')
    attachments = models.FileField(upload_to='vouchers/', null=True, blank=True)
    department_approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='dept_approved_vouchers')
    finance_approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='finance_approved_vouchers')
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='created_vouchers')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.voucher_number} - {self.type} - {self.amount}"

class VoucherDetail(models.Model):
    voucher = models.ForeignKey(Voucher, on_delete=models.CASCADE, related_name='details')
    account = models.ForeignKey('ChartOfAccount', on_delete=models.PROTECT)
    debit_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    credit_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.voucher.voucher_number} - {self.account.name}"

class BankAccount(models.Model):
    name = models.CharField(max_length=255)
    account_number = models.CharField(max_length=50, unique=True)
    bank_name = models.CharField(max_length=255)
    branch = models.CharField(max_length=255)
    ifsc_code = models.CharField(max_length=20)
    current_balance = models.DecimalField(max_digits=15, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.bank_name} - {self.account_number}"

class BankPayment(models.Model):
    PAYMENT_STATUS = (
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('approved', 'Approved'),
        ('executed', 'Payment Executed'),
        ('failed', 'Failed')
    )
    
    payment_id = models.CharField(max_length=50, unique=True)
    bank_account = models.ForeignKey(BankAccount, on_delete=models.PROTECT)
    party_name = models.CharField(max_length=255)
    payment_reason = models.TextField()
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    payment_date = models.DateField()
    reference_number = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='pending')
    attachments = models.FileField(upload_to='bank_payments/', null=True, blank=True)
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='verified_payments')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='approved_payments')
    created_by = models.ForeignKey(User, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.payment_id} - {self.party_name} - {self.amount}"

class Subscription(models.Model):
    FREQUENCY_CHOICES = (
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('yearly', 'Yearly')
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired')
    )
    
    name = models.CharField(max_length=255)
    vendor = models.CharField(max_length=255)
    subscription_type = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    start_date = models.DateField()
    next_payment_date = models.DateField()
    auto_renew = models.BooleanField(default=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    alert_days = models.IntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.vendor}"

        
class ClientInvoice(models.Model):
    BILLING_MODELS = (
        ('per_order', 'Per Order'),
        ('per_fte', 'Per FTE'), 
        ('hybrid', 'Hybrid')
    )
    
    INVOICE_STATUS = (
        ('draft', 'Draft'),
        ('pending_approval', 'Pending Approval'),
        ('approved', 'Approved'),
        ('sent', 'Sent to Client'),
        ('paid', 'Paid'),
        ('overdue', 'Overdue')
    )
    
    invoice_number = models.CharField(max_length=50, unique=True)
    client = models.ForeignKey(User, on_delete=models.PROTECT, limit_choices_to={'groups__name': 'Client'}, related_name='client_invoices')
    billing_model = models.CharField(max_length=20, choices=BILLING_MODELS)
    billing_cycle_start = models.DateField()
    billing_cycle_end = models.DateField()
    order_count = models.IntegerField(null=True, blank=True)
    fte_count = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    rate = models.DecimalField(max_digits=10, decimal_places=2)
    subtotal = models.DecimalField(max_digits=15, decimal_places=2)
    tax_amount = models.DecimalField(max_digits=15, decimal_places=2)
    discount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=15, decimal_places=2)
    status = models.CharField(max_length=20, choices=INVOICE_STATUS, default='draft')
    due_date = models.DateField()
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='approved_invoices')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.invoice_number} - {self.client.get_full_name()}"

class ChartOfAccount(models.Model):
    ACCOUNT_TYPES = (
        ('asset', 'Asset'),
        ('liability', 'Liability'),
        ('equity', 'Equity'),
        ('income', 'Income'),
        ('expense', 'Expense')
    )
    
    name = models.CharField(max_length=255)
    code = models.CharField(max_length=20, unique=True)
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    description = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.code} - {self.name}"


# models.py - Enhanced models for appraisal workflow

from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.urls import reverse
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver


class Appraisal(models.Model):
    """Model for employee appraisals with workflow states"""
    STATUS_CHOICES = (
        ('draft', 'Draft'),
        ('submitted', 'Submitted'), 
        ('manager_review', 'Manager Review'),
        ('hr_review', 'HR Review'),
        ('finance_review', 'Finance Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='appraisals')
    manager = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
                               related_name='managed_appraisals')
    title = models.CharField(max_length=255)
    overview = models.TextField(blank=True)
    period_start = models.DateField()
    period_end = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional fields for tracking
    submitted_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.title} - {self.user}"
    
        


class AppraisalWorkflow(models.Model):
    """Model to track appraisal workflow history"""
    appraisal = models.ForeignKey('Appraisal', on_delete=models.CASCADE, related_name='workflow_history')
    from_status = models.CharField(max_length=20, null=True, blank=True)
    to_status = models.CharField(max_length=20)
    action_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='workflow_actions')
    timestamp = models.DateTimeField(auto_now_add=True)
    comments = models.TextField(blank=True)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"Appraisal #{self.appraisal_id}: {self.from_status or 'initial'} → {self.to_status}"


class AppraisalItem(models.Model):
    """Model for individual items/achievements in an appraisal"""
    CATEGORY_CHOICES = (
        ('goal', 'Goal'),
        ('achievement', 'Achievement'),
        ('improvement', 'Area for Improvement'),
        ('training', 'Training Completed'),
        ('feedback', 'Feedback Received'),
    )
    
    appraisal = models.ForeignKey('Appraisal', on_delete=models.CASCADE, related_name='items')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    date = models.DateField(null=True, blank=True)
    
    # Additional evaluation fields
    employee_rating = models.PositiveSmallIntegerField(null=True, blank=True, choices=[(i, i) for i in range(1, 6)])
    manager_rating = models.PositiveSmallIntegerField(null=True, blank=True, choices=[(i, i) for i in range(1, 6)])
    manager_comments = models.TextField(blank=True)

    def __str__(self):
        return f"{self.title} ({self.category})"


class AppraisalAttachment(models.Model):
    """Model for attachments to appraisals (certificates, evidence, etc.)"""
    appraisal = models.ForeignKey('Appraisal', on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to='appraisal_attachments/%Y/%m/')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    upload_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title