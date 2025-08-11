from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.conf import settings
from datetime import timedelta
import logging
from django.db.models import JSONField
from django.db.models import Q
from django.db import transaction
from datetime import time, timedelta
import uuid
import json
import math
import ipaddress
import geoip2.database
import os
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.core.validators import MinValueValidator, MaxValueValidator
from decimal import Decimal
from django.db.models.signals import post_save
from django.dispatch import receiver



# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

# Helper function for default date values
def get_current_date():
    """Return current date for model defaults"""
    return timezone.now().date()

# Custom Managers for optimized queries
class UserLeaveBalanceManager(models.Manager):
    """Custom manager for UserLeaveBalance with optimized queries"""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)

    def for_user_and_year(self, user, year):
        """Get balances for specific user and year"""
        return self.filter(user=user, year=year)

    def active_balances(self):
        """Get all active (non-deleted) balances"""
        return self.get_queryset()

    def with_available_balance(self):
        """Get balances where available > 0"""
        return self.get_queryset().extra(
            where=["(allocated + carried_forward + additional - used) > 0"]
        )

class LeaveRequestManager(models.Manager):
    """Custom manager for LeaveRequest with optimized queries"""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False).select_related('user', 'leave_type', 'approver')

    def pending(self):
        """Get pending leave requests"""
        return self.filter(status='Pending')

    def approved(self):
        """Get approved leave requests"""
        return self.filter(status='Approved')

    def for_user(self, user):
        """Get leave requests for specific user"""
        return self.filter(user=user)

    def for_date_range(self, start_date, end_date):
        """Get leave requests within date range"""
        return self.filter(
            models.Q(start_date__lte=end_date) & models.Q(end_date__gte=start_date)
        )

    def overlapping_with(self, user, start_date, end_date, exclude_id=None):
        """Check for overlapping leaves for a user"""
        queryset = self.filter(
            user=user,
            status__in=['Approved', 'Pending'],
            start_date__lte=end_date,
            end_date__gte=start_date
        )
        if exclude_id:
            queryset = queryset.exclude(id=exclude_id)
        return queryset

class CompOffRequestManager(models.Manager):
    """Custom manager for CompOffRequest with optimized queries"""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False).select_related('user', 'approver')

    def pending(self):
        """Get pending comp-off requests"""
        return self.filter(status='Pending')

    def approved(self):
        """Get approved comp-off requests"""
        return self.filter(status='Approved')

    def for_user(self, user):
        """Get comp-off requests for specific user"""
        return self.filter(user=user)

    def for_year(self, year):
        """Get comp-off requests for specific year"""
        return self.filter(worked_date__year=year)

'''------------------------- OFFICE LOCATION --------------------'''
class OfficeLocation(models.Model):
    """
    Model to manage office locations for the organization.
    Conference rooms and users will be associated with office locations.
    """
    name = models.CharField(max_length=100, unique=True, help_text="Office location name (e.g., 'Mumbai - Bandra', 'Delhi - Gurgaon')")
    code = models.CharField(max_length=10, unique=True, help_text="Short code for the location (e.g., 'MUM', 'DEL')")
    address_line1 = models.CharField(max_length=255, help_text="Street address")
    address_line2 = models.CharField(max_length=255, blank=True, help_text="Additional address information")
    city = models.CharField(max_length=100, help_text="City name")
    state = models.CharField(max_length=100, help_text="State/Province")
    postal_code = models.CharField(max_length=20, help_text="Postal/ZIP code")
    country = models.CharField(max_length=100, default='India', help_text="Country")

    # Contact Information
    phone = models.CharField(max_length=20, blank=True, help_text="Office phone number")
    email = models.EmailField(blank=True, help_text="Office email address")

    # Operational Details
    is_active = models.BooleanField(default=True, help_text="Is this location active?")
    timezone = models.CharField(max_length=50, default='Asia/Kolkata', help_text="Timezone for this location")
    working_hours_start = models.TimeField(default=time(9, 0), help_text="Office working hours start time")
    working_hours_end = models.TimeField(default=time(18, 0), help_text="Office working hours end time")

    # Administrative
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = "Office Location"
        verbose_name_plural = "Office Locations"

    def __str__(self):
        return f"{self.name} ({self.code})"

    @property
    def full_address(self):
        """Return the complete address as a string."""
        address_parts = [self.address_line1]
        if self.address_line2:
            address_parts.append(self.address_line2)
        address_parts.extend([self.city, self.state, self.postal_code, self.country])
        return ", ".join(address_parts)

    @property
    def working_hours_display(self):
        """Return working hours in a readable format."""
        return f"{self.working_hours_start.strftime('%I:%M %p')} - {self.working_hours_end.strftime('%I:%M %p')}"

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
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
import json
import uuid
import math
import logging
from datetime import timedelta
import ipaddress
import geoip2.database
import os

logger = logging.getLogger(__name__)

class UserSession(models.Model):
    # Session identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sessions')
    parent_session_id = models.UUIDField(null=True, blank=True)
    tab_id = models.CharField(max_length=100, null=True, blank=True)
    is_primary_tab = models.BooleanField(default=False)
    session_fingerprint = models.CharField(max_length=255, null=True, blank=True)
    session_key = models.CharField(max_length=40)

    # Session timing
    created_at = models.DateTimeField(auto_now_add=True)
    login_time = models.DateTimeField(default=timezone.now)
    logout_time = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    session_end_time = models.DateTimeField(null=True, blank=True)
    start_time = models.DateTimeField(default=timezone.now)
    tab_opened_time = models.DateTimeField(null=True, blank=True)
    tab_last_focus = models.DateTimeField(null=True, blank=True)

    # Session status
    is_active = models.BooleanField(default=True)
    is_idle = models.BooleanField(default=False)
    idle_start_time = models.DateTimeField(null=True, blank=True)
    total_idle_time = models.DurationField(default=timedelta)
    working_time = models.DurationField(default=timedelta)
    focus_time = models.DurationField(default=timedelta)
    session_duration = models.FloatField(null=True, blank=True)
    idle_time = models.DurationField(null=True, blank=True)

    # Client information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    browser_fingerprint = models.TextField(null=True, blank=True)
    browser = models.CharField(max_length=100, null=True, blank=True)
    os = models.CharField(max_length=100, null=True, blank=True)
    csrf_token = models.CharField(max_length=64, null=True, blank=True)
    csrf_token_created = models.DateTimeField(null=True, blank=True)
    device_type = models.CharField(max_length=20, null=True, blank=True)
    screen_resolution = models.CharField(max_length=20, null=True, blank=True)
    timezone_offset = models.IntegerField(null=True, blank=True)
    language = models.CharField(max_length=10, null=True, blank=True)
    battery_level = models.FloatField(null=True, blank=True)
    connection_type = models.CharField(max_length=20, null=True, blank=True)

    # Location information
    location_history = models.JSONField(null=True, blank=True)
    location_country = models.CharField(max_length=100, null=True, blank=True)
    location_region = models.CharField(max_length=100, null=True, blank=True)
    location_city = models.CharField(max_length=100, null=True, blank=True)
    location_latitude = models.FloatField(null=True, blank=True)
    location_longitude = models.FloatField(null=True, blank=True)
    location_accuracy = models.FloatField(null=True, blank=True)
    location_type = models.CharField(max_length=20, null=True, blank=True)

    # Page and tab (stored as JSON for multiple tabs)
    tab_title = models.JSONField(default=list, blank=True)
    tab_url = models.JSONField(default=list, blank=True)
    url = models.JSONField(default=list, blank=True)
    title = models.JSONField(default=list, blank=True)
    referrer = models.JSONField(default=list, blank=True)

    # Activity tracking
    page_views = models.JSONField(default=list, blank=True)
    clicks = models.JSONField(default=list, blank=True)
    scrolls = models.JSONField(default=list, blank=True)
    keyboard_events = models.JSONField(default=list, blank=True)
    mouse_movements = models.IntegerField(default=0)
    tab_visibility_log = models.JSONField(default=list, blank=True)
    tab_switches = models.IntegerField(default=0)
    background_time = models.DurationField(default=timedelta(0))
    idle_state_changes = models.JSONField(default=list, blank=True)

    # Performance and errors
    performance_metrics = models.JSONField(default=dict, blank=True)
    network_events = models.JSONField(default=list, blank=True)
    error_events = models.JSONField(default=list, blank=True)

    # Progressive session management
    custom_timeout = models.PositiveIntegerField(null=True, blank=True)
    inactivity_warnings_sent = models.IntegerField(default=0)
    last_warning_time = models.DateTimeField(null=True, blank=True)
    auto_logout_enabled = models.BooleanField(default=True)

    # Offline support
    offline_data = models.JSONField(default=dict, blank=True)
    last_sync_time = models.DateTimeField(null=True, blank=True)
    pending_sync_count = models.IntegerField(default=0)

    # Cross-tab communication
    related_tabs = models.JSONField(default=list, blank=True)
    broadcast_messages_sent = models.IntegerField(default=0)
    broadcast_messages_received = models.IntegerField(default=0)
    cross_tab_activity_syncs = models.IntegerField(default=0)

    # URL frequency tracking
    visited_urls = models.JSONField(default=dict, blank=True)
    most_visited_url = models.URLField(max_length=2000, null=True, blank=True)
    most_visited_count = models.IntegerField(default=0)

    # Metrics and scores
    productivity_score = models.FloatField(null=True, blank=True)
    engagement_score = models.FloatField(null=True, blank=True)
    session_quality = models.CharField(max_length=20, null=True, blank=True)
    security_score = models.FloatField(null=True, blank=True)
    security_anomalies = models.JSONField(default=list, blank=True)
    end_reason = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        db_table = 'trueAlign_usersession'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active'], name='user_is_active_idx'),
            models.Index(fields=['tab_id'], name='tab_id_idx'),
            models.Index(fields=['parent_session_id'], name='parent_session_id_idx'),
            models.Index(fields=['created_at'], name='created_at_idx'),
            models.Index(fields=['last_activity'], name='last_activity_idx'),
        ]

    def __str__(self):
        return f"{self.user.username}'s session ({self.id})"

    @staticmethod
    def generate_session_key():
        """Generate a unique session key"""
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=40))

    # In ardurPeopleSoft/trueAlign/models.py - Add this method to UserSession class

    def end_session(self):
        """Properly end a session"""
        import pytz
        IST = pytz.timezone('Asia/Kolkata')
        now = timezone.now().astimezone(IST)

        self.logout_time = now
        self.ended_at = now
        self.is_active = False
        self.save(update_fields=['logout_time', 'ended_at', 'is_active', 'last_activity'])

        logger.info(f"Session ended for {self.user.username} at {now}")

    @classmethod
    def create_new_session(cls, user, **kwargs):
        """Create a new session without default logout time"""
        session_data = {
            'user': user,
            'login_time': timezone.now(),
            'session_key': cls.generate_session_key(),
            'is_active': True,
            **kwargs
        }

        return cls.objects.create(**session_data)


    @classmethod
    def _original_get_or_create_session(cls, user, tab_id=None, parent_session_id=None, client_data=None, session_key=None, ip_address=None, user_agent=None, browser_fingerprint=None, device_type=None, screen_resolution=None, timezone_offset=None, language=None, url=None, title=None, referrer=None):
        """
        Original fallback session creation method
        """
        logger.info(f"Using fallback session creation for user {user.username}")

        # Simple session creation without enhanced features
        if tab_id:
            try:
                session = cls.objects.get(user=user, tab_id=tab_id, is_active=True)
                session.last_activity = timezone.now()
                session.save(update_fields=['last_activity'])
                return session, False
            except cls.DoesNotExist:
                pass

        # Create new session
        session_data = {
            'user': user,
            'tab_id': tab_id,
            'parent_session_id': parent_session_id or uuid.uuid4(),
            'session_key': session_key or cls.generate_session_key(),
            'is_primary_tab': True,
            'login_time': timezone.now(),
            'last_activity': timezone.now(),
        }

        if client_data:
            session_data.update({
                'ip_address': client_data.get('ip_address'),
                'user_agent': client_data.get('user_agent'),
                'browser_fingerprint': client_data.get('browser_fingerprint'),
                'session_fingerprint': client_data.get('session_fingerprint'),
            })

        new_session = cls.objects.create(**session_data)
        return new_session, True

    @classmethod
    def get_or_create_session(cls, user, tab_id=None, parent_session_id=None, client_data=None, session_key=None, ip_address=None, user_agent=None, browser_fingerprint=None, device_type=None, screen_resolution=None, timezone_offset=None, language=None, url=None, title=None, referrer=None):
        """
        Get an existing session or create a new one using the enhanced session manager
        """
        try:
            from trueAlign.core import get_session_manager, get_session_logger, get_session_validator
        except ImportError as e:
            logger.warning(f"Enhanced session components not available: {e}")
            # Fall back to original implementation
            return cls._original_get_or_create_session(user, tab_id, parent_session_id, client_data, session_key, ip_address, user_agent, browser_fingerprint, device_type, screen_resolution, timezone_offset, language, url, title, referrer)

        import time as time_module
        start_time = time_module.time()
        session_manager = get_session_manager()
        session_logger = get_session_logger()
        session_validator = get_session_validator()

        try:
            # Prepare client data if not provided
            if client_data is None:
                client_data = {}

            # Add standalone parameters to client_data if they're provided
            if ip_address is not None:
                client_data['ip_address'] = ip_address
            if user_agent is not None:
                client_data['user_agent'] = user_agent
            if browser_fingerprint is not None:
                client_data['browser_fingerprint'] = browser_fingerprint
                client_data['session_fingerprint'] = browser_fingerprint
            if device_type is not None:
                client_data['device_type'] = device_type
            if screen_resolution is not None:
                client_data['screen_resolution'] = screen_resolution
            if timezone_offset is not None:
                client_data['timezone_offset'] = timezone_offset
            if language is not None:
                client_data['language'] = language
            if url is not None:
                client_data['url'] = url
            if title is not None:
                client_data['title'] = title
            if referrer is not None:
                client_data['referrer'] = referrer

            # Use enhanced session manager
            session, created = session_manager.get_or_create_session(
                user=user,
                tab_id=tab_id,
                parent_session_id=parent_session_id,
                client_data=client_data,
                session_key=session_key
            )

            # Log session creation
            duration_ms = (time_module.time() - start_time) * 1000
            session_logger.log_session_creation(
                user, session.id, tab_id, duration_ms, created=created
            )

            # Register session for validation if newly created
            if created:
                session_validator.register_session(session)

            return session, created

        except Exception as e:
            # Log error
            session_logger.log_error(
                'session_creation_error',
                str(e),
                user=user,
                details={'tab_id': tab_id, 'parent_session_id': parent_session_id}
            )
            logger.error(f"Error in get_or_create_session for user {user.username}: {str(e)}")
            raise

    def update_location_from_ip(self, ip_address=None):
        """
        Update location information based on IP address using GeoIP2
        """
        if not ip_address:
            ip_address = self.ip_address

        if not ip_address:
            return

        # Skip private IP addresses
        try:
            if ipaddress.ip_address(ip_address).is_private:
                return
        except ValueError:
            return

        # Path to GeoIP2 database
        geoip_db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'geoip', 'GeoLite2-City.mmdb')

        # Check if database exists
        if not os.path.exists(geoip_db_path):
            return

        try:
            # Open GeoIP2 database
            with geoip2.database.Reader(geoip_db_path) as reader:
                response = reader.city(ip_address)

                # Update location information
                self.location_country = response.country.name
                self.location_region = response.subdivisions.most_specific.name if response.subdivisions else None
                self.location_city = response.city.name
                self.location_latitude = response.location.latitude
                self.location_longitude = response.location.longitude

                self.save(update_fields=[
                    'location_country', 'location_region', 'location_city',
                    'location_latitude', 'location_longitude'
                ])
        except Exception as e:
            print(f"Error updating location from IP: {e}")

    def determine_location_type(self):
        """
        Determine if the location is home, office, or other based on time and previous sessions
        """
        if not self.location_latitude or not self.location_longitude:
            return

        # Get current hour in user's timezone
        current_time = timezone.now()
        if self.timezone_offset is not None:
            # Convert timezone offset from minutes to hours
            offset_hours = -self.timezone_offset / 60
            current_time = current_time + timedelta(hours=offset_hours)

        current_hour = current_time.hour

        # Check if it's within typical office hours (9 AM to 6 PM on weekdays)
        is_weekday = current_time.weekday() < 5  # Monday to Friday
        is_office_hours = 9 <= current_hour <= 18

        # Get previous sessions with location data
        previous_sessions = UserSession.objects.filter(
            user=self.user,
            location_latitude__isnull=False,
            location_longitude__isnull=False
        ).exclude(id=self.id).order_by('-created_at')[:50]

        # Group locations by frequency
        location_groups = {}
        for session in previous_sessions:
            # Round coordinates to reduce precision for grouping
            lat_rounded = round(session.location_latitude, 3)
            lng_rounded = round(session.location_longitude, 3)
            location_key = f"{lat_rounded},{lng_rounded}"

            if location_key not in location_groups:
                location_groups[location_key] = {
                    'count': 0,
                    'type': session.location_type,
                    'lat': session.location_latitude,
                    'lng': session.location_longitude,
                    'sessions': []
                }

            location_groups[location_key]['count'] += 1
            location_groups[location_key]['sessions'].append(session.id)

        # Find the closest location group to current location
        closest_group = None
        min_distance = 0.01  # Approximately 1km

        for key, group in location_groups.items():
            distance = self.calculate_distance(
                self.location_latitude, self.location_longitude,
                group['lat'], group['lng']
            )

            if distance < min_distance:
                closest_group = group
                min_distance = distance

        # Determine location type
        if closest_group and closest_group['type']:
            # Use the type from the closest known location
            self.location_type = closest_group['type']
        elif is_weekday and is_office_hours:
            # Assume office during weekday office hours
            self.location_type = 'office'
        else:
            # Assume home outside office hours or on weekends
            self.location_type = 'home'

        self.save(update_fields=['location_type'])

    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """
        Calculate distance between two points using Haversine formula
        """
        # Convert decimal degrees to radians
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])

        # Haversine formula
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        r = 6371  # Radius of earth in kilometers
        return c * r

    def update_activity(self, activity_time, is_idle=False):
        """Update the last activity timestamp and idle status"""
        self.last_activity = activity_time
        self.is_idle = is_idle

        if not is_idle:
            # Reset idle start time when user becomes active
            self.idle_start_time = None
        elif is_idle and not self.idle_start_time:
            # Set idle start time when user becomes idle
            self.idle_start_time = activity_time

        self.save(update_fields=['last_activity', 'is_idle', 'idle_start_time'])

    def end_session(self, is_idle=False):
        """
        End the session and calculate final metrics
        """
        if not self.is_active:
            return

        # Set end time and mark as inactive
        self.ended_at = timezone.now()
        self.logout_time = timezone.now()  # Add logout time
        self.is_active = False

        # If ending due to idle, make sure idle status is set
        if is_idle:
            self.is_idle = True
            if not self.idle_start_time:
                self.idle_start_time = self.ended_at

        # Calculate final metrics
        self.calculate_working_time()
        self.calculate_productivity_score()
        self.calculate_engagement_score()

        # Process visited URLs
        self.process_visited_urls()

        self.save()

        # End related tab sessions if this is a parent session
        if not self.parent_session_id:
            UserSession.objects.filter(
                user=self.user,
                parent_session_id=self.id,
                is_active=True
            ).update(
                is_active=False,
                ended_at=timezone.now()
            )

    def update_tab_activity(self, activity_data):
        """Update tab-specific activity data"""
        # Update basic activity
        self.last_activity = timezone.now()

        # Update tab information if provided
        if activity_data.get('url'):
            if not isinstance(self.tab_url, list):
                self.tab_url = []
            if activity_data['url'] not in self.tab_url:
                self.tab_url.append(activity_data['url'])

        if activity_data.get('title'):
            if not isinstance(self.tab_title, list):
                self.tab_title = []
            if activity_data['title'] not in self.tab_title:
                self.tab_title.append(activity_data['title'])

        # Update device info if provided
        if activity_data.get('battery_level') is not None:
            self.battery_level = activity_data['battery_level']

        if activity_data.get('connection_type'):
            self.connection_type = activity_data['connection_type']

        # Save changes
        update_fields = ['last_activity']
        if activity_data.get('url'):
            update_fields.append('tab_url')
        if activity_data.get('title'):
            update_fields.append('tab_title')
        if activity_data.get('battery_level') is not None:
            update_fields.append('battery_level')
        if activity_data.get('connection_type'):
            update_fields.append('connection_type')

        self.save(update_fields=update_fields)

    def update_last_activity(self):
        """
        Update the last activity timestamp
        """
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])

    def update_idle_status(self, is_idle):
        """
        Update the idle status and calculate idle time
        """
        # No change in idle status
        if self.is_idle == is_idle:
            return

        now = timezone.now()

        if is_idle:
            # Becoming idle
            self.is_idle = True
            self.idle_start_time = now
        else:
            # Becoming active again
            self.is_idle = False

            # Calculate and add to total idle time if we have a start time
            if self.idle_start_time:
                idle_duration = now - self.idle_start_time
                if not self.total_idle_time:
                    self.total_idle_time = idle_duration
                else:
                    self.total_idle_time += idle_duration
                self.idle_start_time = None

        self.save(update_fields=['is_idle', 'idle_start_time', 'total_idle_time'])

    def update_click(self, click_data):
        """
        Add a click event to the session
        """
        if not isinstance(self.clicks, list):
            self.clicks = []

        self.clicks.append(click_data)

        # Keep only the last 1000 clicks to prevent excessive data
        if len(self.clicks) > 1000:
            self.clicks = self.clicks[-1000:]

        self.save(update_fields=['clicks'])

    def update_scroll(self, scroll_data):
        """
        Add a scroll event to the session
        """
        if not isinstance(self.scrolls, list):
            self.scrolls = []

        self.scrolls.append(scroll_data)

        # Keep only the last 500 scrolls to prevent excessive data
        if len(self.scrolls) > 500:
            self.scrolls = self.scrolls[-500:]

        self.save(update_fields=['scrolls'])

    def update_keyboard(self, keyboard_data):
        """
        Add a keyboard event to the session
        """
        if not isinstance(self.keyboard_events, list):
            self.keyboard_events = []

        self.keyboard_events.append(keyboard_data)

        # Keep only the last 500 keyboard events to prevent excessive data
        if len(self.keyboard_events) > 500:
            self.keyboard_events = self.keyboard_events[-500:]

        self.save(update_fields=['keyboard_events'])

    def update_mouse_move(self, mouse_data):
        """
        Add a mouse movement event to the session
        """
        # mouse_movements is an IntegerField, not a JSONField
        # Just increment the counter instead of storing the data
        self.mouse_movements += 1
        self.save(update_fields=['mouse_movements'])

    def update_tab_visibility(self, visibility_data):
        """
        Add a tab visibility change event to the session
        """
        if not isinstance(self.tab_visibility_log, list):
            self.tab_visibility_log = []

        self.tab_visibility_log.append(visibility_data)

        # Keep only the last 100 visibility changes to prevent excessive data
        if len(self.tab_visibility_log) > 100:
            self.tab_visibility_log = self.tab_visibility_log[-100:]

        self.save(update_fields=['tab_visibility_log'])

    def update_idle_state(self, idle_data):
        """
        Add an idle state change event to the session
        """
        if not isinstance(self.idle_state_changes, list):
            self.idle_state_changes = []

        self.idle_state_changes.append(idle_data)

        # Keep only the last 50 idle state changes to prevent excessive data
        if len(self.idle_state_changes) > 50:
            self.idle_state_changes = self.idle_state_changes[-50:]

        self.save(update_fields=['idle_state_changes'])

    def update_page_view(self, page_data):
        """
        Add a page view event to the session
        """
        if not isinstance(self.page_views, list):
            self.page_views = []

        self.page_views.append(page_data)

        # Update current URL and title
        self.url = page_data.get('url')
        self.title = page_data.get('title')
        self.referrer = page_data.get('referrer')

        # Keep only the last 100 page views to prevent excessive data
        if len(self.page_views) > 100:
            self.page_views = self.page_views[-100:]

        self.save(update_fields=['page_views', 'url', 'title', 'referrer'])

    def update_performance_metrics(self, metrics_data):
        """
        Update performance metrics for the session
        """
        if not isinstance(self.performance_metrics, dict):
            self.performance_metrics = {}

        # Merge new metrics with existing ones
        self.performance_metrics.update(metrics_data)

        self.save(update_fields=['performance_metrics'])

    def update_device_info(self, device_data):
        """
        Update device information for the session
        """
        updated_fields = []

        if 'battery_level' in device_data and device_data['battery_level'] is not None:
            self.battery_level = device_data['battery_level']
            updated_fields.append('battery_level')

        if 'connection_type' in device_data and device_data['connection_type']:
            self.connection_type = device_data['connection_type']
            updated_fields.append('connection_type')

        if 'screen_resolution' in device_data and device_data['screen_resolution']:
            self.screen_resolution = device_data['screen_resolution']
            updated_fields.append('screen_resolution')

        if 'device_type' in device_data and device_data['device_type']:
            self.device_type = device_data['device_type']
            updated_fields.append('device_type')

        if updated_fields:
            self.save(update_fields=updated_fields)

    def update_cross_tab_event(self, event_data):
        """
        Update cross-tab communication events
        """
        if not isinstance(self.related_tabs, list):
            self.related_tabs = []

        # Add the tab to related tabs if not already present
        tab_id = event_data.get('source_tab_id')
        if tab_id and tab_id not in [tab.get('tab_id') for tab in self.related_tabs]:
            self.related_tabs.append({
                'tab_id': tab_id,
                'first_seen': timezone.now().isoformat(),
                'events': []
            })

        # Add the event to the tab's events
        for tab in self.related_tabs:
            if tab.get('tab_id') == tab_id:
                if 'events' not in tab:
                    tab['events'] = []

                tab['events'].append(event_data)
                tab['last_seen'] = timezone.now().isoformat()

                # Keep only the last 20 events per tab
                if len(tab['events']) > 20:
                    tab['events'] = tab['events'][-20:]
                break

        self.save(update_fields=['related_tabs'])

    def update_visited_urls(self, visited_urls_data):
        """
        Update visited URLs frequency data
        """
        if not isinstance(self.visited_urls, dict):
            self.visited_urls = {}

        # Merge new URLs with existing ones
        for url, data in visited_urls_data.items():
            if url in self.visited_urls:
                # Update existing URL data
                self.visited_urls[url]['count'] += data.get('count', 1)
                self.visited_urls[url]['last_visit'] = data.get('last_visit', timezone.now().isoformat())
            else:
                # Add new URL data
                self.visited_urls[url] = {
                    'count': data.get('count', 1),
                    'first_visit': data.get('first_visit', timezone.now().isoformat()),
                    'last_visit': data.get('last_visit', timezone.now().isoformat()),
                    'title': data.get('title', '')
                }

        # Process visited URLs to find most visited
        self.process_visited_urls()

        self.save(update_fields=['visited_urls', 'most_visited_url', 'most_visited_count'])

    def process_visited_urls(self):
        """
        Process visited URLs to find most visited and clean up old data
        """
        if not isinstance(self.visited_urls, dict) or not self.visited_urls:
            return

        # Find most visited URL
        most_visited = max(self.visited_urls.items(), key=lambda x: x[1].get('count', 0))
        self.most_visited_url = most_visited[0]
        self.most_visited_count = most_visited[1].get('count', 0)

        # Keep only the top 100 most visited URLs to prevent excessive data
        if len(self.visited_urls) > 100:
            sorted_urls = sorted(
                self.visited_urls.items(),
                key=lambda x: x[1].get('count', 0),
                reverse=True
            )
            self.visited_urls = dict(sorted_urls[:100])

    def calculate_working_time(self):
        """
        Calculate total working time (session duration minus idle time)
        """
        end_time = self.ended_at or timezone.now()
        session_duration = end_time - self.created_at

        # Add current idle time if session is still idle
        total_idle = self.total_idle_time
        if self.is_idle and self.idle_start_time:
            current_idle = end_time - self.idle_start_time
            if not total_idle:
                total_idle = current_idle
            else:
                total_idle += current_idle

        # Working time is session duration minus idle time
        self.working_time = max(timedelta(0), session_duration - (total_idle or timedelta(0)))

        # Calculate focus time (time spent actively engaging with the page)
        focus_time = timedelta(0)

        # Use tab visibility log to calculate focus time
        if isinstance(self.tab_visibility_log, list) and self.tab_visibility_log:
            focus_periods = []
            focus_start = None

            for event in sorted(self.tab_visibility_log, key=lambda x: x.get('timestamp', '')):
                if event.get('action') == 'focus_gained' and not focus_start:
                    focus_start = event.get('timestamp')
                elif event.get('action') in ['focus_lost', 'focus_lost_to_other_tab'] and focus_start:
                    try:
                        focus_end = event.get('timestamp')
                        focus_periods.append((focus_start, focus_end))
                        focus_start = None
                    except (ValueError, TypeError):
                        focus_start = None

            # Add the last focus period if still in focus
            if focus_start:
                focus_periods.append((focus_start, end_time.isoformat()))

            # Calculate total focus time
            for start, end in focus_periods:
                try:
                    start_dt = timezone.datetime.fromisoformat(start.replace('Z', '+00:00'))

                    if isinstance(end, str):
                        end_dt = timezone.datetime.fromisoformat(end.replace('Z', '+00:00'))
                    else:
                        end_dt = end

                    period_duration = end_dt - start_dt
                    focus_time += period_duration
                except (ValueError, TypeError):
                    continue

        self.focus_time = focus_time
        self.save(update_fields=['working_time', 'focus_time'])

    def calculate_productivity_score(self):
        """
        Calculate productivity score based on working time, idle time, and interaction frequency
        """
        # Ensure working time is calculated
        if not self.working_time:
            self.calculate_working_time()

        # Get session duration
        end_time = self.ended_at or timezone.now()
        session_duration = end_time - self.created_at

        # Avoid division by zero
        if session_duration.total_seconds() == 0:
            self.productivity_score = 0
            return

        # Calculate base score from working time ratio
        working_ratio = self.working_time.total_seconds() / session_duration.total_seconds()
        base_score = working_ratio * 100

        # Calculate interaction frequency score
        interaction_count = (
            len(self.clicks or []) +
            len(self.keyboard_events or []) +
            len(self.scrolls or []) +
            len(self.page_views or [])
        )

        # Normalize interaction count by working time (per hour)
        working_hours = self.working_time.total_seconds() / 3600
        if working_hours > 0:
            interactions_per_hour = interaction_count / working_hours

            # Score based on interactions per hour (diminishing returns after 300)
            interaction_score = min(100, interactions_per_hour / 3)
        else:
            interaction_score = 0

        # Final productivity score is weighted average
        self.productivity_score = (base_score * 0.7) + (interaction_score * 0.3)

        # Clamp to 0-100 range
        self.productivity_score = max(0, min(100, self.productivity_score))

        self.save(update_fields=['productivity_score'])

    def calculate_engagement_score(self):
        """
        Calculate engagement score based on focus time, interaction rate, page view rate, and session length
        """
        # Ensure working time and focus time are calculated
        if not self.working_time or not self.focus_time:
            self.calculate_working_time()

        # Get session duration
        end_time = self.ended_at or timezone.now()
        session_duration = end_time - self.created_at

        # Avoid division by zero
        if session_duration.total_seconds() == 0:
            self.engagement_score = 0
            return

        # Calculate focus ratio (focus time / working time)
        if self.working_time.total_seconds() > 0:
            focus_ratio = self.focus_time.total_seconds() / self.working_time.total_seconds()
        else:
            focus_ratio = 0

        # Calculate interaction rate (interactions per minute of working time)
        interaction_count = (
            len(self.clicks or []) +
            len(self.keyboard_events or []) +
            len(self.scrolls or [])
        )

        working_minutes = self.working_time.total_seconds() / 60
        if working_minutes > 0:
            interaction_rate = interaction_count / working_minutes
        else:
            interaction_rate = 0

        # Calculate page view rate (page views per hour)
        page_view_count = len(self.page_views or [])
        working_hours = self.working_time.total_seconds() / 3600
        if working_hours > 0:
            page_view_rate = page_view_count / working_hours
        else:
            page_view_rate = 0

        # Calculate session length score (diminishing returns after 2 hours)
        session_hours = session_duration.total_seconds() / 3600
        session_length_score = min(100, session_hours * 50)

        # Calculate component scores (0-100 scale)
        focus_score = focus_ratio * 100
        interaction_score = min(100, interaction_rate * 10)  # Cap at 10 interactions per minute
        page_view_score = min(100, page_view_rate * 5)  # Cap at 20 page views per hour

        # Final engagement score is weighted average
        self.engagement_score = (
            (focus_score * 0.4) +
            (interaction_score * 0.3) +
            (page_view_score * 0.2) +
            (session_length_score * 0.1)
        )

        # Clamp to 0-100 range
        self.engagement_score = max(0, min(100, self.engagement_score))

        self.save(update_fields=['engagement_score'])

    def check_security_anomalies(self):
        """
        Check for security anomalies in the session
        """
        anomalies = []

        # Check for fingerprint mismatch
        if self.browser_fingerprint:
            # Get other active sessions for this user
            other_sessions = UserSession.objects.filter(
                user=self.user,
                is_active=True
            ).exclude(id=self.id)

            for session in other_sessions:
                if session.browser_fingerprint and session.browser_fingerprint != self.browser_fingerprint:
                    anomalies.append({
                        'type': 'fingerprint_mismatch',
                        'severity': 'high',
                        'details': {
                            'session_id': str(session.id),
                            'timestamp': timezone.now().isoformat()
                        }
                    })

        # Check for excessive clicking (potential bot/automation)
        if isinstance(self.clicks, list) and len(self.clicks) > 0:
            # Calculate clicks per minute
            end_time = self.ended_at or timezone.now()
            session_minutes = (end_time - self.created_at).total_seconds() / 60

            if session_minutes > 0:
                clicks_per_minute = len(self.clicks) / session_minutes

                if clicks_per_minute > 30:  # More than 30 clicks per minute is suspicious
                    anomalies.append({
                        'type': 'excessive_clicking',
                        'severity': 'medium',
                        'details': {
                            'clicks_per_minute': clicks_per_minute,
                            'timestamp': timezone.now().isoformat()
                        }
                    })

        # Check for rapid tab switching
        if isinstance(self.tab_visibility_log, list) and len(self.tab_visibility_log) > 10:
            # Calculate tab switches per minute
            end_time = self.ended_at or timezone.now()
            session_minutes = (end_time - self.created_at).total_seconds() / 60

            if session_minutes > 0:
                switches_per_minute = len(self.tab_visibility_log) / session_minutes / 2  # Divide by 2 because each switch is 2 events

                if switches_per_minute > 10:  # More than 10 switches per minute is suspicious
                    anomalies.append({
                        'type': 'rapid_tab_switching',
                        'severity': 'low',
                        'details': {
                            'switches_per_minute': switches_per_minute,
                            'timestamp': timezone.now().isoformat()
                        }
                    })

        # Update security anomalies if new ones found
        if anomalies:
            if not isinstance(self.security_anomalies, list):
                self.security_anomalies = []

            self.security_anomalies.extend(anomalies)
            self.security_score = self.calculate_security_score()

            self.save(update_fields=['security_anomalies', 'security_score'])

        return anomalies

    def calculate_security_score(self):
        """
        Calculate security score based on anomalies
        """
        if not isinstance(self.security_anomalies, list):
            return 100

        # Count anomalies by severity
        high_count = sum(1 for a in self.security_anomalies if a.get('severity') == 'high')
        medium_count = sum(1 for a in self.security_anomalies if a.get('severity') == 'medium')
        low_count = sum(1 for a in self.security_anomalies if a.get('severity') == 'low')

        # Calculate score (100 is best, 0 is worst)
        score = 100 - (high_count * 20) - (medium_count * 10) - (low_count * 5)

        # Clamp to 0-100 range
        return max(0, min(100, score))

    def should_show_warning(self, warning_threshold_minutes=25):
        """
        Determine if an inactivity warning should be shown
        """
        if not self.is_active or not self.is_idle:
            return False

        # Calculate idle time
        now = timezone.now()
        if not self.idle_start_time:
            return False

        idle_minutes = (now - self.idle_start_time).total_seconds() / 60

        # Show warning if idle time is greater than warning threshold
        # but less than auto-logout threshold
        return idle_minutes >= warning_threshold_minutes and idle_minutes < 30

    def get_remaining_time(self):
        """
        Get remaining time until auto-logout in minutes
        """
        if not self.is_active or not self.is_idle or not self.idle_start_time:
            return 30  # Default auto-logout threshold

        # Calculate idle time
        now = timezone.now()
        idle_minutes = (now - self.idle_start_time).total_seconds() / 60

        # Calculate remaining time
        remaining = max(0, 30 - idle_minutes)  # 30 minutes is the auto-logout threshold

        return round(remaining)

    def get_idle_time(self):
        """
        Get current idle time in minutes
        """
        if not self.is_idle or not self.idle_start_time:
            return 0

        # Calculate idle time
        now = timezone.now()
        idle_minutes = (now - self.idle_start_time).total_seconds() / 60

        return round(idle_minutes)

    def get_session_duration(self):
        """
        Get session duration in minutes
        """
        end_time = self.ended_at or timezone.now()
        duration = (end_time - self.created_at).total_seconds() / 60

        return round(duration)

    def get_working_time_minutes(self):
        """
        Get working time in minutes
        """
        self.calculate_working_time()  # Ensure working time is up to date
        return round(self.working_time.total_seconds() / 60)

    def get_focus_time_minutes(self):
        """
        Get focus time in minutes
        """
        self.calculate_working_time()  # Ensure focus time is up to date
        return round(self.focus_time.total_seconds() / 60)

    def get_session_summary(self):
        """
        Get a summary of the session
        """
        # Ensure metrics are up to date
        if self.is_active:
            self.calculate_working_time()
            self.calculate_productivity_score()
            self.calculate_engagement_score()
            self.check_security_anomalies()

        # Get page view count by URL
        page_views_by_url = {}
        if isinstance(self.page_views, list):
            for view in self.page_views:
                url = view.get('url')
                if url:
                    if url not in page_views_by_url:
                        page_views_by_url[url] = {
                            'count': 0,
                            'title': view.get('title', '')
                        }
                    page_views_by_url[url]['count'] += 1

        # Get most visited URLs
        most_visited = []
        if isinstance(self.visited_urls, dict):
            sorted_urls = sorted(
                self.visited_urls.items(),
                key=lambda x: x[1].get('count', 0),
                reverse=True
            )[:5]  # Top 5 most visited

            most_visited = [
                {
                    'url': url,
                    'count': data.get('count', 0),
                    'title': data.get('title', '')
                }
                for url, data in sorted_urls
            ]

        # Get related tabs
        related_tabs = []
        if isinstance(self.related_tabs, list):
            for tab in self.related_tabs:
                related_tabs.append({
                    'tab_id': tab.get('tab_id'),
                    'first_seen': tab.get('first_seen'),
                    'last_seen': tab.get('last_seen'),
                    'event_count': len(tab.get('events', []))
                })

        return {
            'session_id': str(self.id),
            'user': self.user.username,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'is_active': self.is_active,
            'is_idle': self.is_idle,
            'idle_time_minutes': self.get_idle_time(),
            'session_duration_minutes': self.get_session_duration(),
            'working_time_minutes': self.get_working_time_minutes(),
            'focus_time_minutes': self.get_focus_time_minutes(),
            'productivity_score': round(self.productivity_score) if self.productivity_score is not None else None,
            'engagement_score': round(self.engagement_score) if self.engagement_score is not None else None,
            'security_score': round(self.security_score) if self.security_score is not None else None,
            'device_type': self.device_type,
            'location': {
                'country': self.location_country,
                'region': self.location_region,
                'city': self.location_city,
                'type': self.location_type
            },
            'activity_counts': {
                'page_views': len(self.page_views or []),
                'clicks': len(self.clicks or []),
                'scrolls': len(self.scrolls or []),
                'keyboard_events': len(self.keyboard_events or []),
                'mouse_movements': self.mouse_movements
            },
            'most_visited_urls': most_visited,
            'related_tabs': related_tabs,
            'security_anomalies': self.security_anomalies if isinstance(self.security_anomalies, list) else []
        }


    def determine_location(self):
        """
        Determine location based on IP address
        """
        if self.ip_address:
            self.update_location_from_ip()
        return {
            'country': self.location_country or 'Unknown',
            'region': self.location_region or 'Unknown',
            'city': self.location_city or 'Unknown',
            'type': self.location_type or 'unknown'
        }

    def save(self, *args, **kwargs):
        # Initialize JSON fields with proper defaults if they are None
        json_fields = ['tab_title', 'tab_url', 'url', 'title', 'referrer', 'page_views',
                      'clicks', 'scrolls', 'keyboard_events', 'tab_visibility_log',
                      'idle_state_changes', 'visited_urls', 'related_tabs', 'security_anomalies']

        for field in json_fields:
            field_value = getattr(self, field)
            if field_value is None:
                if field in ['visited_urls', 'performance_metrics', 'offline_data']:
                    setattr(self, field, {})
                else:
                    setattr(self, field, [])

        # Generate session_key if not set
        if not self.session_key:
            self.session_key = self.generate_session_key()

        # Generate tab_id if not set
        if not self.tab_id:
            self.tab_id = str(uuid.uuid4())

        # Set tab opened time for new records
        if not self.pk and not self.tab_opened_time:
            self.tab_opened_time = self.login_time or timezone.now()

        # Generate parent_session_id if not set (this becomes the primary session)
        if not self.parent_session_id and not self.pk:
            self.parent_session_id = uuid.uuid4()
            self.is_primary_tab = True
            logger.info(f"Auto-generating parent_session_id in save(): {self.parent_session_id}")

        # Set location if not already set for new sessions
        if not self.pk and not self.location_city and self.ip_address:
            try:
                self.update_location_from_ip()
            except Exception as e:
                logger.warning(f"Failed to update location from IP: {e}")

        # All times should already be in UTC when saved to DB
        super().save(*args, **kwargs)

        if not hasattr(self, '_skip_log') or not self._skip_log:
            logger.info(f"Session saved: {self.id} for user {self.user.username}, active: {self.is_active}, idle: {self.is_idle}")

class SessionActivity(models.Model):
    """
    Separate model for tracking user activities to improve performance
    """
    # Link to session
    session = models.ForeignKey(UserSession, on_delete=models.CASCADE, related_name='activities')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='session_activities')

    # Activity timing
    created_at = models.DateTimeField(auto_now_add=True)
    activity_time = models.DateTimeField(default=timezone.now)

    # Activity type and data
    ACTIVITY_TYPES = (
        ('click', 'Click'),
        ('scroll', 'Scroll'),
        ('keyboard', 'Keyboard'),
        ('mouse_move', 'Mouse Move'),
        ('page_view', 'Page View'),
        ('tab_visibility', 'Tab Visibility'),
        ('idle_state', 'Idle State'),
        ('heartbeat', 'Heartbeat'),
        ('location_update', 'Location Update'),
    )
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_TYPES)
    activity_data = models.JSONField(default=dict, blank=True)

    # Page information
    url = models.URLField(max_length=2000, null=True, blank=True)
    title = models.CharField(max_length=500, null=True, blank=True)

    # Location data (if applicable)
    location_latitude = models.FloatField(null=True, blank=True)
    location_longitude = models.FloatField(null=True, blank=True)
    location_accuracy = models.FloatField(null=True, blank=True)

    # Activity metrics
    productivity_score = models.FloatField(null=True, blank=True)
    engagement_score = models.FloatField(null=True, blank=True)

    class Meta:
        db_table = 'trueAlign_sessionactivity'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['session', 'activity_type'], name='session_activity_type_idx'),
            models.Index(fields=['user', 'activity_time'], name='user_activity_time_idx'),
            models.Index(fields=['created_at'], name='activity_created_at_idx'),
            models.Index(fields=['activity_type', 'activity_time'], name='type_time_idx'),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.activity_type} at {self.activity_time}"

    @classmethod
    def record_activity(cls, session, activity_type, activity_data=None, url=None, title=None, location_data=None):
        """
        Record a user activity using enhanced batch writer and location synchronizer
        """
        from trueAlign.core import get_batch_writer, get_location_synchronizer, get_session_logger

        try:
            # Validate required parameters
            if not session:
                logger.error("Cannot record activity: session is required")
                return None

            if not activity_type:
                logger.warning("Cannot record activity: activity_type is required")
                return None

            # Validate activity_type is in allowed list
            allowed_types = [choice[0] for choice in cls.ACTIVITY_TYPES]
            if activity_type not in allowed_types:
                logger.warning(f"Unknown activity type: {activity_type}. Using 'heartbeat' as fallback.")
                activity_type = 'heartbeat'

            # Ensure activity_data is a dict
            if activity_data is None:
                activity_data = {}
            elif not isinstance(activity_data, dict):
                logger.warning(f"activity_data should be a dict, got {type(activity_data)}. Converting to dict.")
                try:
                    if isinstance(activity_data, str):
                        activity_data = json.loads(activity_data)
                    else:
                        activity_data = {'data': str(activity_data)}
                except json.JSONDecodeError:
                    activity_data = {'raw_data': str(activity_data)}

            # Validate and truncate URL if too long
            if url and len(url) > 2000:
                logger.warning(f"URL too long ({len(url)} chars), truncating to 2000 chars")
                url = url[:2000]

            # Validate and truncate title if too long
            if title and len(title) > 500:
                logger.warning(f"Title too long ({len(title)} chars), truncating to 500 chars")
                title = title[:500]

            # Add timestamp to activity_data if not present
            if 'timestamp' not in activity_data:
                activity_data['timestamp'] = timezone.now().isoformat()

            # Get enhanced components
            batch_writer = get_batch_writer()
            location_sync = get_location_synchronizer()
            session_logger = get_session_logger()

            # Use batch writer for efficient activity recording
            batch_writer.add_activity(
                user_id=session.user.id,
                session_id=session.id,
                activity_type=activity_type,
                activity_data=activity_data,
                location_data=location_data,
                url=url,
                title=title
            )

            # Queue location update for synchronization if location data exists
            if location_data and isinstance(location_data, dict):
                try:
                    # Validate basic location data structure
                    lat = location_data.get('latitude')
                    lng = location_data.get('longitude')

                    if lat is not None and lng is not None:
                        lat = float(lat)
                        lng = float(lng)

                        # Validate coordinate ranges
                        if -90 <= lat <= 90 and -180 <= lng <= 180:
                            # Queue for location synchronization
                            location_sync.queue_location_update(
                                session_id=session.id,
                                activity_id=None,  # Will be set when activity is created
                                location_data=location_data,
                                timestamp=timezone.now()
                            )

                            logger.debug(f"Queued location update for session {session.id}: lat={lat}, lng={lng}")
                        else:
                            logger.warning(f"Invalid coordinates: lat={lat}, lng={lng}")
                            session_logger.log_location_update(
                                session.user, session.id, location_data, success=False,
                                error="Invalid coordinate ranges"
                            )
                    else:
                        logger.warning("Missing latitude or longitude in location data")

                except (ValueError, TypeError) as e:
                    logger.warning(f"Error processing location data: {e}")
                    session_logger.log_location_update(
                        session.user, session.id, location_data, success=False, error=str(e)
                    )

            # Update session's last activity timestamp using cache
            cache_key = f"session_last_activity_{session.id}"
            cache.set(cache_key, timezone.now().isoformat(), 300)  # 5 minutes

            # Immediate database update only for critical activities
            if activity_type in ['session_end', 'logout', 'error']:
                session.last_activity = timezone.now()
                session.save(update_fields=['last_activity'])

            logger.debug(f"Queued {activity_type} activity for session {session.id} (batched)")

            # Return a mock activity object for compatibility
            # Note: The actual activity will be created by the batch writer
            from types import SimpleNamespace
            mock_activity = SimpleNamespace(
                id=None,  # Will be set when actually created
                session=session,
                user=session.user,
                activity_type=activity_type,
                activity_data=activity_data,
                url=url,
                title=title,
                timestamp=timezone.now(),
                location_data=location_data
            )

            return mock_activity

        except Exception as e:
            # Log error using enhanced logger
            session_logger.log_error(
                'activity_recording_error',
                str(e),
                user=session.user if session else None,
                session_id=session.id if session else None,
                details={
                    'activity_type': activity_type,
                    'has_location_data': bool(location_data)
                }
            )
            logger.error(f"Error recording activity: {e}", exc_info=True)
            return None

    @classmethod
    def get_recent_activities(cls, session, hours=24):
        """
        Get recent activities for a session
        """
        cutoff_time = timezone.now() - timedelta(hours=hours)
        return cls.objects.filter(
            session=session,
            activity_time__gte=cutoff_time
        ).order_by('-activity_time')

    @classmethod
    def get_activity_summary(cls, session):
        """
        Get activity summary for a session
        """
        activities = cls.objects.filter(session=session)

        summary = {}
        for activity_type, _ in cls.ACTIVITY_TYPES:
            count = activities.filter(activity_type=activity_type).count()
            summary[activity_type] = count

        return summary

    @classmethod
    def cleanup_old_activities(cls, days=30):
        """
        Clean up activities older than specified days
        """
        cutoff_date = timezone.now() - timedelta(days=days)
        deleted_count = cls.objects.filter(created_at__lt=cutoff_date).delete()[0]
        logger.info(f"Cleaned up {deleted_count} old session activities")
        return deleted_count



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

    # Role/Designation Choices
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('hr', 'HR'),
        ('manager', 'Manager'),
        ('team_lead', 'Team Lead'),
        ('senior_developer', 'Senior Developer'),
        ('developer', 'Developer'),
        ('junior_developer', 'Junior Developer'),
        ('intern', 'Intern'),
        ('qa_engineer', 'QA Engineer'),
        ('devops_engineer', 'DevOps Engineer'),
        ('ui_ux_designer', 'UI/UX Designer'),
        ('business_analyst', 'Business Analyst'),
        ('project_manager', 'Project Manager'),
        ('scrum_master', 'Scrum Master'),
        ('consultant', 'Consultant'),
        ('trainee', 'Trainee'),
        ('other', 'Other')
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
    role = models.CharField(
        max_length=50,
        choices=ROLE_CHOICES,
        default='developer',
        help_text="Employee role/designation in the company"
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
    office_location = models.ForeignKey(
        OfficeLocation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='employees',
        help_text="Office location where the employee works"
    )
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
            models.Index(fields=['office_location']),
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


# Dashboard Layout Preferences Model
class LayoutPreference(models.Model):
    """
    Model to store user's dashboard layout preferences
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='layout_preference'
    )
    layout = JSONField(
        default=dict,
        help_text="JSON data storing card positions, sizes, and order"
    )
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Layout Preference"
        verbose_name_plural = "Layout Preferences"

    def __str__(self):
        return f"{self.user.username}'s Layout Preference"




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

    # Validation constants
    MIN_SHIFT_DURATION = 0.5  # 30 minutes minimum
    MAX_SHIFT_DURATION = 24.0  # 24 hours maximum
    MAX_BREAK_HOURS = 8.0  # 8 hours maximum break
    MAX_GRACE_MINUTES = 120  # 2 hours maximum grace period
    name = models.CharField(max_length=50)
    start_time = models.TimeField()
    end_time = models.TimeField()
    shift_duration = models.DecimalField(max_digits=5, decimal_places=2, default=8.0)
    break_duration = models.DurationField(default=timedelta(minutes=30))
    grace_period = models.DurationField(default=timedelta(minutes=15))
    work_days = models.CharField(max_length=20, choices=WORK_DAYS_CHOICES, default='Weekdays')
    # Increased max_length to 255 to handle longer custom day lists
    custom_work_days = models.CharField(max_length=255, null=True, blank=True, help_text="Comma-separated day names (Monday,Tuesday,etc.)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Shift"
        verbose_name_plural = "Shifts"
        constraints = [
            # Ensure shift duration is reasonable
            models.CheckConstraint(
                check=models.Q(shift_duration__gte=0.5) & models.Q(shift_duration__lte=24.0),
                name='shift_duration_range'
            ),
            # Ensure unique shift names
            models.UniqueConstraint(
                fields=['name'],
                name='unique_shift_name'
            ),
        ]
        indexes = [
            models.Index(fields=['name', 'is_active']),
            models.Index(fields=['start_time', 'end_time']),
            models.Index(fields=['is_active']),
        ]

    @property
    def crosses_midnight(self):
        """Determine if the shift crosses midnight"""
        return self.end_time < self.start_time

    def clean(self):
        """Comprehensive model validation"""
        from django.core.exceptions import ValidationError
        errors = {}

        # Validate shift name
        if not self.name or not self.name.strip():
            errors['name'] = 'Shift name is required.'
        elif len(self.name.strip()) > 50:
            errors['name'] = 'Shift name cannot exceed 50 characters.'

        # Check for duplicate names (case-insensitive)
        if self.name:
            existing = ShiftMaster.objects.filter(
                name__iexact=self.name.strip()
            )
            if self.pk:
                existing = existing.exclude(pk=self.pk)
            if existing.exists():
                errors['name'] = f'A shift with the name "{self.name}" already exists.'

        # Validate times
        if not self.start_time:
            errors['start_time'] = 'Start time is required.'
        if not self.end_time:
            errors['end_time'] = 'End time is required.'

        # Validate shift duration
        if self.shift_duration is not None:
            if self.shift_duration < self.MIN_SHIFT_DURATION:
                errors['shift_duration'] = f'Shift duration must be at least {self.MIN_SHIFT_DURATION} hours.'
            elif self.shift_duration > self.MAX_SHIFT_DURATION:
                errors['shift_duration'] = f'Shift duration cannot exceed {self.MAX_SHIFT_DURATION} hours.'

        # Validate break duration
        if self.break_duration:
            break_hours = self.break_duration.total_seconds() / 3600
            if break_hours > self.MAX_BREAK_HOURS:
                errors['break_duration'] = f'Break duration cannot exceed {self.MAX_BREAK_HOURS} hours.'

            # Break cannot exceed shift duration
            if self.shift_duration and break_hours >= float(self.shift_duration):
                errors['break_duration'] = 'Break duration must be less than shift duration.'

        # Validate grace period
        if self.grace_period:
            grace_minutes = self.grace_period.total_seconds() / 60
            if grace_minutes > self.MAX_GRACE_MINUTES:
                errors['grace_period'] = f'Grace period cannot exceed {self.MAX_GRACE_MINUTES} minutes.'

        # Validate custom work days
        if self.work_days == 'Custom':
            if not self.custom_work_days:
                errors['custom_work_days'] = 'Custom work days are required when "Custom" is selected.'
            else:
                try:
                    self._validate_custom_work_days()
                except ValidationError as e:
                    errors['custom_work_days'] = str(e)

        # Time consistency validation
        if self.start_time and self.end_time:
            # For same-day shifts, end time should be after start time
            if not self.crosses_midnight and self.start_time >= self.end_time:
                if self.start_time == self.end_time:
                    errors['__all__'] = 'Shift duration must be greater than zero.'
                else:
                    errors['__all__'] = 'End time must be after start time for same-day shifts. For overnight shifts, end time should be earlier than start time.'

        # Check for overlapping shifts with same work pattern
        if self.start_time and self.end_time and self.work_days:
            overlapping = self._check_shift_overlap()
            if overlapping:
                errors['__all__'] = f'This shift overlaps with existing shift: {overlapping.name}'

        if errors:
            raise ValidationError(errors)

    def _validate_custom_work_days(self):
        """Validate custom work days format"""
        from django.core.exceptions import ValidationError

        if not self.custom_work_days:
            return

        valid_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        day_names = [day.strip() for day in self.custom_work_days.split(',') if day.strip()]

        if not day_names:
            raise ValidationError('At least one work day must be specified.')

        # Check for invalid day names
        invalid_days = [day for day in day_names if day not in valid_days]
        if invalid_days:
            raise ValidationError(f'Invalid day names: {", ".join(invalid_days)}. Valid days: {", ".join(valid_days)}')

        # Check for duplicates
        if len(day_names) != len(set(day_names)):
            raise ValidationError('Duplicate day names found in custom work days.')

        # Ensure at least one working day
        if len(day_names) == 0:
            raise ValidationError('At least one working day must be specified.')

    def _check_shift_overlap(self):
        """Check for overlapping shifts with similar work patterns"""
        # Get other active shifts
        other_shifts = ShiftMaster.objects.filter(is_active=True)
        if self.pk:
            other_shifts = other_shifts.exclude(pk=self.pk)

        my_work_days = set(self.working_days_list)

        for shift in other_shifts:
            other_work_days = set(shift.working_days_list)

            # Check if work days overlap
            if my_work_days.intersection(other_work_days):
                # Check time overlap
                if self._times_overlap(shift):
                    return shift

        return None

    def _times_overlap(self, other_shift):
        """Check if two shifts have overlapping times"""
        # Convert times to minutes for easier comparison
        my_start = self.start_time.hour * 60 + self.start_time.minute
        my_end = self.end_time.hour * 60 + self.end_time.minute

        other_start = other_shift.start_time.hour * 60 + other_shift.start_time.minute
        other_end = other_shift.end_time.hour * 60 + other_shift.end_time.minute

        # Handle midnight crossover
        if self.crosses_midnight:
            my_end += 24 * 60  # Add 24 hours in minutes

        if other_shift.crosses_midnight:
            other_end += 24 * 60

        # Check for actual overlap (not just touching)
        # Two shifts overlap only if one starts before the other ends AND vice versa
        return (my_start < other_end) and (other_start < my_end)

    def get_working_days(self):
        """Return a list of working day names"""
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        working_day_indices = self.working_days_list
        return [day_names[i] for i in working_day_indices]


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

    def is_night_shift(self):
        """
        Determine if this is a night shift based on timing
        """
        # If end time is before start time, it crosses midnight (night shift)
        if self.crosses_midnight:
            return True

        # If shift starts after 6 PM, consider it a night shift
        if self.start_time.hour >= 18:
            return True

        # If shift name explicitly contains "Night"
        if 'night' in self.name.lower():
            return True

        return False

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

    from decimal import Decimal

    # Inside your Django model class

    @property
    def expected_hours(self) -> Decimal:
        """
        Calculates the expected work hours by subtracting the break duration
        from the total shift duration.
        """
        # self.break_duration is a timedelta object on a model instance
        break_seconds = self.break_duration.total_seconds()

        # Convert break_seconds to hours as a Decimal
        break_hours = Decimal(break_seconds) / Decimal(3600)

        # self.shift_duration is already a Decimal object
        # No need to cast it again with Decimal()
        return self.shift_duration - break_hours


    def __str__(self):
        return f"{self.name} ({self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')})"

    def save(self, *args, **kwargs):
        # Clean the model before saving
        self.full_clean()

        # Check if this is a new object (not yet saved to database)
        is_new = self.pk is None

        # Set default times and durations based on shift type for new objects
        if is_new:
            if self.name == 'Day Shift' and not hasattr(self, '_start_time_set'):
                self.start_time = time(9, 0)  # 9:00 AM
                self.end_time = time(17, 30)  # 5:30 PM (8.5 hours)
                self.shift_duration = Decimal('8.5')
                self.work_days = 'All Days'  # Monday to Saturday
                self._start_time_set = True
            elif self.name == 'Night Shift' and not hasattr(self, '_start_time_set'):
                self.start_time = time(18, 30)  # 6:30 PM
                self.end_time = time(3, 30)    # 3:30 AM (9 hours)
                self.shift_duration = Decimal('9.0')
                self.work_days = 'Weekdays'  # Monday to Friday
                self._start_time_set = True

        # Calculate shift duration if not provided
        if not self.shift_duration or self.shift_duration == Decimal('0.0'):
            # Check if we have valid start and end times
            if self.start_time and self.end_time:
                # Calculate hours between start and end time
                if self.crosses_midnight:
                    # For shifts crossing midnight
                    hours_before_midnight = Decimal(str(24 - self.start_time.hour - self.start_time.minute/60))
                    hours_after_midnight = Decimal(str(self.end_time.hour + self.end_time.minute/60))
                    self.shift_duration = round(hours_before_midnight + hours_after_midnight, 2)
                else:
                    # For regular shifts
                    hours = Decimal(str(self.end_time.hour - self.start_time.hour))
                    minutes = Decimal(str(self.end_time.minute - self.start_time.minute)) / Decimal('60')
                    self.shift_duration = round(hours + minutes, 2)

        # Set default break and grace periods if not set
        if not self.break_duration:
            self.break_duration = timedelta(minutes=30)
        if not self.grace_period:
            self.grace_period = timedelta(minutes=15)

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

class ShiftAssignment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shift_assignments')
    shift = models.ForeignKey(ShiftMaster, on_delete=models.PROTECT, related_name='assignments')
    effective_from = models.DateField()
    effective_to = models.DateField(null=True, blank=True)
    is_current = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True, null=True)  # example



    # Additional fields for better tracking
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_assignments',
        help_text="User who created this assignment"
    )
    notes = models.TextField(
        blank=True,
        help_text="Additional notes about this assignment"
    )

    class Meta:
        verbose_name = "Shift Assignment"
        verbose_name_plural = "Shift Assignments"
        constraints = [
            # Prevent overlapping assignments for same user
            models.UniqueConstraint(
                fields=['user', 'effective_from'],
                condition=models.Q(is_current=True),
                name='unique_current_assignment_per_user'
            ),
            # Ensure effective_to is after effective_from
            models.CheckConstraint(
                check=models.Q(effective_to__isnull=True) | models.Q(effective_to__gt=models.F('effective_from')),
                name='valid_date_range'
            ),
        ]
        indexes = [
            models.Index(fields=['user', 'effective_from']),
            models.Index(fields=['is_current']),
            models.Index(fields=['effective_from', 'effective_to']),
            models.Index(fields=['shift', 'effective_from']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.shift.name} (from {self.effective_from})"

    def clean(self):
        """Comprehensive validation for shift assignments"""
        from django.core.exceptions import ValidationError
        errors = {}

        # Validate required fields
        if not self.user:
            errors['user'] = 'User is required.'
        if not self.shift:
            errors['shift'] = 'Shift is required.'
        if not self.effective_from:
            errors['effective_from'] = 'Effective from date is required.'

        # Validate date range
        if self.effective_from and self.effective_to:
            if self.effective_to <= self.effective_from:
                errors['effective_to'] = 'Effective to date must be after effective from date.'

        # Prevent assignments in the past (with some flexibility for admin users)
        if self.effective_from:
            today = timezone.now().date()
            # Allow assignments up to 7 days in the past for corrections
            if self.effective_from < (today - timedelta(days=7)):
                errors['effective_from'] = 'Assignment cannot be more than 7 days in the past.'

        # Check for overlapping assignments
        if self.user and self.effective_from:
            overlapping = self._check_overlapping_assignments()
            if overlapping:
                errors['__all__'] = f'This assignment overlaps with existing assignment: {overlapping}'

        # Validate shift is active
        if self.shift and not self.shift.is_active:
            errors['shift'] = 'Cannot assign inactive shift.'

        if errors:
            raise ValidationError(errors)

    def _check_overlapping_assignments(self):
        """Check for overlapping assignments for the same user"""
        queryset = ShiftAssignment.objects.filter(
            user=self.user,
            effective_from__lte=self.effective_to or timezone.now().date()
        )

        if self.effective_to:
            queryset = queryset.filter(effective_to__gte=self.effective_from)
        else:
            queryset = queryset.filter(
                Q(effective_to__gte=self.effective_from) | Q(effective_to__isnull=True)
            )

        if self.pk:
            queryset = queryset.exclude(pk=self.pk)

        overlapping = queryset.first()
        if overlapping:
            return f"{overlapping.shift.name} from {overlapping.effective_from} to {overlapping.effective_to or 'ongoing'}"
        return None

    def save(self, *args, **kwargs):
        # Clean the model before saving
        self.full_clean()

        # Handle string dates if necessary
        if isinstance(self.effective_from, str):
            self.effective_from = timezone.datetime.strptime(self.effective_from, '%Y-%m-%d').date()

        if isinstance(self.effective_to, str):
            self.effective_to = timezone.datetime.strptime(self.effective_to, '%Y-%m-%d').date()

        # Set current assignment logic
        if self.is_current:
            # Mark other current assignments for this user as not current
            other_assignments = ShiftAssignment.objects.filter(
                user=self.user,
                is_current=True
            ).exclude(id=self.id if self.id else None)

            for assignment in other_assignments:
                assignment.is_current = False
                if not assignment.effective_to:
                    assignment.effective_to = self.effective_from - timedelta(days=1)
                assignment.save(update_fields=['is_current', 'effective_to'])

        super().save(*args, **kwargs)

    def is_active_on(self, date):
        """Check if this shift assignment is active on a given date"""
        if self.effective_from <= date and (not self.effective_to or date <= self.effective_to):
            return True
        return False

    def days_remaining(self):
        """Return number of days left in this shift assignment"""
        today = timezone.now().date()
        if self.effective_to:
            remaining = (self.effective_to - today).days
            return max(remaining, 0)
        return None  # Open-ended shift

    def total_duration(self):
        """Return total duration in days of the shift assignment"""
        if self.effective_to:
            return (self.effective_to - self.effective_from).days + 1
        return None

    def has_ended(self):
        """Check if this shift assignment has ended"""
        if self.effective_to and self.effective_to < timezone.now().date():
            return True
        return False

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
                day_shift = ShiftMaster.objects.create(
                    name='Day Shift',
                    start_time=time(9, 0),
                    end_time=time(17, 30),
                    shift_duration=8.5,
                    work_days='All Days'
                )
            return day_shift

        return assignment.shift

    @classmethod
    def current_assignment_for_user(cls, user):
        """Get current active assignment for user"""
        today = timezone.now().date()
        return cls.objects.filter(
            user=user,
            effective_from__lte=today
        ).filter(
            Q(effective_to__gte=today) | Q(effective_to__isnull=True)
        ).order_by('-effective_from').first()

    @classmethod
    def upcoming_shift_endings(cls, days=7):
        """Find shift assignments ending in next N days"""
        today = timezone.now().date()
        end_limit = today + timedelta(days=days)
        return cls.objects.filter(
            effective_to__range=(today, end_limit)
        ).select_related('user', 'shift')

    @classmethod
    def get_shift_history(cls, user, start_date=None, end_date=None):
        """Get shift assignment history for a user within date range"""
        query = cls.objects.filter(user=user)
        if start_date:
            query = query.filter(effective_from__gte=start_date)
        if end_date:
            query = query.filter(effective_to__lte=end_date)
        return query.order_by('-effective_from')
        if self.user and not self.user.is_active:
            errors['user'] = 'Cannot assign shift to inactive user.'

        if errors:
            raise ValidationError(errors)

    def _check_assignment_overlap(self):
        """Check for overlapping assignments for the same user"""
        assignments = ShiftAssignment.objects.filter(user=self.user)
        if self.pk:
            assignments = assignments.exclude(pk=self.pk)

        for assignment in assignments:
            if self._dates_overlap(assignment):
                return assignment
        return None

    def _dates_overlap(self, other_assignment):
        """Check if two assignments have overlapping date ranges"""
        # This assignment's range
        my_start = self.effective_from
        my_end = self.effective_to  # Can be None

        # Other assignment's range
        other_start = other_assignment.effective_from
        other_end = other_assignment.effective_to  # Can be None

        # If either assignment has no end date, check if starts overlap
        if my_end is None and other_end is None:
            return my_start == other_start

        if my_end is None:
            return my_start <= (other_end or other_start)

        if other_end is None:
            return other_start <= my_end

        # Both have end dates - allow same-day transitions (end date == start date)
        return not (my_end <= other_start or other_end <= my_start)

    def save(self, *args, **kwargs):
        # Clean the model before saving
        self.full_clean()

        if isinstance(self.effective_from, str):
            self.effective_from = timezone.datetime.strptime(self.effective_from, '%Y-%m-%d').date()

        # Handle current assignment logic
        if self.is_current:
            # End other current assignments for this user
            other_assignments = ShiftAssignment.objects.filter(
                user=self.user,
                is_current=True
            ).exclude(id=self.id if self.id else None)

            for assignment in other_assignments:
                assignment.is_current = False
                if not assignment.effective_to:
                    # Set end date to day before new assignment starts
                    assignment.effective_to = self.effective_from - timedelta(days=1)
                assignment.save(update_fields=['is_current', 'effective_to'])

        super().save(*args, **kwargs)

    def is_active_on(self, date):
        """Check if this shift assignment is active on a given date"""
        if self.effective_from <= date and (not self.effective_to or date <= self.effective_to):
            return True
        return False

    def days_remaining(self):
        """Return number of days left in this shift assignment"""
        today = timezone.now().date()
        if self.effective_to:
            remaining = (self.effective_to - today).days
            return max(remaining, 0)
        return None  # Open-ended shift

    def total_duration(self):
        """Return total duration in days of the shift assignment"""
        if self.effective_to:
            return (self.effective_to - self.effective_from).days + 1
        return None

    def has_ended(self):
        """Check if this shift assignment has ended"""
        if self.effective_to and self.effective_to < timezone.now().date():
            return True
        return False

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
                day_shift = ShiftMaster.objects.create(
                    name='Day Shift',
                    start_time=time(9, 0),
                    end_time=time(17, 30),
                    shift_duration=8.5,
                    work_days='All Days'
                )
            return day_shift

        return assignment.shift

    @classmethod
    def current_assignment_for_user(cls, user):
        """Get current active assignment for user"""
        today = timezone.now().date()
        return cls.objects.filter(
            user=user,
            effective_from__lte=today
        ).filter(
            models.Q(effective_to__gte=today) | models.Q(effective_to__isnull=True)
        ).order_by('-effective_from').first()

    @classmethod
    def upcoming_shift_endings(cls, days=7):
        """Find shift assignments ending in next N days"""
        today = timezone.now().date()
        end_limit = today + timedelta(days=days)
        return cls.objects.filter(
            effective_to__range=(today, end_limit)
        ).select_related('user', 'shift')

    @classmethod
    def get_shift_history(cls, user, start_date=None, end_date=None):
        """Get shift assignment history for a user within date range"""
        query = cls.objects.filter(user=user)
        if start_date:
            query = query.filter(effective_from__gte=start_date)
        if end_date:
            query = query.filter(effective_to__lte=end_date)
        return query.order_by('-effective_from')

'''----------------------------------- LEAVE AREA -----------------------------------'''
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import User

class LeavePolicy(models.Model):
    """
    Defines leave policies for different groups/departments
    """
    name = models.CharField(max_length=100)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='leave_policies')
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)  # Soft delete
    effective_from = models.DateField(default=get_current_date)
    effective_to = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_leave_policies')

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['group'],
                condition=Q(is_active=True, is_deleted=False),
                name='unique_active_policy_per_group'
            )
        ]
        indexes = [
            models.Index(fields=['group', 'is_active', 'is_deleted']),
            models.Index(fields=['effective_from', 'effective_to']),
        ]

    def clean(self):
        """Validate policy dates"""
        if self.effective_to and self.effective_from > self.effective_to:
            raise ValidationError("Effective from date must be before effective to date")

    def is_effective_on(self, date):
        """Check if policy is effective on given date"""
        if not self.is_active or self.is_deleted:
            return False

        if date < self.effective_from:
            return False

        if self.effective_to and date > self.effective_to:
            return False

        return True

    def __str__(self):
        return f"{self.name} ({self.group.name})"

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
    max_days_allowed = models.PositiveIntegerField(default=30, help_text="Maximum days allowed per year")
    carry_forward_allowed = models.BooleanField(default=False, help_text="Allow carrying forward unused leaves")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class LeaveAllocation(models.Model):
    """
    Defines how many leaves are allocated per leave type in a policy
    """
    policy = models.ForeignKey(LeavePolicy, on_delete=models.CASCADE, related_name='allocations')
    leave_type = models.ForeignKey(LeaveType, on_delete=models.CASCADE)
    annual_days = models.DecimalField(max_digits=5, decimal_places=1, validators=[MinValueValidator(Decimal('0.0'))])
    advance_notice_days = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    max_consecutive_days = models.IntegerField(default=0, help_text="0 means no limit", validators=[MinValueValidator(0)])
    carryforward_limit = models.DecimalField(max_digits=5, decimal_places=1, default=0, validators=[MinValueValidator(Decimal('0.0'))])
    is_deleted = models.BooleanField(default=False)  # Soft delete
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('policy', 'leave_type')
        constraints = [
            models.CheckConstraint(
                check=Q(annual_days__gte=0, advance_notice_days__gte=0, max_consecutive_days__gte=0, carryforward_limit__gte=0),
                name='non_negative_allocation_fields'
            )
        ]
        indexes = [
            models.Index(fields=['policy', 'leave_type', 'is_deleted']),
        ]

    def clean(self):
        """Validate allocation data"""
        if self.carryforward_limit > self.annual_days:
            raise ValidationError("Carryforward limit cannot exceed annual allocation")

    def __str__(self):
        return f"{self.leave_type.name} allocation for {self.policy.name}"

class UserLeaveBalance(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leave_balances')
    leave_type = models.ForeignKey(LeaveType, on_delete=models.CASCADE)
    year = models.IntegerField()
    allocated = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    used = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    carried_forward = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    additional = models.DecimalField(max_digits=5, decimal_places=1, default=0)
    is_deleted = models.BooleanField(default=False)  # Soft delete

    # Custom manager
    objects = UserLeaveBalanceManager()

    class Meta:
        unique_together = ('user', 'leave_type', 'year')
        constraints = [
            models.CheckConstraint(
                check=Q(allocated__gte=0, used__gte=0, carried_forward__gte=0, additional__gte=0),
                name='non_negative_balance_fields'
            )
        ]

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
    is_deleted = models.BooleanField(default=False)  # Soft delete
    _balance_updated = False  # Flag to track if balance has been updated

    # Custom manager
    objects = LeaveRequestManager()

    class Meta:
        indexes = [
            models.Index(fields=['user', 'start_date', 'status']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['approver', 'status']),
        ]
        constraints = [
            models.CheckConstraint(
                check=Q(end_date__gte=models.F('start_date')),
                name='valid_leave_date_range'
            ),
            models.CheckConstraint(
                check=Q(leave_days__gte=0),
                name='positive_leave_days'
            )
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

        # Check for overlapping leaves - include both Approved and Pending
        overlap_statuses = ['Approved', 'Pending']
        overlapping_leaves = LeaveRequest.objects.filter(
            status__in=overlap_statuses,
            start_date__lte=self.end_date,
            end_date__gte=self.start_date,
            user=self.user,
            is_deleted=False
        ).exclude(id=self.id)

        if overlapping_leaves.exists():
            raise ValidationError("You already have approved or pending leave during this period")

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
                is_active=True,
                is_deleted=False
            ).first()
        except LeavePolicy.DoesNotExist:
            return None

    def calculate_leave_days(self):
        """Calculate actual leave days based on leave type configuration"""
        if not (self.start_date and self.end_date):
            return Decimal('0')

        total_days = Decimal('0')
        current_date = self.start_date

        # For single day leave requests, respect half_day setting
        if self.start_date == self.end_date and self.half_day:
            if not (current_date.weekday() >= 5) or self.leave_type.count_weekends:
                return Decimal('0.5')
            else:
                return Decimal('0')

        while current_date <= self.end_date:
            # Skip weekends unless leave type counts weekends
            is_weekend = current_date.weekday() >= 5  # Saturday or Sunday

            if not is_weekend or self.leave_type.count_weekends:
                # For multi-day requests, half_day only applies to first or last day
                if self.half_day and (current_date == self.start_date or current_date == self.end_date):
                    total_days += Decimal('0.5')
                else:
                    total_days += Decimal('1.0')

            current_date += timedelta(days=1)

        return total_days

    def has_sufficient_balance(self):
        """Check if user has sufficient leave balance"""
        if not self.user_id:
            logger.debug("has_sufficient_balance - no user_id")
            return False

        # Skip balance check for unpaid leave types
        if not self.leave_type.is_paid:
            logger.debug(f"has_sufficient_balance - leave type {self.leave_type.name} not paid, returning True")
            return True

        year = self.start_date.year
        try:
            balance = UserLeaveBalance.objects.for_user_and_year(self.user, year).select_for_update().get(
                leave_type=self.leave_type
            )
            days_needed = self.calculate_leave_days()
            has_balance = balance.available >= days_needed
            logger.debug(f"has_sufficient_balance - available: {balance.available}, needed: {days_needed}, result: {has_balance}")
            return has_balance
        except UserLeaveBalance.DoesNotExist:
            logger.debug(f"has_sufficient_balance - no balance record found")
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

    def _update_leave_balance_service(self):
        """Service method to update leave balance when leave is approved"""
        logger.info(f"Updating leave balance for user {self.user_id}, leave type {self.leave_type}")
        if not self.user_id:
            logger.debug("Skipping balance update - no user_id")
            return

        year = self.start_date.year
        leave_days_decimal = self.leave_days if isinstance(self.leave_days, Decimal) else Decimal(str(self.leave_days))

        with transaction.atomic():
            try:
                balance = UserLeaveBalance.objects.for_user_and_year(self.user, year).select_for_update().get(
                    leave_type=self.leave_type
                )
                logger.debug(f"Found balance - current used: {balance.used}, adding: {leave_days_decimal}")
                balance.used = balance.used + leave_days_decimal
                balance.save()
                logger.debug(f"Updated balance - new used total: {balance.used}")
                self._balance_updated = True

            except UserLeaveBalance.DoesNotExist:
                logger.debug(f"No balance record found for user {self.user_id}, leave type {self.leave_type}, year {year}")
                self._create_balance_record(year, leave_days_decimal)

    def _create_balance_record(self, year, leave_days_decimal):
        """Helper method to create new balance record"""
        policy = self.get_user_policy()
        allocated_days = Decimal('0')

        if policy:
            try:
                allocation = LeaveAllocation.objects.get(
                    policy=policy,
                    leave_type=self.leave_type,
                    is_deleted=False
                )
                allocated_days = allocation.annual_days
                logger.debug(f"Found allocation with {allocated_days} days")
            except LeaveAllocation.DoesNotExist:
                logger.debug(f"No allocation found for leave type {self.leave_type} in user's policy")

        balance = UserLeaveBalance.objects.create(
            user=self.user,
            leave_type=self.leave_type,
            year=year,
            allocated=allocated_days,
            used=leave_days_decimal,
            carried_forward=Decimal('0'),
            additional=Decimal('0')
        )
        logger.debug(f"Created balance record with {allocated_days} allocation and {leave_days_decimal} used")
        self._balance_updated = True

    def _revert_leave_balance_service(self):
        """Service method to revert leave balance when leave is cancelled/rejected"""
        if not self.user_id:
            return

        year = self.start_date.year
        leave_days_decimal = self.leave_days if isinstance(self.leave_days, Decimal) else Decimal(str(self.leave_days))

        with transaction.atomic():
            try:
                balance = UserLeaveBalance.objects.for_user_and_year(self.user, year).select_for_update().get(
                    leave_type=self.leave_type
                )
                balance.used = balance.used - leave_days_decimal
                balance.save()
                logger.debug(f"Reverted balance - removed {leave_days_decimal} days, new used total: {balance.used}")
            except UserLeaveBalance.DoesNotExist:
                logger.debug(f"No balance record found to revert for {self.user_id}, {self.leave_type}")
                pass

    def _update_attendance_service(self):
        """Service method to update attendance records for approved leave period"""
        if not self.user_id:
            return

        try:
            # Import here to avoid circular imports
            from django.apps import apps
            Attendance = apps.get_model('trueAlign', 'Attendance')

            current_date = self.start_date
            while current_date <= self.end_date:
                is_weekend = current_date.weekday() >= 5  # Saturday or Sunday

                # Skip weekends unless leave type counts weekends
                if not is_weekend or self.leave_type.count_weekends:
                    defaults = {
                        'status': 'On Leave',
                        'leave_type': self.leave_type.name,
                        'is_half_day': self.half_day and (current_date == self.start_date or current_date == self.end_date),
                        'remarks': f"Auto-marked by leave system: {self.leave_type.name}",
                        'modified_by': None
                    }

                    # Check if attendance already exists and is manually approved
                    try:
                        existing = Attendance.objects.get(user=self.user, date=current_date)
                        if hasattr(existing, 'is_manually_approved') and existing.is_manually_approved:
                            logger.info(f"Skipping attendance update for {current_date} - manually approved")
                            current_date += timedelta(days=1)
                            continue
                    except Attendance.DoesNotExist:
                        pass

                    Attendance.objects.update_or_create(
                        user=self.user,
                        date=current_date,
                        defaults=defaults
                    )
                current_date += timedelta(days=1)

        except Exception as e:
            logger.error(f"Error updating attendance for leave request {self.id}: {str(e)}")

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        previous_status = None
        old_leave_days = Decimal('0')

        if not self.user_id:
            raise ValidationError("User is required")

        # Use consistent timezone handling
        from django.utils import timezone
        today = timezone.localdate()

        # Convert half_day string to boolean if needed
        if isinstance(self.half_day, str):
            self.half_day = self.half_day.lower() == 'true'

        # Calculate leave days with Decimal precision
        self.leave_days = self.calculate_leave_days()

        logger.info(f"Leave request save() - ID: {self.id if not is_new else 'new'}, Status: {self.status}, User: {self.user_id}, Leave type: {self.leave_type.name}, Days: {self.leave_days}")

        # Get previous state for comparison
        if not is_new:
            try:
                previous = LeaveRequest.objects.get(id=self.id)
                previous_status = previous.status
                old_leave_days = previous.leave_days
                logger.debug(f"Previous status: {previous_status}, Old leave days: {old_leave_days}")

                # Track status change for signals
                if previous_status != self.status:
                    self._status_changed = (previous_status, self.status)
                    logger.info(f"Status change detected: {previous_status} -> {self.status}")
            except LeaveRequest.DoesNotExist:
                logger.warning("Could not find previous leave request for comparison")

        try:
            with transaction.atomic():
                # Validate before saving
                self.full_clean()

                # Save the instance
                super().save(*args, **kwargs)

                logger.debug(f"After save, status: {self.status}")

                # Handle status changes
                if self.status == 'Approved':
                    logger.info(f"Processing approved leave - is_new: {is_new}, previous_status: {previous_status}")

                    if is_new or previous_status != 'Approved':
                        # Update balance for newly approved requests
                        self._update_leave_balance_service()
                        self._update_attendance_service()
                        logger.info("Leave balance and attendance updated for approved leave")

                        # Log audit trail
                        LeaveRequestHistory.log_action(
                            leave_request=self,
                            action='approved',
                            performed_by=getattr(self, '_approved_by', None),
                            reason=f"Leave request approved - {self.leave_days} days"
                        )

                    elif previous_status == 'Approved' and self.leave_days != old_leave_days:
                        logger.info(f"Leave days changed from {old_leave_days} to {self.leave_days}")
                        # Handle case where leave days changed for already approved request
                        self._handle_leave_days_change(old_leave_days)

                        # Log audit trail
                        LeaveRequestHistory.log_action(
                            leave_request=self,
                            action='updated',
                            performed_by=getattr(self, '_modified_by', None),
                            old_values={'leave_days': str(old_leave_days)},
                            new_values={'leave_days': str(self.leave_days)},
                            reason="Leave days modified"
                        )

                elif previous_status == 'Approved' and self.status in ['Cancelled', 'Rejected']:
                    logger.info("Reverting previously approved leave")
                    self._revert_leave_balance_service()

                    # Log audit trail
                    LeaveRequestHistory.log_action(
                        leave_request=self,
                        action=self.status.lower(),
                        performed_by=getattr(self, '_modified_by', None),
                        reason=getattr(self, 'rejection_reason', None) or f"Leave request {self.status.lower()}"
                    )

                # Auto-convert to Loss of Pay if insufficient balance and this is a new request
                if is_new and self.status == 'Pending' and self.leave_type.is_paid and not self.has_sufficient_balance():
                    logger.info("Insufficient balance, attempting auto-convert to Loss of Pay")
                    old_leave_type = self.leave_type.name
                    if self.auto_convert_leave_type():
                        logger.info(f"Auto-converted to leave type: {self.leave_type.name}")

                        # Log audit trail
                        LeaveRequestHistory.log_action(
                            leave_request=self,
                            action='updated',
                            old_values={'leave_type': old_leave_type},
                            new_values={'leave_type': self.leave_type.name},
                            reason="Auto-converted due to insufficient balance"
                        )

                        # Re-save with new leave type
                        self.save(update_fields=['leave_type'])

        except ValidationError as e:
            logger.error(f"Validation error in leave request save: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in leave request save: {str(e)}")
            raise ValidationError(f"Error processing leave request: {str(e)}")

    def _handle_leave_days_change(self, old_leave_days):
        """Handle balance adjustment when leave days change for approved request"""
        year = self.start_date.year
        difference = self.leave_days - old_leave_days

        with transaction.atomic():
            try:
                balance = UserLeaveBalance.objects.for_user_and_year(self.user, year).select_for_update().get(
                    leave_type=self.leave_type
                )
                balance.used = balance.used + difference
                balance.save()
                logger.info(f"Adjusted balance for changed leave days. Difference: {difference}, New used: {balance.used}")
            except UserLeaveBalance.DoesNotExist:
                logger.warning("No balance record found for adjustment, updating balance from scratch")
                self._update_leave_balance_service()

class CompOffRequest(models.Model):
    """
    Model to track comp-off requests and approvals
    """
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Cancelled', 'Cancelled')
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comp_off_requests')
    worked_date = models.DateField()
    reason = models.TextField()
    hours_worked = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        validators=[MinValueValidator(Decimal('0.5')), MaxValueValidator(Decimal('24.0'))]
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(User, related_name='comp_off_approvals', on_delete=models.SET_NULL, null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)  # Soft delete
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Custom manager
    objects = CompOffRequestManager()

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=Q(hours_worked__gte=Decimal('0.5'), hours_worked__lte=Decimal('24.0')),
                name='valid_comp_off_hours'
            ),
            # Note: Dynamic date constraints should be handled in clean() method
            # models.CheckConstraint with timezone.now() is not supported
        ]
        indexes = [
            models.Index(fields=['user', 'status', 'is_deleted']),
            models.Index(fields=['worked_date', 'status']),
            models.Index(fields=['approver', 'status']),
        ]

    def clean(self):
        """Validate comp-off request"""
        from django.utils import timezone

        errors = {}

        # Validate worked date is not in future
        if self.worked_date and self.worked_date > timezone.localdate():
            errors['worked_date'] = "Worked date cannot be in the future"

        # Validate worked date is not too old (e.g., more than 30 days)
        if self.worked_date and (timezone.localdate() - self.worked_date).days > 30:
            errors['worked_date'] = "Comp-off requests must be made within 30 days of working"

        # Validate hours worked
        if self.hours_worked and (self.hours_worked < Decimal('0.5') or self.hours_worked > Decimal('24.0')):
            errors['hours_worked'] = "Hours worked must be between 0.5 and 24.0"

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        previous_status = None

        # Get previous status for comparison
        if not is_new:
            try:
                previous = CompOffRequest.objects.get(id=self.id)
                previous_status = previous.status
            except CompOffRequest.DoesNotExist:
                pass

        # Validate before saving
        self.full_clean()

        try:
            with transaction.atomic():
                super().save(*args, **kwargs)

                # Handle status changes
                if self.status == 'Approved' and previous_status != 'Approved':
                    logger.info(f"Processing approved comp-off request for {self.user.username}")
                    self._update_comp_off_balance_service()
                elif previous_status == 'Approved' and self.status != 'Approved':
                    logger.info(f"Reverting comp-off balance for {self.user.username}")
                    self._revert_comp_off_balance_service()

        except Exception as e:
            logger.error(f"Error saving comp-off request: {str(e)}")
            raise ValidationError(f"Error processing comp-off request: {str(e)}")

    def _update_comp_off_balance_service(self):
        """Service method to update user's comp-off balance when request is approved"""
        try:
            comp_off_type = LeaveType.objects.get(name='Comp Off', is_deleted=False)
            year = self.worked_date.year

            # Calculate days earned - convert hours to days (8 hours = 1 day)
            days_earned = self.hours_worked / Decimal('8.0')

            with transaction.atomic():
                balance, created = UserLeaveBalance.objects.for_user_and_year(self.user, year).get_or_create(
                    leave_type=comp_off_type,
                    defaults={
                        'allocated': Decimal('0'),
                        'used': Decimal('0'),
                        'carried_forward': Decimal('0'),
                        'additional': Decimal('0')
                    }
                )

                balance.additional += days_earned
                balance.save()

                logger.info(f"Added {days_earned} comp-off days to {self.user.username}'s balance")

                # Update attendance record
                self._update_attendance_for_comp_off()

        except LeaveType.DoesNotExist:
            logger.error("Comp Off leave type not found")
            raise ValidationError("Comp Off leave type not configured")
        except Exception as e:
            logger.error(f"Error updating comp-off balance: {str(e)}")
            raise

    def _revert_comp_off_balance_service(self):
        """Service method to revert comp-off balance when request is rejected/cancelled"""
        try:
            comp_off_type = LeaveType.objects.get(name='Comp Off', is_deleted=False)
            year = self.worked_date.year
            days_to_revert = self.hours_worked / Decimal('8.0')

            with transaction.atomic():
                try:
                    balance = UserLeaveBalance.objects.for_user_and_year(self.user, year).select_for_update().get(
                        leave_type=comp_off_type
                    )
                    balance.additional = max(Decimal('0'), balance.additional - days_to_revert)
                    balance.save()
                    logger.info(f"Reverted {days_to_revert} comp-off days from {self.user.username}'s balance")
                except UserLeaveBalance.DoesNotExist:
                    logger.warning("No comp-off balance found to revert")

        except Exception as e:
            logger.error(f"Error reverting comp-off balance: {str(e)}")

    def _update_attendance_for_comp_off(self):
        """Update attendance record for comp-off worked day"""
        try:
            from django.apps import apps
            Attendance = apps.get_model('trueAlign', 'Attendance')

            defaults = {
                'status': 'Comp Off',
                'is_weekend': self.worked_date.weekday() >= 5,
                'total_hours': self.hours_worked,
                'overtime_hours': self.hours_worked,
                'is_overtime_approved': True,
                'remarks': f"Comp-off approved for {self.hours_worked} hours - Request ID: {self.id}"
            }

            Attendance.objects.update_or_create(
                user=self.user,
                date=self.worked_date,
                defaults=defaults
            )

        except Exception as e:
            logger.error(f"Error updating attendance for comp-off: {str(e)}")

    def __str__(self):
        return f"{self.user.username} - Comp Off ({self.worked_date}) - {self.status}"


# Post-save signals for leave processing
@receiver(post_save, sender=LeaveRequest)
def handle_leave_request_status_change(sender, instance, created, **kwargs):
    """
    Handle leave request status changes via signals for better separation of concerns
    """
    if not created:  # Only for updates, not new records
        try:
            # Get previous state from database
            previous = LeaveRequest.objects.get(id=instance.id)

            # Log status changes for audit
            if hasattr(instance, '_previous_status') and instance._previous_status != instance.status:
                logger.info(f"Leave request {instance.id} status changed from {instance._previous_status} to {instance.status}")

                # Send notifications based on status change
                if instance.status == 'Approved':
                    logger.info(f"Leave request {instance.id} approved - sending notification")
                    # Future: Add notification service call here
                elif instance.status == 'Rejected':
                    logger.info(f"Leave request {instance.id} rejected - sending notification")
                    # Future: Add notification service call here

        except LeaveRequest.DoesNotExist:
            pass
        except Exception as e:
            logger.error(f"Error in leave request post_save signal: {str(e)}")


@receiver(post_save, sender=CompOffRequest)
def handle_comp_off_status_change(sender, instance, created, **kwargs):
    """
    Handle comp-off request status changes via signals
    """
    if not created:  # Only for updates
        try:
            if hasattr(instance, '_previous_status') and instance._previous_status != instance.status:
                logger.info(f"Comp-off request {instance.id} status changed from {instance._previous_status} to {instance.status}")

                # Send notifications
                if instance.status == 'Approved':
                    logger.info(f"Comp-off request {instance.id} approved - sending notification")
                    # Future: Add notification service call here
                elif instance.status == 'Rejected':
                    logger.info(f"Comp-off request {instance.id} rejected - sending notification")
                    # Future: Add notification service call here

        except Exception as e:
            logger.error(f"Error in comp-off post_save signal: {str(e)}")


class LeaveRequestHistory(models.Model):
    """
    Audit trail for leave request changes
    """
    ACTION_CHOICES = [
        ('created', 'Created'),
        ('updated', 'Updated'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled'),
        ('balance_updated', 'Balance Updated'),
        ('attendance_updated', 'Attendance Updated'),
    ]

    leave_request = models.ForeignKey(LeaveRequest, on_delete=models.CASCADE, related_name='history')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    old_values = models.JSONField(null=True, blank=True, help_text="Previous values before change")
    new_values = models.JSONField(null=True, blank=True, help_text="New values after change")
    reason = models.TextField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['leave_request', 'action']),
            models.Index(fields=['performed_by', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"{self.leave_request} - {self.action} at {self.timestamp}"

    @classmethod
    def log_action(cls, leave_request, action, performed_by=None, old_values=None, new_values=None, reason=None, ip_address=None, user_agent=None):
        """Helper method to log actions"""
        try:
            return cls.objects.create(
                leave_request=leave_request,
                action=action,
                performed_by=performed_by,
                old_values=old_values,
                new_values=new_values,
                reason=reason,
                ip_address=ip_address,
                user_agent=user_agent
            )
        except Exception as e:
            logger.error(f"Failed to log leave request history: {str(e)}")


'''---------- ATTENDANCE AREA ----------'''
from datetime import time, timedelta
from decimal import Decimal
from django.db import models




# Configure logger
logger = logging.getLogger(__name__)

# Configure logger

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import datetime, timedelta, time, date
from decimal import Decimal
import pytz
import logging
from django.db.models import Q
from trueAlign.attendance.managers import AttendanceManager
from django.core.validators import MinValueValidator, MaxValueValidator


logger = logging.getLogger(__name__)

class Attendance(models.Model):
    """
    Comprehensive Attendance model with better organization and separation of concerns
    """
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Present & Late', 'Present & Late'),
        ('Absent', 'Absent'),
        ('Late', 'Late'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
        ('Weekend', 'Weekend'),
        ('Holiday', 'Holiday'),
        ('Comp Off', 'Comp Off'),
        ('Not Marked', 'Not Marked'),
        ('Yet to Clock In', 'Yet to Clock In'),
        ('Half Day', 'Half Day')
    ]

    LOCATION_CHOICES = [
        ('Office', 'Office'),
        ('Home', 'Home'),
        ('Remote', 'Remote'),
        ('Client Site', 'Client Site'),
        ('Other', 'Other')
    ]

    REGULARIZATION_STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected')
    ]

    # Basic fields
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attendance_records')
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Not Marked')

    # Time tracking fields
    clock_in_time = models.DateTimeField(null=True, blank=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)
    total_hours = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    expected_hours = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))]
    )

    # Leave and shift information
    leave_type = models.CharField(max_length=50, null=True, blank=True)
    shift = models.ForeignKey(ShiftMaster, on_delete=models.SET_NULL, null=True, blank=True)

    # Location and device tracking
    location = models.CharField(max_length=50, choices=LOCATION_CHOICES, default='Office')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.JSONField(null=True, blank=True)

    # Break and time calculations
    breaks = models.JSONField(default=list, blank=True)
    late_minutes = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)]
    )
    early_departure_minutes = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)]
    )
    overtime_hours = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        validators=[MinValueValidator(Decimal('0.00'))]
    )

    # Boolean flags
    is_weekend = models.BooleanField(default=False)
    is_holiday = models.BooleanField(default=False)
    is_half_day = models.BooleanField(default=False)
    left_early = models.BooleanField(default=False)
    is_overtime_approved = models.BooleanField(default=False)

    # Holiday information
    holiday_name = models.CharField(max_length=100, blank=True, null=True)

    # Session tracking
    first_session = models.ForeignKey(
        UserSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='first_session_attendance'
    )
    last_session = models.ForeignKey(
        UserSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='last_session_attendance'
    )
    total_sessions = models.IntegerField(default=0)
    idle_time = models.DurationField(default=timedelta(0))

    # Regularization fields
    regularization_reason = models.TextField(null=True, blank=True)
    regularization_status = models.CharField(
        max_length=20,
        choices=REGULARIZATION_STATUS_CHOICES,
        null=True,
        blank=True
    )
    requested_status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        null=True,
        blank=True,
        help_text="Status requested by employee during regularization"
    )
    regularization_attempts = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    last_regularization_date = models.DateTimeField(null=True, blank=True)

    # Original values for audit trail
    original_clock_in_time = models.DateTimeField(null=True, blank=True)
    original_clock_out_time = models.DateTimeField(null=True, blank=True)
    original_status = models.CharField(max_length=20, null=True, blank=True)

    # Notification flags
    is_employee_notified = models.BooleanField(default=False)
    is_hr_notified = models.BooleanField(default=False)

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    modified_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='attendance_modifications'
    )
    remarks = models.TextField(null=True, blank=True)

    # Use custom manager
    objects = AttendanceManager()

    class Meta:
        unique_together = ('user', 'date')
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date', 'status']),
            models.Index(fields=['regularization_status']),
            models.Index(fields=['clock_in_time']),
            models.Index(fields=['clock_out_time']),
            models.Index(fields=['is_weekend', 'is_holiday']),
        ]
        ordering = ['-date', 'user__username']

    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.status}"

    def clean(self):
        """Validate attendance data"""
        errors = {}

        # Validate clock times
        if self.clock_in_time and self.clock_out_time:
            if self.clock_out_time <= self.clock_in_time:
                errors['clock_out_time'] = "Clock out time must be after clock in time"

        # Validate dates (allow today, prevent future dates)
        if self.date and self.date > timezone.now().date():
            # Allow if it's today but in different timezone
            ist_now = timezone.now().astimezone(pytz.timezone('Asia/Kolkata'))
            if self.date > ist_now.date():
                errors['date'] = "Cannot create attendance for future dates"

        # Validate total hours
        if self.total_hours and self.total_hours > 24:
            errors['total_hours'] = "Total hours cannot exceed 24 hours"

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        """
        Simplified save method - main business logic moved to separate methods
        """
        # Store original values for audit trail
        if self.pk:
            try:
                original = Attendance.objects.get(pk=self.pk)
                if not self.original_status:
                    self.original_status = original.status
                if not self.original_clock_in_time:
                    self.original_clock_in_time = original.clock_in_time
                if not self.original_clock_out_time:
                    self.original_clock_out_time = original.clock_out_time
            except Attendance.DoesNotExist:
                pass

        # Run validations
        self.full_clean()

        # Initialize data for new records
        if not self.pk:
            self._initialize_attendance_defaults()

        # Calculate time-related fields
        self._calculate_time_fields()

        # Update status based on calculated data
        self._update_status_logic()

        super().save(*args, **kwargs)

    def _initialize_attendance_defaults(self):
        """Initialize default values for new attendance records"""
        try:
            # Set shift information
            if not self.shift:
                self.shift = ShiftAssignment.get_user_current_shift(self.user, self.date)

            if self.shift:
                self.expected_hours = Decimal(str(self.shift.shift_duration))

            # Check for leave status
            if self._is_user_on_leave():
                self._set_leave_status()
                return

            # Check for holiday
            if self._is_date_holiday():
                self._set_holiday_status()
                return

            # Check for weekend
            if self._is_date_weekend():
                self._set_weekend_status()
                return

        except Exception as e:
            logger.error(f"Error initializing attendance defaults for {self.user.username}: {e}")

    def _calculate_time_fields(self):
        """Calculate time-related fields like total hours and overtime"""
        if self.clock_in_time and self.clock_out_time and self.clock_out_time > self.clock_in_time:
            # Calculate total duration
            duration = self.clock_out_time - self.clock_in_time
            hours = Decimal(str(duration.total_seconds() / 3600))

            # Subtract break time if applicable
            if self.shift and self.shift.break_duration:
                break_hours = Decimal(str(self.shift.break_duration.total_seconds() / 3600))
                hours = max(Decimal('0'), hours - break_hours)

            # Subtract idle time
            if self.idle_time:
                idle_hours = Decimal(str(self.idle_time.total_seconds() / 3600))
                hours = max(Decimal('0'), hours - idle_hours)

            self.total_hours = round(hours, 2)

            # Calculate overtime
            if self.shift and self.total_hours > Decimal(str(self.shift.shift_duration)):
                self.overtime_hours = self.total_hours - Decimal(str(self.shift.shift_duration))

            # Calculate late minutes
            if self.shift and self.clock_in_time:
                self._calculate_late_minutes()

            # Calculate early departure
            if self.shift and self.clock_out_time:
                self._calculate_early_departure()

    # In ardurPeopleSoft/trueAlign/models.py - Replace the _update_status_logic method

    def _update_status_logic(self):
        """Update attendance status based on calculated data and business rules"""
        # Skip status update for certain fixed statuses
        if self.status in ['On Leave', 'Holiday', 'Weekend']:
            return

        if self.clock_in_time:
            self._handle_clocked_in_status()
        else:
            self._handle_no_clock_in_status()

    def _handle_clocked_in_status(self):
        """Handle status logic when user has clocked in"""
        self._ensure_shift_assignment()

        if self._should_mark_late():
            self.status = 'Present & Late'
        elif self._has_minimum_working_hours():
            self.status = 'Present & Late' if self._should_mark_late() else 'Present'
        else:
            self.status = 'Present'

    def _handle_no_clock_in_status(self):
        """Handle status logic when user has not clocked in"""
        if self.status == 'Yet to Clock In' and self._is_shift_ended():
            self._mark_as_absent("Auto-marked as absent (no activity, shift ended)")
        elif self.status == 'Not Marked' and self._is_past_date():
            self._mark_as_absent("Auto-marked as absent (no activity recorded)")

    def _ensure_shift_assignment(self):
        """Ensure shift is assigned if missing"""
        if not self.shift:
            try:
                self.shift = ShiftAssignment.get_user_current_shift(self.user, self.date)
            except Exception:
                pass

    def _should_mark_late(self):
        """Check if user should be marked as late"""
        return self.shift and self.late_minutes > 0

    def _has_minimum_working_hours(self):
        """Check if user has minimum working hours"""
        return self.total_hours and self.total_hours >= Decimal('0.5')

    def _is_past_date(self):
        """Check if attendance date is in the past"""
        IST = pytz.timezone('Asia/Kolkata')
        today = timezone.now().astimezone(IST).date()
        return self.date < today

    def _mark_as_absent(self, reason):
        """Mark attendance as absent with reason"""
        self.status = 'Absent'
        if not self.regularization_reason:
            self.regularization_reason = reason



    def _calculate_late_minutes(self):
        """Calculate how many minutes late the user is"""
        if not self.clock_in_time or not self.shift:
            return

        clock_in_time = self.clock_in_time.time()
        shift_start = self.shift.start_time

        # Get grace period
        grace_minutes = 10  # default
        if self.shift.grace_period:
            grace_minutes = int(self.shift.grace_period.total_seconds() / 60)

        shift_start_minutes = shift_start.hour * 60 + shift_start.minute
        grace_end_minutes = shift_start_minutes + grace_minutes
        clock_in_minutes = clock_in_time.hour * 60 + clock_in_time.minute

        if clock_in_minutes > grace_end_minutes:
            self.late_minutes = clock_in_minutes - shift_start_minutes

    # In ardurPeopleSoft/trueAlign/models.py - Replace the _calculate_early_departure method

    def _calculate_early_departure(self):
        """Calculate early departure minutes"""
        if not self._can_calculate_early_departure():
            return

        clock_out_minutes = self._get_clock_out_minutes()
        shift_end_minutes = self._get_shift_end_minutes()

        # Handle night shifts
        if self._is_night_shift():
            clock_out_minutes = self._adjust_for_night_shift(clock_out_minutes, shift_end_minutes)

        if clock_out_minutes < shift_end_minutes:
            self._set_early_departure(shift_end_minutes - clock_out_minutes)

    def _can_calculate_early_departure(self):
        """Check if early departure can be calculated"""
        return self.clock_out_time and self.shift

    def _get_clock_out_minutes(self):
        """Get clock out time in minutes"""
        return self.clock_out_time.time().hour * 60 + self.clock_out_time.time().minute

    def _get_shift_end_minutes(self):
        """Get shift end time in minutes"""
        return self.shift.end_time.hour * 60 + self.shift.end_time.minute

    def _is_night_shift(self):
        """Check if this is a night shift"""
        return (hasattr(self.shift, 'is_night_shift') and self.shift.is_night_shift()) or \
               (hasattr(self.shift, 'crosses_midnight') and self.shift.crosses_midnight)

    def _adjust_for_night_shift(self, clock_out_minutes, shift_end_minutes):
        """Adjust clock out minutes for night shift"""
        if clock_out_minutes > shift_end_minutes:
            return clock_out_minutes + 24 * 60
        return clock_out_minutes

    def _set_early_departure(self, minutes):
        """Set early departure values"""
        self.left_early = True
        self.early_departure_minutes = minutes


    def _is_user_on_leave(self):
        """Check if user is on approved leave for this date"""
        return LeaveRequest.objects.filter(
            user=self.user,
            status='Approved',
            start_date__lte=self.date,
            end_date__gte=self.date
        ).exists()

    def _is_date_holiday(self):
        """Check if date is a holiday"""
        return Holiday.is_holiday(self.date)

    def _is_date_weekend(self):
        """Check if date is weekend based on shift or default logic"""
        weekday = self.date.weekday()

        if self.shift:
            working_days = self.shift.get_working_days()
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            current_day = day_names[weekday]
            return current_day not in working_days

        # Default weekend logic (Saturday, Sunday)
        return weekday >= 5

    def _set_leave_status(self):
        """Set leave status and related information"""
        leave_request = LeaveRequest.objects.filter(
            user=self.user,
            status='Approved',
            start_date__lte=self.date,
            end_date__gte=self.date
        ).select_related('leave_type').first()

        if leave_request:
            self.status = 'On Leave'
            self.leave_type = leave_request.leave_type.name
            if not self.regularization_reason:
                self.regularization_reason = f"On {leave_request.leave_type.name} leave"

    def _set_holiday_status(self):
        """Set holiday status and related information"""
        holiday = Holiday.get_holiday(self.date)
        if holiday:
            self.status = 'Holiday'
            self.is_holiday = True
            self.holiday_name = holiday.name
            if not self.regularization_reason:
                self.regularization_reason = f"Holiday: {holiday.name}"

    def _set_weekend_status(self):
        """Set weekend status"""
        self.status = 'Weekend'
        self.is_weekend = True
        if not self.regularization_reason:
            self.regularization_reason = "Weekend"

    def _is_shift_ended(self):
        """Check if the shift has ended for today"""
        if not self.shift:
            return False

        IST = pytz.timezone('Asia/Kolkata')
        current_time = timezone.now().astimezone(IST).time()
        today = timezone.now().astimezone(IST).date()

        # Only check for today's attendance
        if self.date != today:
            return True

        return self._check_shift_end_time(current_time, self.shift.start_time, self.shift.end_time)

    @staticmethod
    def _check_shift_end_time(current_time, shift_start, shift_end):
        """Utility method to check if shift has ended, handling night shifts"""
        current_minutes = current_time.hour * 60 + current_time.minute
        start_minutes = shift_start.hour * 60 + shift_start.minute
        end_minutes = shift_end.hour * 60 + shift_end.minute

        # Handle night shifts (crosses midnight)
        if end_minutes < start_minutes:
            end_minutes += 24 * 60
            if current_minutes < start_minutes:
                current_minutes += 24 * 60

        return current_minutes > end_minutes

    def get_working_hours(self):
        """Get actual working hours (total hours minus breaks and idle time)"""
        if not self.total_hours:
            return Decimal('0.00')

        working_hours = self.total_hours

        # Subtract official break time
        if self.shift and self.shift.break_duration:
            break_hours = Decimal(str(self.shift.break_duration.total_seconds() / 3600))
            working_hours = max(Decimal('0'), working_hours - break_hours)

        return working_hours

    def is_eligible_for_overtime(self):
        """Check if attendance is eligible for overtime pay"""
        return (
            self.overtime_hours > 0 and
            self.status in ['Present', 'Present & Late'] and
            not self.is_weekend and
            not self.is_holiday
        )

    def get_attendance_efficiency(self):
        """Calculate attendance efficiency as a percentage"""
        if not self.expected_hours or self.expected_hours == 0:
            return 0

        actual_hours = self.get_working_hours()
        return min(100, (actual_hours / self.expected_hours) * 100)

    @classmethod
    def create_attendance_record(cls, user, clock_in_time=None, location='Office', **kwargs):
        """
        Class method to create attendance record with proper initialization
        """
        IST = pytz.timezone('Asia/Kolkata')

        if not clock_in_time:
            clock_in_time = timezone.now().astimezone(IST)
        elif timezone.is_naive(clock_in_time):
            clock_in_time = timezone.make_aware(clock_in_time, IST)

        attendance_date = clock_in_time.date()

        # Get or create attendance record
        attendance, created = cls.objects.get_or_create_today_attendance(user, attendance_date)

        # Update with clock-in information if this is first clock-in
        if created or not attendance.clock_in_time:
            attendance.clock_in_time = clock_in_time
            attendance.location = location

            # Set additional fields from kwargs
            for key, value in kwargs.items():
                if hasattr(attendance, key):
                    setattr(attendance, key, value)

            attendance.save()
            logger.info(f"Created attendance record for {user.username} at {clock_in_time}")

        return attendance

    @classmethod
    def record_clock_out(cls, user, clock_out_time=None, location=None, **kwargs):
        """
        Class method to record clock-out time for attendance
        """
        IST = pytz.timezone('Asia/Kolkata')

        if not clock_out_time:
            clock_out_time = timezone.now().astimezone(IST)
        elif timezone.is_naive(clock_out_time):
            clock_out_time = timezone.make_aware(clock_out_time, IST)

        attendance_date = clock_out_time.date()

        try:
            attendance = cls.objects.get(user=user, date=attendance_date)

            # Only update if this is a later clock-out time
            if not attendance.clock_out_time or clock_out_time > attendance.clock_out_time:
                attendance.clock_out_time = clock_out_time

                if location:
                    attendance.location = location

                # Update additional fields from kwargs
                for key, value in kwargs.items():
                    if hasattr(attendance, key):
                        setattr(attendance, key, value)

                attendance.save()
                logger.info(f"Updated clock-out time for {user.username} to {clock_out_time}")

            return attendance

        except cls.DoesNotExist:
            # Create attendance record if it doesn't exist
            logger.warning(f"No attendance record found for {user.username} on {attendance_date}, creating new one")
            return cls.create_attendance_record(
                user=user,
                clock_in_time=clock_out_time - timedelta(minutes=1),  # Assume 1 minute session
                location=location or 'Office',
                **kwargs
            )

    @classmethod
    def update_session_data(cls, user, session, date=None):
        """
        Update attendance record with session information
        """
        from django.db import transaction

        if not date:
            date = session.login_time.date()

        try:
            # Skip if we're already in a transaction to avoid nested transaction issues
            if transaction.get_connection().in_atomic_block:
                # Simple update without atomic block
                attendance = cls.objects.get(user=user, date=date)

                # Update session information
                if not attendance.first_session or session.login_time < attendance.first_session.login_time:
                    attendance.first_session = session

                if not attendance.last_session or session.login_time > attendance.last_session.login_time:
                    attendance.last_session = session

                # Update session count
                attendance.total_sessions = UserSession.objects.filter(
                    user=user,
                    login_time__date=date
                ).count()

                # Update clock times based on session
                if not attendance.clock_in_time or session.login_time < attendance.clock_in_time:
                    attendance.clock_in_time = session.login_time

                if session.logout_time:
                    if not attendance.clock_out_time or session.logout_time > attendance.clock_out_time:
                        attendance.clock_out_time = session.logout_time

                attendance.save()
                logger.info(f"Updated session data for {user.username} on {date}")
            else:
                # Use atomic transaction if not already in one
                with transaction.atomic():
                    try:
                        # Use select_for_update to prevent deadlocks
                        attendance = cls.objects.select_for_update().get(user=user, date=date)

                        # Validate session exists and is not None
                        if not session or not hasattr(session, 'login_time'):
                            logger.warning(f"Invalid session provided for {user.username} on {date}")
                            return

                        # Update session information with proper existence checks
                        update_first_session = False
                        update_last_session = False

                        # Check if we need to update first_session
                        if not attendance.first_session:
                            update_first_session = True
                        else:
                            try:
                                # Verify first_session still exists
                                if attendance.first_session and hasattr(attendance.first_session, 'login_time'):
                                    if session.login_time < attendance.first_session.login_time:
                                        update_first_session = True
                                else:
                                    update_first_session = True
                            except (AttributeError, UserSession.DoesNotExist):
                                update_first_session = True

                        # Check if we need to update last_session
                        if not attendance.last_session:
                            update_last_session = True
                        else:
                            try:
                                # Verify last_session still exists
                                if attendance.last_session and hasattr(attendance.last_session, 'login_time'):
                                    if session.login_time > attendance.last_session.login_time:
                                        update_last_session = True
                                else:
                                    update_last_session = True
                            except (AttributeError, UserSession.DoesNotExist):
                                update_last_session = True

                        # Apply updates
                        if update_first_session:
                            attendance.first_session = session
                        if update_last_session:
                            attendance.last_session = session

                        # Update session count
                        attendance.total_sessions = UserSession.objects.filter(
                            user=user,
                            login_time__date=date
                        ).count()

                        # Update clock times based on session
                        if not attendance.clock_in_time or session.login_time < attendance.clock_in_time:
                            attendance.clock_in_time = session.login_time

                        if session.logout_time:
                            if not attendance.clock_out_time or session.logout_time > attendance.clock_out_time:
                                attendance.clock_out_time = session.logout_time

                        attendance.save()
                        logger.info(f"Updated session data for {user.username} on {date}")

                    except Exception as e:
                        logger.error(f"Error in atomic transaction for {user.username}: {e}")
                        raise

        except cls.DoesNotExist:
            logger.warning(f"No attendance record found for {user.username} on {date}")
        except Exception as e:
            logger.error(f"Error updating session data for {user.username}: {e}")

    def request_regularization(self, requested_status, reason, requested_by=None):
        """
        Submit a regularization request for this attendance record
        """
        if self.regularization_status == 'Pending':
            raise ValidationError("A regularization request is already pending for this attendance")

        if self.regularization_attempts >= 5:
            raise ValidationError("Maximum regularization attempts exceeded")

        # Store original values if not already stored
        if not self.original_status:
            self.original_status = self.status
        if not self.original_clock_in_time:
            self.original_clock_in_time = self.clock_in_time
        if not self.original_clock_out_time:
            self.original_clock_out_time = self.clock_out_time

        self.requested_status = requested_status
        self.regularization_reason = reason
        self.regularization_status = 'Pending'
        self.regularization_attempts += 1
        self.last_regularization_date = timezone.now()

        if requested_by:
            self.modified_by = requested_by

        self.save()
        logger.info(f"Regularization requested for {self.user.username} on {self.date}")

    def approve_regularization(self, approved_by, comments=None):
        """
        Approve the regularization request
        """
        if self.regularization_status != 'Pending':
            raise ValidationError("No pending regularization request to approve")

        # Apply the requested changes
        if self.requested_status:
            self.status = self.requested_status

        self.regularization_status = 'Approved'
        self.modified_by = approved_by

        if comments:
            self.remarks = comments

        self.save()
        logger.info(f"Regularization approved for {self.user.username} on {self.date}")

    def reject_regularization(self, rejected_by, comments=None):
        """
        Reject the regularization request
        """
        if self.regularization_status != 'Pending':
            raise ValidationError("No pending regularization request to reject")

        self.regularization_status = 'Rejected'
        self.modified_by = rejected_by

        if comments:
            self.remarks = comments

        # Reset to original values
        if self.original_status:
            self.status = self.original_status
        if self.original_clock_in_time:
            self.clock_in_time = self.original_clock_in_time
        if self.original_clock_out_time:
            self.clock_out_time = self.original_clock_out_time

        self.save()
        logger.info(f"Regularization rejected for {self.user.username} on {self.date}")



    def get_formatted_duration(self):
        """
        Returns duration as formatted string 'Xh Ym', using Asia/Kolkata timezone.
        Handles None, negative, or invalid durations gracefully.
        """
        if not self.clock_in_time or not self.clock_out_time:
            return "0h 0m"

        # Convert to Asia/Kolkata time
        india_tz = pytz.timezone("Asia/Kolkata")
        clock_in = self.clock_in_time.astimezone(india_tz)
        clock_out = self.clock_out_time.astimezone(india_tz)

        # Ensure no negative durations
        if clock_out < clock_in:
            return "0h 0m"

        duration_seconds = (clock_out - clock_in).total_seconds()
        total_hours = duration_seconds / 3600.0

        hours = int(floor(total_hours))
        minutes = int(round((total_hours - hours) * 60))

        if minutes == 60:
            hours += 1
            minutes = 0

        return f"{hours}h {minutes}m"

    def get_status_color(self):
        """
        Get color code for status display
        """
        status_colors = {
            'Present': 'success',
            'Present & Late': 'warning',
            'Absent': 'danger',
            'Late': 'warning',
            'On Leave': 'info',
            'Work From Home': 'primary',
            'Weekend': 'secondary',
            'Holiday': 'info',
            'Comp Off': 'info',
            'Not Marked': 'light',
            'Yet to Clock In': 'warning',
            'Half Day': 'warning'
        }
        return status_colors.get(self.status, 'light')

    def can_request_regularization(self):
        """
        Check if user can request regularization for this attendance
        """
        # Can't regularize if already approved or if max attempts reached
        if self.regularization_status == 'Approved':
            return False

        if self.regularization_attempts >= 5:
            return False

        # Can't regularize weekend or holiday unless it was worked
        if self.status in ['Weekend', 'Holiday'] and not self.clock_in_time:
            return False

        # Can regularize within 7 days of the attendance date
        days_diff = (timezone.now().date() - self.date).days
        return days_diff <= 7
