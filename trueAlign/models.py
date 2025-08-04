from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.conf import settings
from datetime import time, timedelta
import logging
from django.db.models import JSONField
import uuid
import json
import math
import ipaddress
import geoip2.database
import os

# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

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
import json
import uuid
import math
from datetime import timedelta
import ipaddress
import geoip2.database
import os

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
    def get_or_create_session(cls, user, tab_id=None, parent_session_id=None, client_data=None, session_key=None, ip_address=None, user_agent=None, browser_fingerprint=None, device_type=None, screen_resolution=None, timezone_offset=None, language=None, url=None, title=None, referrer=None):
        """
        Get an existing session or create a new one using the enhanced session manager
        """
        from trueAlign.core.session_manager import get_session_manager
        from trueAlign.core.enhanced_logger import get_session_logger
        
        start_time = time.time()
        session_manager = get_session_manager()
        session_logger = get_session_logger()
        
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
            duration_ms = (time.time() - start_time) * 1000
            session_logger.log_session_creation(
                user, session.id, tab_id, duration_ms, created=created
            )
            
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

        # 3. Try to find existing session by session_fingerprint only (same browser/device)
        if session_fingerprint:
            recent_time = timezone.now() - timedelta(minutes=30)  # Look for sessions in last 30 minutes
            session = cls.objects.filter(
                user=user,
                session_fingerprint=session_fingerprint,
                is_active=True,
                last_activity__gte=recent_time
            ).first()
            if session:
                logger.info(f"Found existing session by fingerprint: {session.id}")
                session.last_activity = timezone.now()
                session.save(update_fields=['last_activity'])
                return session, False

        # Handle standalone parameters if client_data is not provided
        if client_data is None:
            client_data = {}

        # Add standalone parameters to client_data if they're provided
        if ip_address is not None:
            client_data['ip_address'] = ip_address
        if user_agent is not None:
            client_data['user_agent'] = user_agent
        if browser_fingerprint is not None:
            client_data['browser_fingerprint'] = browser_fingerprint
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

        # Generate parent_session_id if not provided
        if not parent_session_id:
            parent_session_id = uuid.uuid4()
            logger.info(f"Generated new parent_session_id: {parent_session_id}")

        # Create a new session with detailed client data if available
        session_data = {
            'user': user,
            'tab_id': tab_id,
            'parent_session_id': parent_session_id,
            'session_key': session_key or cls.generate_session_key(),
            'is_primary_tab': True,  # Mark as primary since it's a new parent session
            'session_fingerprint': session_fingerprint,
        }

        if client_data:
            session_data.update({
                'ip_address': client_data.get('ip_address'),
                'user_agent': client_data.get('user_agent'),
                'browser_fingerprint': client_data.get('browser_fingerprint'),
                'device_type': client_data.get('device_type'),
                'screen_resolution': client_data.get('screen_resolution'),
                'timezone_offset': client_data.get('timezone_offset'),
                'language': client_data.get('language'),
                'url': client_data.get('url'),
                'title': client_data.get('title'),
                'referrer': client_data.get('referrer')
            })

        session = cls(**session_data)

        # Process location data if available
        if client_data and client_data.get('ip_address'):
            try:
                session.update_location_from_ip(client_data.get('ip_address'))
            except Exception as e:
                logger.warning(f"Failed to update location from IP: {e}")

        # Process geolocation data if available
        if client_data:
            location_data = client_data.get('location_data')
            if location_data and isinstance(location_data, dict):
                session.location_latitude = location_data.get('latitude')
                session.location_longitude = location_data.get('longitude')
                session.location_accuracy = location_data.get('accuracy')

        session.save()
        logger.info(f"Created new session {session.id} with parent_session_id: {session.parent_session_id}")
        return session, True

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
        from trueAlign.core.optimized_batch_writer import get_batch_writer
        from trueAlign.core.location_sync import get_location_synchronizer
        from trueAlign.core.enhanced_logger import get_session_logger
        
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