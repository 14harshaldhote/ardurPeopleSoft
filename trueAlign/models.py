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
import logging
from decimal import Decimal
from django.db import models
import datetime
# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')
from decimal import Decimal




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
    logout_time = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
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

    # Client information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    browser_fingerprint = models.TextField(null=True, blank=True)
    csrf_token = models.CharField(max_length=64, null=True, blank=True)
    csrf_token_created = models.DateTimeField(null=True, blank=True)
    device_type = models.CharField(max_length=20, null=True, blank=True)
    screen_resolution = models.CharField(max_length=20, null=True, blank=True)
    timezone_offset = models.IntegerField(null=True, blank=True)
    language = models.CharField(max_length=10, null=True, blank=True)
    battery_level = models.FloatField(null=True, blank=True)
    connection_type = models.CharField(max_length=20, null=True, blank=True)

    # Location information
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

    class Meta:
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

    @classmethod
    def get_or_create_session(cls, user, tab_id=None, parent_session_id=None, client_data=None, session_key=None, ip_address=None, user_agent=None, browser_fingerprint=None, device_type=None, screen_resolution=None, timezone_offset=None, language=None, url=None, title=None, referrer=None):
        """
        Get an existing session or create a new one based on tab_id and parent_session_id
        """
        # Try to find an existing active session by tab_id
        if tab_id:
            try:
                session = cls.objects.get(user=user, tab_id=tab_id, is_active=True)
                return session, False
            except cls.DoesNotExist:
                pass

        # Try to find an existing active session by parent_session_id
        if parent_session_id:
            try:
                session = cls.objects.get(user=user, parent_session_id=parent_session_id, is_active=True)
                return session, False
            except cls.DoesNotExist:
                pass

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

        # Create a new session with detailed client data if available
        if client_data:
            session = cls(
                user=user,
                tab_id=tab_id,
                parent_session_id=parent_session_id,
                session_key=session_key or cls.generate_session_key(),
                ip_address=client_data.get('ip_address'),
                user_agent=client_data.get('user_agent'),
                browser_fingerprint=client_data.get('browser_fingerprint'),
                device_type=client_data.get('device_type'),
                screen_resolution=client_data.get('screen_resolution'),
                timezone_offset=client_data.get('timezone_offset'),
                language=client_data.get('language'),
                url=client_data.get('url'),
                title=client_data.get('title'),
                referrer=client_data.get('referrer')
            )

            # Process location data if available
            if client_data.get('ip_address'):
                session.update_location_from_ip(client_data.get('ip_address'))

            # Process geolocation data if available
            location_data = client_data.get('location_data')
            if location_data and isinstance(location_data, dict):
                session.location_latitude = location_data.get('latitude')
                session.location_longitude = location_data.get('longitude')
                session.location_accuracy = location_data.get('accuracy')

                # Determine location type (home/office) based on time and previous sessions
                if hasattr(session, 'determine_location_type'):
                    session.determine_location_type()
        else:
            # Create a basic session if no client data is available
            session = cls(user=user, tab_id=tab_id, parent_session_id=parent_session_id, session_key=session_key or cls.generate_session_key())

        session.save()
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
            if getattr(self, field) is None:
                if field in ['page_views', 'clicks', 'scrolls', 'keyboard_events',
                            'tab_visibility_log', 'idle_state_changes', 'visited_urls', 'security_anomalies']:
                    setattr(self, field, [])
                else:
                    setattr(self, field, {})

        # Set location if not already set for new sessions
        if not self.pk and not self.location_city and self.ip_address:
            self.update_location_from_ip()

        # Generate tab_id if not set
        if not self.tab_id:
            import uuid
            self.tab_id = str(uuid.uuid4())

        # Set tab opened time for new records
        if not self.pk and not self.tab_opened_time:
            self.tab_opened_time = self.login_time

        # All times should already be in UTC when saved to DB
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
from datetime import time, timedelta
from decimal import Decimal
from django.db import models
from django.utils import timezone

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
    custom_work_days = models.CharField(max_length=255, null=True, blank=True, help_text="Comma-separated day names (Monday,Tuesday,etc.)")
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

    from decimal import Decimal

    # Inside your Django model class

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
        if isinstance(self.effective_from, str):
            self.effective_from = timezone.datetime.strptime(self.effective_from, '%Y-%m-%d').date()

        if self.is_current:
            other_assignments = ShiftAssignment.objects.filter(
                user=self.user,
                is_current=True
            ).exclude(id=self.id if self.id else None)

            for assignment in other_assignments:
                assignment.is_current = False
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

        # Validate dates
        if self.date and self.date > timezone.now().date():
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

    def _update_status_logic(self):
        """Update attendance status based on calculated data and business rules"""
        # Skip status update for certain fixed statuses
        if self.status in ['On Leave', 'Holiday', 'Weekend']:
            return

        # Update status based on clock times and shift
        if self.clock_in_time and self.shift:
            if self.late_minutes > 0:
                self.status = 'Present & Late'
            elif self.total_hours and self.total_hours >= Decimal('4.0'):
                self.status = 'Present'

        # Handle "Yet to Clock In" to "Absent" conversion
        if self.status == 'Yet to Clock In' and not self.clock_in_time:
            if self._is_shift_ended():
                self.status = 'Absent'
                if not self.regularization_reason:
                    self.regularization_reason = "Auto-marked as absent (no activity, shift ended)"

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

    def _calculate_early_departure(self):
        """Calculate early departure minutes"""
        if not self.clock_out_time or not self.shift:
            return

        clock_out_time = self.clock_out_time.time()
        shift_end = self.shift.end_time

        shift_end_minutes = shift_end.hour * 60 + shift_end.minute
        clock_out_minutes = clock_out_time.hour * 60 + clock_out_time.minute

        # Handle night shifts
        if self.shift.is_night_shift() and clock_out_minutes > shift_end_minutes:
            # Next day clock out
            clock_out_minutes += 24 * 60

        if clock_out_minutes < shift_end_minutes:
            self.left_early = True
            self.early_departure_minutes = shift_end_minutes - clock_out_minutes

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
        if not date:
            date = session.login_time.date()

        try:
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

        except cls.DoesNotExist:
            logger.warning(f"No attendance record found for {user.username} on {date}")

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
        Get formatted duration string
        """
        if not self.total_hours:
            return "0h 0m"

        hours = int(self.total_hours)
        minutes = int((self.total_hours - hours) * 60)
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


'''-------------------------------------------- SUPPORT AREA ---------------------------------------'''
import uuid
from django.db import models
from django.utils.timezone import now
from django.contrib.auth import get_user_model
from django.utils import timezone

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

    # SLA Status choices
    class SLAStatus(models.TextChoices):
        WITHIN_SLA = 'Within SLA', 'Within SLA'
        BREACHED = 'Breached', 'Breached'

    # Core Fields
    ticket_id = models.CharField(max_length=100, unique=True, blank=True)
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

    # CC Users
    cc_users = models.ManyToManyField(
        User,
        blank=True,
        related_name='cc_tickets',
        help_text="Users to be CC'd on this ticket"
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
    sla_target_date = models.DateTimeField(null=True, blank=True, help_text="Target date for SLA compliance")
    sla_status = models.CharField(
        max_length=20,
        choices=SLAStatus.choices,
        null=True,
        blank=True,
        help_text="Status of SLA compliance"
    )
    resolution_summary = models.TextField(blank=True)
    resolution_time = models.DurationField(null=True, blank=True)

    # Response time tracking
    response_time = models.DurationField(
        null=True,
        blank=True,
        help_text="Time taken for first response"
    )
    time_to_close = models.DurationField(
        null=True,
        blank=True,
        help_text="Total time from creation to closure"
    )

    # Escalation tracking
    escalation_level = models.PositiveSmallIntegerField(
        default=0,
        help_text="Current escalation level of the ticket"
    )

    # Add this field
    reopen_count = models.PositiveSmallIntegerField(
        default=0,
        help_text="Number of times this ticket has been reopened"
    )

    # User Satisfaction
    satisfaction_rating = models.IntegerField(null=True, blank=True, choices=[(i, i) for i in range(1, 6)])
    feedback = models.TextField(blank=True)

    # Soft delete field - ADD DEFAULT VALUE
    is_deleted = models.BooleanField(default=False, help_text="Soft delete flag")

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ticket_id']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['user']),
            models.Index(fields=['due_date']),
            models.Index(fields=['resolved_at']),
            models.Index(fields=['priority']),
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

        # Auto-generate ticket_id if not set
        if not self.ticket_id:
            # Short code from IssueType value (convert to uppercase and replace spaces with _ or remove)
            issue_type_code = self.issue_type.upper().replace(' ', '_')

            # Count existing tickets with this issue_type
            existing_count = Support.objects.filter(issue_type=self.issue_type).count() + 1

            # Generate ticket_id
            self.ticket_id = f"{issue_type_code}-{existing_count}"

        # Auto-assign tickets to HR or Admin based on issue type
        if not self.assigned_group:
            hr_issues = [self.IssueType.HR, self.IssueType.ACCESS]
            self.assigned_group = self.AssignedGroup.HR if self.issue_type in hr_issues else self.AssignedGroup.ADMIN

        # Calculate SLA target date if not set
        if not self.sla_target_date and self.created_at:
            self.set_sla_target_date()

        # Track status changes
        if self.pk:
            old_ticket = Support.objects.get(pk=self.pk)

            # Check for status changes
            if old_ticket.status != self.status:
                self._status_changed = (old_ticket.status, self.status)

                # Track resolution time when moving to Resolved status
                if self.status == self.Status.RESOLVED and not self.resolved_at:
                    self.resolved_at = now()
                    if self.created_at:
                        self.resolution_time = self.resolved_at - self.created_at

                # Calculate time_to_close when status changes to Closed
                if self.status == self.Status.CLOSED and not self.time_to_close:
                    if self.created_at:
                        self.time_to_close = now() - self.created_at
            else:
                self._status_changed = None
        else:
            # New ticket
            self._status_changed = (None, self.status)

        # Check SLA compliance based on target date
        if self.sla_target_date:
            if self.resolved_at and self.resolved_at > self.sla_target_date:
                self.sla_breach = True
                self.sla_status = self.SLAStatus.BREACHED
            elif self.resolved_at and self.resolved_at <= self.sla_target_date:
                self.sla_breach = False
                self.sla_status = self.SLAStatus.WITHIN_SLA

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


    def set_sla_target_date(self):
        """Calculate SLA target date based on priority"""
        if not self.created_at:
            return

        # Define SLA target times based on priority (in hours)
        sla_targets = {
            self.Priority.CRITICAL: 4,    # 4 hours
            self.Priority.HIGH: 8,        # 8 hours
            self.Priority.MEDIUM: 24,     # 24 hours
            self.Priority.LOW: 48,        # 48 hours
        }

        # Get target hours for this ticket's priority
        target_hours = sla_targets.get(self.priority, 24)  # Default to 24 hours

        # Calculate target date (considering business hours could be added here)
        self.sla_target_date = self.created_at + timezone.timedelta(hours=target_hours)


import os

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





class TicketActivity(models.Model):
    """Model for tracking ticket activity, including reopening"""
    class Action(models.TextChoices):
        CREATED = 'CREATED', 'Created'
        UPDATED = 'UPDATED', 'Updated'
        ASSIGNED = 'ASSIGNED', 'Assigned'
        COMMENTED = 'COMMENTED', 'Commented'
        REOPENED = 'REOPENED', 'Reopened'
        ESCALATED = 'ESCALATED', 'Escalated'
        RESOLVED = 'RESOLVED', 'Resolved'
        CLOSED = 'CLOSED', 'Closed'

    ticket = models.ForeignKey(Support, on_delete=models.CASCADE, related_name='ticket_activity')
    action = models.CharField(max_length=20, choices=Action.choices)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = "Ticket Activities"

    def __str__(self):
        return f"{self.action} on {self.ticket.ticket_id} by {self.user.username if self.user else 'System'}"


# Add this to your trueAlign/models.py file
from django.db import models
from django.contrib.auth.models import User
from django.utils.text import get_valid_filename
import os
import uuid

class CommentAttachment(models.Model):
    """Model for storing attachments related to ticket comments"""
    comment = models.ForeignKey(
        TicketComment,
        on_delete=models.CASCADE,
        related_name='attachments',  # Use 'attachments' for easy access from a comment object
        help_text="The comment this attachment belongs to"
    )

    ticket_activity = models.ForeignKey(
        'TicketActivity',
        on_delete=models.CASCADE,
        related_name='comment_attachments',
        help_text="The ticket activity/comment this attachment belongs to"
    )

    file = models.FileField(
        upload_to='comment_attachments/%Y/%m/%d/',
        help_text="Upload attachment file"
    )

    original_filename = models.CharField(
        max_length=255,
        help_text="Original name of the uploaded file"
    )

    formatted_filename = models.CharField(
        max_length=255,
        help_text="Formatted filename with ticket ID and number",
        blank=True
    )

    file_size = models.PositiveIntegerField(
        default=0,
        help_text="Size of the file in bytes"
    )

    content_type = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="MIME type of the file"
    )

    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        help_text="User who uploaded this attachment"
    )

    uploaded_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When the attachment was uploaded"
    )

    description = models.TextField(
        blank=True,
        null=True,
        help_text="Optional description of the attachment"
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether this attachment is active"
    )


    class Meta:
        db_table = 'truealign_comment_attachment'
        verbose_name = 'Comment Attachment'
        verbose_name_plural = 'Comment Attachments'
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.original_filename} - {self.ticket_activity}"

    def generate_formatted_filename(self, filename):
        """Generate formatted filename based on ticket ID and comment number"""
        # Get ticket id
        ticket_id = self.ticket_activity.ticket.ticket_id

        # Get count of existing attachments
        existing_count = CommentAttachment.objects.filter(
            ticket_activity=self.ticket_activity,
            is_active=True
        ).count()

        # Next number for this comment
        next_number = existing_count + 1

        # Get file extension
        ext = filename.split('.')[-1].lower()

        # Build formatted filename
        return f"{ticket_id}-comment-{next_number}.{ext}"

    def comment_attachment_path(self, filename):
        """Define the upload path and filename"""
        ticket_id = self.ticket_activity.ticket.ticket_id
        formatted_name = self.generate_formatted_filename(filename)

        # Store the formatted filename
        self.formatted_filename = formatted_name

        # Return full path
        return os.path.join('comment_attachments', str(ticket_id), formatted_name)

    def save(self, *args, **kwargs):
        if self.file:
            # Store original filename
            if not self.original_filename:
                self.original_filename = get_valid_filename(self.file.name)

            # Generate formatted filename and update file path
            if not self.formatted_filename:
                self.file.name = self.comment_attachment_path(self.file.name)

            # Update file size
            if not self.file_size and hasattr(self.file, 'size'):
                self.file_size = self.file.size

            # Update content type
            if not self.content_type and hasattr(self.file, 'content_type'):
                self.content_type = self.file.content_type

        super().save(*args, **kwargs)

    @property
    def file_size_human(self):
        """Return human readable file size"""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"


class TicketAttachment(models.Model):
    """Model for file attachments on tickets"""
    ticket = models.ForeignKey(Support, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to='ticket_attachments/%Y/%m/%d/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=255, blank=True)

    original_filename = models.CharField(
        max_length=255,
        help_text="Original name of the uploaded file"
    )

    formatted_filename = models.CharField(
        max_length=255,
        help_text="Formatted filename with ticket ID and number",
        blank=True
    )

    file_size = models.PositiveIntegerField(
        default=0,
        help_text="File size in bytes"
    )

    file_type = models.CharField(
        max_length=100,
        blank=True,
        help_text="MIME type of the file"
    )

    is_deleted = models.BooleanField(
        default=False,
        help_text="Soft delete flag"
    )

    def generate_formatted_filename(self, filename):
        """Generate formatted filename based on ticket ID and attachment number"""
        # Get ticket_id
        ticket_id = self.ticket.ticket_id

        # Get count of existing attachments
        existing_count = TicketAttachment.objects.filter(
            ticket=self.ticket,
            is_deleted=False
        ).count()

        # Next number
        next_number = existing_count + 1

        # Get file extension
        ext = filename.split('.')[-1].lower()

        # Build formatted filename
        return f"{ticket_id}-{next_number}.{ext}"

    def ticket_attachment_path(self, filename):
        """Define the upload path and filename"""
        ticket_id = self.ticket.ticket_id
        formatted_name = self.generate_formatted_filename(filename)

        # Store the formatted filename
        self.formatted_filename = formatted_name

        # Return full path
        return os.path.join('ticket_attachments', str(ticket_id), formatted_name)

    def save(self, *args, **kwargs):
        if self.file:
            # Store original filename
            if not self.original_filename:
                self.original_filename = get_valid_filename(self.file.name)

            # Generate formatted filename and update file path
            if not self.formatted_filename:
                self.file.name = self.ticket_attachment_path(self.file.name)

            # Update file size
            if not self.file_size and hasattr(self.file, 'size'):
                self.file_size = self.file.size

            # Update file type
            if not self.file_type and hasattr(self.file, 'content_type'):
                self.file_type = self.file.content_type

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Attachment for {self.ticket.ticket_id}: {self.original_filename}"

    @property
    def file_size_human(self):
        """Return human readable file size"""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"



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


'''----------------------------------- Entertainment -----------------------------------'''


class GameIcon(models.Model):
    """Custom icons for the Tic-Tac-Toe game"""
    name = models.CharField(max_length=50)
    symbol = models.CharField(max_length=10)  # Can store emoji or character
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_icons')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.symbol})"

class TicTacToeGame(models.Model):
    """Model to track Tic-Tac-Toe games between users"""
    STATUS_CHOICES = (
        ('pending', 'Pending Acceptance'),
        ('active', 'Game in Progress'),
        ('completed', 'Game Completed'),
        ('cancelled', 'Game Cancelled'),
        ('timeout', 'Game Timeout'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_games')
    opponent = models.ForeignKey(User, on_delete=models.CASCADE, related_name='invited_games')

    # Game board stored as a string representation of 9 characters
    # Empty spaces are represented by spaces, other spaces by player symbols
    board = models.CharField(max_length=9, default=' ' * 9)

    # Who's turn is it
    current_turn = models.ForeignKey(User, on_delete=models.CASCADE, related_name='games_turn', null=True)

    # Game status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Winner of the game (null if draw or game not completed)
    winner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='won_games', null=True, blank=True)

    # Custom icons for the game
    creator_icon = models.ForeignKey(GameIcon, on_delete=models.SET_NULL, related_name='creator_games', null=True)
    opponent_icon = models.ForeignKey(GameIcon, on_delete=models.SET_NULL, related_name='opponent_games', null=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_move_at = models.DateTimeField(auto_now_add=True)

    # Spectator feature
    allow_spectators = models.BooleanField(default=True)

    def __str__(self):
        return f"Game {self.id}: {self.creator.username} vs {self.opponent.username} ({self.status})"

    def is_timeout(self):
        """Check if the game has timed out (no move in 10 minutes)"""
        return timezone.now() > self.last_move_at + timedelta(minutes=10)

    def check_winner(self):
        """Check if there is a winner or if the game is a draw"""
        winning_combinations = [
            # Rows
            [0, 1, 2], [3, 4, 5], [6, 7, 8],
            # Columns
            [0, 3, 6], [1, 4, 7], [2, 5, 8],
            # Diagonals
            [0, 4, 8], [2, 4, 6]
        ]

        for combo in winning_combinations:
            if (self.board[combo[0]] != ' ' and
                self.board[combo[0]] == self.board[combo[1]] == self.board[combo[2]]):
                # We have a winner
                if self.board[combo[0]] == self.creator_icon.symbol:
                    self.winner = self.creator
                else:
                    self.winner = self.opponent
                self.status = 'completed'
                return True

        # Check for a draw
        if ' ' not in self.board:
            self.status = 'completed'
            return True

        return False

    def make_move(self, user, position):
        """Make a move on the board"""
        if self.status != 'active':
            return False, "Game is not active"

        if user != self.current_turn:
            return False, "Not your turn"

        if not (0 <= position < 9):
            return False, "Invalid position"

        if self.board[position] != ' ':
            return False, "Position already taken"

        # Update the board
        board_list = list(self.board)
        symbol = self.creator_icon.symbol if user == self.creator else self.opponent_icon.symbol
        board_list[position] = symbol
        self.board = ''.join(board_list)

        # Update last move timestamp
        self.last_move_at = timezone.now()

        # Switch turns
        self.current_turn = self.opponent if user == self.creator else self.creator

        # Check if the game is over
        self.check_winner()

        # Save changes
        self.save()

        # Create a notification for the other player
        if self.status == 'active':
            Notification.objects.create(
                recipient=self.current_turn,
                message=f"It's your turn in the game against {user.username}",
                notification_type='game_turn',
                game=self
            )
        elif self.status == 'completed' and self.winner:
            # Notify the loser about the game result
            loser = self.opponent if self.winner == self.creator else self.creator
            Notification.objects.create(
                recipient=loser,
                message=f"Game over! {self.winner.username} has won the game.",
                notification_type='game_over',
                game=self
            )

        return True, "Move successful"

    def accept_game(self):
        """Accept a game invitation"""
        if self.status != 'pending':
            return False, "Game is not pending"

        self.status = 'active'
        self.current_turn = self.creator  # Creator goes first
        self.save()

        # Notify the creator that the game has been accepted
        Notification.objects.create(
            recipient=self.creator,
            message=f"{self.opponent.username} has accepted your game invitation! It's your turn to play.",
            notification_type='game_accepted',
            game=self
        )

        return True, "Game accepted"

    def decline_game(self):
        """Decline a game invitation"""
        if self.status != 'pending':
            return False, "Game is not pending"

        self.status = 'cancelled'
        self.save()

        # Notify the creator that the game has been declined
        Notification.objects.create(
            recipient=self.creator,
            message=f"{self.opponent.username} has declined your game invitation.",
            notification_type='game_declined',
            game=self
        )

        return True, "Game declined"

    def forfeit_game(self, user):
        """Forfeit the game"""
        if self.status != 'active':
            return False, "Game is not active"

        self.status = 'completed'
        self.winner = self.opponent if user == self.creator else self.creator
        self.save()

        # Notify the winner
        Notification.objects.create(
            recipient=self.winner,
            message=f"{user.username} has forfeited the game. You win!",
            notification_type='game_forfeit',
            game=self
        )

        return True, "Game forfeited"


class GameSpectator(models.Model):
    """Model to track users spectating games"""
    game = models.ForeignKey(TicTacToeGame, on_delete=models.CASCADE, related_name='spectators')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='spectating_games')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('game', 'user')

    def __str__(self):
        return f"{self.user.username} spectating game {self.game.id}"


class PlayerStats(models.Model):
    """Model to track player statistics for a leaderboard"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='game_stats')
    games_played = models.IntegerField(default=0)
    games_won = models.IntegerField(default=0)
    games_lost = models.IntegerField(default=0)
    games_drawn = models.IntegerField(default=0)

    def __str__(self):
        return f"Stats for {self.user.username}"

    @property
    def win_percentage(self):
        """Calculate win percentage"""
        if self.games_played == 0:
            return 0
        return (self.games_won / self.games_played) * 100

    @classmethod
    def update_stats(cls, game):
        """Update player statistics after a game is completed"""
        if game.status != 'completed':
            return

        # Get or create stats for both players
        creator_stats, _ = cls.objects.get_or_create(user=game.creator)
        opponent_stats, _ = cls.objects.get_or_create(user=game.opponent)

        # Update games played count
        creator_stats.games_played += 1
        opponent_stats.games_played += 1

        # Update win/loss/draw counts
        if game.winner:
            if game.winner == game.creator:
                creator_stats.games_won += 1
                opponent_stats.games_lost += 1
            else:
                opponent_stats.games_won += 1
                creator_stats.games_lost += 1
        else:
            # It's a draw
            creator_stats.games_drawn += 1
            opponent_stats.games_drawn += 1

        # Save the updated stats
        creator_stats.save()
        opponent_stats.save()


class Notification(models.Model):
    """Model for user notifications"""
    NOTIFICATION_TYPES = (
        ('game_invite', 'Game Invitation'),
        ('game_turn', 'Your Turn'),
        ('game_accepted', 'Game Accepted'),
        ('game_declined', 'Game Declined'),
        ('game_over', 'Game Over'),
        ('game_forfeit', 'Game Forfeit'),
        ('game_timeout', 'Game Timeout'),
    )

    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.CharField(max_length=255)
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    game = models.ForeignKey(TicTacToeGame, on_delete=models.CASCADE, related_name='notifications', null=True, blank=True)

    def __str__(self):
        return f"Notification for {self.recipient.username}: {self.message[:30]}"

    class Meta:
        ordering = ['-created_at']



'''----------------------------- Conference Room Booking -----------------------------'''


class Room(models.Model):
    """
    Represents a conference room available for booking.
    """
    class RoomStatus(models.TextChoices):
        ACTIVE = 'ACTIVE', 'Active'
        MAINTENANCE = 'MAINTENANCE', 'Under Maintenance'
        INACTIVE = 'INACTIVE', 'Inactive'

    class RoomType(models.TextChoices):
        CONFERENCE = 'CONFERENCE', 'Conference Room'
        HUDDLE = 'HUDDLE', 'Huddle Room'
        MEETING = 'MEETING', 'Meeting Room'
        BOARD = 'BOARD', 'Board Room'

    name = models.CharField(max_length=100, unique=True, help_text="Room name")
    room_type = models.CharField(
        max_length=15,
        choices=RoomType.choices,
        default=RoomType.CONFERENCE
    )
    capacity = models.PositiveIntegerField(default=8, help_text="Maximum seating capacity")
    location = models.CharField(max_length=100, blank=True, help_text="Room location/floor")
    facilities = models.TextField(
        blank=True,
        help_text="Available facilities (e.g., Projector, Whiteboard, Video Conferencing)"
    )
    status = models.CharField(
        max_length=12,
        choices=RoomStatus.choices,
        default=RoomStatus.ACTIVE
    )
    hourly_rate = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=0.00,
        help_text="Cost per hour (if applicable)"
    )
    description = models.TextField(blank=True, help_text="Room description")
    image = models.ImageField(
        upload_to='room_images/',
        blank=True,
        null=True,
        help_text="Room photo"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Analytics fields
    total_bookings = models.PositiveIntegerField(default=0, help_text="Total bookings made")
    total_hours_booked = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        help_text="Total hours booked"
    )

    class Meta:
        ordering = ['name']
        verbose_name = "Conference Room"
        verbose_name_plural = "Conference Rooms"

    def __str__(self):
        return f"{self.name} ({self.get_room_type_display()}) - {self.get_status_display()}"

    @property
    def is_available(self):
        """Returns True if room is active and available for booking."""
        return self.status == self.RoomStatus.ACTIVE

    @property
    def current_booking(self):
        """Returns current active booking if any."""
        now = timezone.now()
        return self.bookings.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lte=now,
            end_time__gt=now
        ).first()

    @property
    def next_booking(self):
        """Returns the next upcoming booking."""
        now = timezone.now()
        return self.bookings.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__gt=now
        ).order_by('start_time').first()

    @property
    def is_occupied(self):
        """Returns True if room is currently occupied."""
        return self.current_booking is not None

    def get_bookings_today(self):
        """Get all bookings for today."""
        today = timezone.now().date()
        return self.bookings.filter(
            start_time__date=today,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        ).order_by('start_time')

    def get_availability_today(self):
        """Get available time slots for today."""
        from datetime import datetime, time, timedelta
        from pytz import timezone as pytz_timezone
        import pytz

        IST = pytz_timezone('Asia/Kolkata')
        today = timezone.now().date()

        # Working hours: 9 AM to 6 PM
        day_start = IST.localize(datetime.combine(today, time(9, 0)))
        day_end = IST.localize(datetime.combine(today, time(18, 0)))

        bookings = self.get_bookings_today()
        available_slots = []

        current_time = max(timezone.now(), day_start.astimezone(pytz.UTC))

        for booking in bookings:
            if booking.start_time > current_time:
                # Gap between current time and next booking
                available_slots.append({
                    'start': current_time,
                    'end': booking.start_time
                })
            current_time = max(current_time, booking.end_time)

        # Check if there's time after the last booking
        if current_time < day_end.astimezone(pytz.UTC):
            available_slots.append({
                'start': current_time,
                'end': day_end.astimezone(pytz.UTC)
            })

        return available_slots

    def update_analytics(self):
        """Update room analytics based on confirmed bookings."""
        from django.db.models import Count, Sum, F

        stats = self.bookings.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED
        ).aggregate(
            total_bookings=Count('id'),
            total_duration=Sum(
                F('end_time') - F('start_time'),
                output_field=models.DurationField()
            )
        )

        self.total_bookings = stats['total_bookings'] or 0
        if stats['total_duration']:
            # Convert duration to hours
            total_seconds = stats['total_duration'].total_seconds()
            self.total_hours_booked = round(total_seconds / 3600, 2)
        else:
            self.total_hours_booked = 0.00

        self.save(update_fields=['total_bookings', 'total_hours_booked'])

    @classmethod
    def get_most_booked_rooms(cls, limit=5):
        """Get the most frequently booked rooms."""
        return cls.objects.filter(
            status=cls.RoomStatus.ACTIVE
        ).order_by('-total_bookings')[:limit]

    @classmethod
    def get_available_rooms(cls):
        """Get all available rooms for booking."""
        return cls.objects.filter(status=cls.RoomStatus.ACTIVE)


class ConferenceBooking(models.Model):
    """
    Represents a booking for a conference room.
    """
    class BookingStatus(models.TextChoices):
        CONFIRMED = 'CONFIRMED', 'Confirmed'
        CANCELLED = 'CANCELLED', 'Cancelled'
        PENDING = 'PENDING', 'Pending Approval'
        REJECTED = 'REJECTED', 'Rejected'

    class Priority(models.TextChoices):
        LOW = 'LOW', 'Low'
        MEDIUM = 'MEDIUM', 'Medium'
        HIGH = 'HIGH', 'High'
        URGENT = 'URGENT', 'Urgent'

    # Core booking fields
    room = models.ForeignKey(
        Room,
        on_delete=models.CASCADE,
        related_name='bookings',
        help_text="Conference room being booked"
    )
    booked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='conference_bookings'
    )
    purpose = models.CharField(max_length=255, help_text="Purpose of the meeting")
    description = models.TextField(blank=True, help_text="Additional meeting details")
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    # Meeting details
    attendees_count = models.PositiveIntegerField(
        default=1,
        help_text="Expected number of attendees"
    )
    external_attendees = models.PositiveIntegerField(
        default=0,
        help_text="Number of external/guest attendees"
    )
    meeting_type = models.CharField(
        max_length=50,
        choices=[
            ('INTERNAL', 'Internal Meeting'),
            ('CLIENT', 'Client Meeting'),
            ('INTERVIEW', 'Interview'),
            ('TRAINING', 'Training'),
            ('PRESENTATION', 'Presentation'),
            ('OTHER', 'Other')
        ],
        default='INTERNAL'
    )
    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.MEDIUM
    )

    # Status and tracking
    status = models.CharField(
        max_length=10,
        choices=BookingStatus.choices,
        default=BookingStatus.CONFIRMED
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Cancellation tracking
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='cancelled_bookings'
    )
    cancellation_reason = models.TextField(blank=True, help_text="Reason for cancellation")

    # Approval workflow (if needed)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_bookings'
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    # Additional features
    recurring_pattern = models.CharField(
        max_length=20,
        choices=[
            ('NONE', 'No Recurrence'),
            ('DAILY', 'Daily'),
            ('WEEKLY', 'Weekly'),
            ('MONTHLY', 'Monthly')
        ],
        default='NONE'
    )
    parent_booking = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='recurring_bookings',
        help_text="Original booking for recurring series"
    )

    # Check-in feature
    checked_in = models.BooleanField(default=False)
    checked_in_at = models.DateTimeField(null=True, blank=True)
    no_show = models.BooleanField(default=False, help_text="Meeting didn't happen")

    # Cost tracking
    hourly_rate = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=0.00,
        help_text="Rate per hour for this booking"
    )
    total_cost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        help_text="Total cost of booking"
    )

    class Meta:
        ordering = ['-created_at', 'start_time']
        verbose_name = "Conference Room Booking"
        verbose_name_plural = "Conference Room Bookings"

        # Ensure no overlapping confirmed bookings for the same room
        constraints = [
            models.UniqueConstraint(
                fields=['room', 'start_time', 'end_time'],
                condition=models.Q(status='CONFIRMED'),
                name='unique_confirmed_booking_slot'
            ),
            models.CheckConstraint(
                check=models.Q(end_time__gt=models.F('start_time')),
                name='end_time_after_start_time'
            ),
            models.CheckConstraint(
                check=models.Q(attendees_count__gte=1),
                name='minimum_one_attendee'
            )
        ]

        indexes = [
            models.Index(fields=['room', 'start_time', 'status']),
            models.Index(fields=['booked_by', 'status']),
            models.Index(fields=['start_time', 'end_time']),
            models.Index(fields=['status', 'created_at']),
        ]

    def __str__(self):
        return (
            f"{self.room.name} for '{self.purpose}' "
            f"({self.start_time.strftime('%b %d, %I:%M %p')} - "
            f"{self.end_time.strftime('%I:%M %p')}) "
            f"[{self.status}]"
        )

    @property
    def room_name(self):
        """Backward compatibility property."""
        return self.room.name

    @property
    def is_active(self):
        """Returns True if the booking is confirmed and in the future."""
        return self.status == self.BookingStatus.CONFIRMED and self.end_time > timezone.now()

    @property
    def is_current(self):
        """Returns True if the booking is currently active."""
        now = timezone.now()
        return (
            self.status == self.BookingStatus.CONFIRMED and
            self.start_time <= now <= self.end_time
        )

    @property
    def is_past(self):
        """Returns True if the booking has ended."""
        return self.end_time < timezone.now()

    @property
    def duration(self):
        """Returns booking duration as timedelta."""
        return self.end_time - self.start_time

    @property
    def duration_hours(self):
        """Returns booking duration in hours."""
        return round(self.duration.total_seconds() / 3600, 2)

    @property
    def can_be_cancelled(self):
        """Check if booking can be cancelled."""
        if self.status != self.BookingStatus.CONFIRMED:
            return False

        # Can't cancel if meeting has already started
        if self.start_time <= timezone.now():
            return False

        return True

    @property
    def can_check_in(self):
        """Check if user can check in to the meeting."""
        now = timezone.now()
        # Allow check-in 15 minutes before and 15 minutes after start time
        check_in_window_start = self.start_time - timedelta(minutes=15)
        check_in_window_end = self.start_time + timedelta(minutes=15)

        return (
            self.status == self.BookingStatus.CONFIRMED and
            not self.checked_in and
            not self.no_show and
            check_in_window_start <= now <= check_in_window_end
        )

    def clean(self):
        """Validate booking data."""
        from django.core.exceptions import ValidationError

        # Validate end time is after start time
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            raise ValidationError("End time must be after start time.")

        # Validate booking is not in the past
        if self.start_time and self.start_time < timezone.now():
            raise ValidationError("Booking cannot be in the past.")

        # Validate attendees don't exceed room capacity
        if self.room and self.attendees_count > self.room.capacity:
            raise ValidationError(
                f"Number of attendees ({self.attendees_count}) exceeds room capacity ({self.room.capacity})."
            )

        # Validate room is available
        if self.room and not self.room.is_available:
            raise ValidationError(f"Room '{self.room.name}' is not available for booking.")

    def save(self, *args, **kwargs):
        """Override save to calculate costs and update room analytics."""
        from decimal import Decimal

        # Calculate total cost
        if self.hourly_rate == 0 and self.room:
            self.hourly_rate = self.room.hourly_rate

        # Convert duration_hours to Decimal to avoid float * Decimal error
        duration_decimal = Decimal(str(self.duration_hours))
        self.total_cost = duration_decimal * self.hourly_rate

        # Call parent save
        super().save(*args, **kwargs)

        # Update room analytics if this is a confirmed booking
        if self.status == self.BookingStatus.CONFIRMED and self.room:
            self.room.update_analytics()

    def cancel(self, cancelled_by, reason=""):
        """Cancel the booking."""
        if not self.can_be_cancelled:
            raise ValueError("This booking cannot be cancelled.")

        self.status = self.BookingStatus.CANCELLED
        self.cancelled_at = timezone.now()
        self.cancelled_by = cancelled_by
        self.cancellation_reason = reason
        self.save()

        # Update room analytics
        if self.room:
            self.room.update_analytics()

    def check_in(self):
        """Check in to the meeting."""
        if not self.can_check_in:
            raise ValueError("Cannot check in at this time.")

        self.checked_in = True
        self.checked_in_at = timezone.now()
        self.save(update_fields=['checked_in', 'checked_in_at'])

    def mark_no_show(self):
        """Mark booking as no-show."""
        if self.is_past and not self.checked_in:
            self.no_show = True
            self.save(update_fields=['no_show'])

    @classmethod
    def get_conflicting_bookings(cls, room, start_time, end_time, exclude_id=None):
        """Get bookings that conflict with the given time range."""
        queryset = cls.objects.filter(
            room=room,
            status=cls.BookingStatus.CONFIRMED,
            start_time__lt=end_time,
            end_time__gt=start_time
        )

        if exclude_id:
            queryset = queryset.exclude(id=exclude_id)

        return queryset

    @classmethod
    def get_room_utilization(cls, room, start_date=None, end_date=None):
        """Calculate room utilization percentage for a given period."""
        from django.db.models import Sum, F

        if not start_date:
            start_date = timezone.now().date()
        if not end_date:
            end_date = start_date

        # Calculate total booked hours
        bookings = cls.objects.filter(
            room=room,
            status=cls.BookingStatus.CONFIRMED,
            start_time__date__range=[start_date, end_date]
        )

        total_booked_seconds = bookings.aggregate(
            total=Sum(F('end_time') - F('start_time'))
        )['total']

        if not total_booked_seconds:
            return 0.0

        total_booked_hours = total_booked_seconds.total_seconds() / 3600

        # Calculate available hours (9 AM to 6 PM = 9 hours per day)
        days_count = (end_date - start_date).days + 1
        total_available_hours = days_count * 9  # 9 working hours per day

        utilization = (total_booked_hours / total_available_hours) * 100
        return round(utilization, 2)

    @classmethod
    def get_user_booking_stats(cls, user, start_date=None, end_date=None):
        """Get booking statistics for a user."""
        queryset = cls.objects.filter(booked_by=user)

        if start_date and end_date:
            queryset = queryset.filter(start_time__date__range=[start_date, end_date])

        stats = {
            'total_bookings': queryset.count(),
            'confirmed_bookings': queryset.filter(status=cls.BookingStatus.CONFIRMED).count(),
            'cancelled_bookings': queryset.filter(status=cls.BookingStatus.CANCELLED).count(),
            'no_shows': queryset.filter(no_show=True).count(),
            'total_hours': 0
        }

        # Calculate total hours
        confirmed_bookings = queryset.filter(status=cls.BookingStatus.CONFIRMED)
        total_duration = sum([booking.duration for booking in confirmed_bookings], timedelta())
        stats['total_hours'] = round(total_duration.total_seconds() / 3600, 2)

        return stats


class BookingAnalytics:
    """
    Utility class for generating booking analytics and reports.
    """

    @staticmethod
    def get_daily_utilization(date=None):
        """Get room utilization for a specific date."""
        if not date:
            date = timezone.now().date()

        rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        utilization_data = []

        for room in rooms:
            utilization = ConferenceBooking.get_room_utilization(room, date, date)
            bookings_count = ConferenceBooking.objects.filter(
                room=room,
                start_time__date=date,
                status=ConferenceBooking.BookingStatus.CONFIRMED
            ).count()

            utilization_data.append({
                'room': room,
                'utilization_percentage': utilization,
                'bookings_count': bookings_count,
                'current_booking': room.current_booking,
                'next_booking': room.next_booking
            })

        return utilization_data

    @staticmethod
    def get_weekly_report(start_date=None):
        """Generate weekly booking report."""
        if not start_date:
            start_date = timezone.now().date()

        end_date = start_date + timedelta(days=6)

        # Get all bookings for the week
        bookings = ConferenceBooking.objects.filter(
            start_time__date__range=[start_date, end_date],
            status=ConferenceBooking.BookingStatus.CONFIRMED
        ).select_related('room', 'booked_by')

        # Group by room and day
        report_data = {}
        for room in Room.objects.filter(status=Room.RoomStatus.ACTIVE):
            room_bookings = bookings.filter(room=room)
            daily_data = []

            for i in range(7):
                day = start_date + timedelta(days=i)
                day_bookings = room_bookings.filter(start_time__date=day)

                daily_data.append({
                    'date': day,
                    'bookings_count': day_bookings.count(),
                    'total_hours': sum([b.duration_hours for b in day_bookings], 0),
                    'utilization': ConferenceBooking.get_room_utilization(room, day, day)
                })

            report_data[room] = {
                'total_bookings': room_bookings.count(),
                'total_hours': sum([b.duration_hours for b in room_bookings], 0),
                'average_utilization': sum([d['utilization'] for d in daily_data]) / 7,
                'daily_data': daily_data
            }

        return report_data

    @staticmethod
    def get_popular_time_slots():
        """Get most popular booking time slots."""
        from django.db.models import Count

        # Group by hour of day
        bookings = ConferenceBooking.objects.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__gte=timezone.now() - timedelta(days=30)  # Last 30 days
        ).extra(
            select={'hour': 'EXTRACT(hour FROM start_time)'}
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('-count')

        return bookings[:10]  # Top 10 popular hours

    @staticmethod
    def get_hourly_booking_timeline(date=None):
        """Get real hourly booking data for timeline visualization."""
        if not date:
            date = timezone.now().date()

        from django.db.models import Count
        from django.db.models.functions import Extract

        # Get all confirmed bookings for the specified date
        bookings = ConferenceBooking.objects.filter(
            start_time__date=date,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )

        # Group bookings by hour
        hourly_data = bookings.annotate(
            hour=Extract('start_time', 'hour')
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('hour')

        # Create a complete 24-hour timeline
        timeline = []
        hourly_dict = {item['hour']: item['count'] for item in hourly_data}

        for hour in range(24):
            count = hourly_dict.get(hour, 0)

            # Calculate utilization percentage for visual height
            max_possible_bookings = Room.objects.filter(status=Room.RoomStatus.ACTIVE).count()
            utilization_percentage = (count / max_possible_bookings * 100) if max_possible_bookings > 0 else 0

            timeline.append({
                'hour': hour,
                'count': count,
                'utilization_percentage': min(utilization_percentage, 100),  # Cap at 100%
                'formatted_hour': f"{hour:02d}:00"
            })

        return timeline

    @staticmethod
    def get_user_analytics(user, days=30):
        """Get comprehensive analytics for a specific user."""
        start_date = timezone.now().date() - timedelta(days=days)
        end_date = timezone.now().date()

        bookings = ConferenceBooking.objects.filter(
            booked_by=user,
            start_time__date__range=[start_date, end_date]
        )

        analytics = {
            'total_bookings': bookings.count(),
            'confirmed_bookings': bookings.filter(status=ConferenceBooking.BookingStatus.CONFIRMED).count(),
            'cancelled_bookings': bookings.filter(status=ConferenceBooking.BookingStatus.CANCELLED).count(),
            'no_shows': bookings.filter(no_show=True).count(),
            'total_hours': sum([b.duration_hours for b in bookings.filter(status=ConferenceBooking.BookingStatus.CONFIRMED)], 0),
            'favorite_rooms': bookings.values('room__name').annotate(
                count=Count('id')
            ).order_by('-count')[:3],
            'meeting_types': bookings.values('meeting_type').annotate(
                count=Count('id')
            ).order_by('-count'),
            'average_meeting_duration': 0,
            'peak_hours': bookings.extra(
                select={'hour': 'EXTRACT(hour FROM start_time)'}
            ).values('hour').annotate(
                count=Count('id')
            ).order_by('-count')[:3]
        }

        # Calculate average meeting duration
        confirmed_bookings = bookings.filter(status=ConferenceBooking.BookingStatus.CONFIRMED)
        if confirmed_bookings.exists():
            total_duration = sum([b.duration for b in confirmed_bookings], timedelta())
            analytics['average_meeting_duration'] = round(
                total_duration.total_seconds() / 3600 / confirmed_bookings.count(), 2
            )

        return analytics


class RoomManager:
    """
    Utility class for room management operations.
    """

    @staticmethod
    def get_available_rooms_for_slot(start_time, end_time, min_capacity=1):
        """Get available rooms for a specific time slot."""
        # Get all active rooms with sufficient capacity
        rooms = Room.objects.filter(
            status=Room.RoomStatus.ACTIVE,
            capacity__gte=min_capacity
        )

        available_rooms = []

        for room in rooms:
            # Check if room has any conflicting bookings
            conflicts = ConferenceBooking.get_conflicting_bookings(
                room, start_time, end_time
            )

            if not conflicts.exists():
                available_rooms.append({
                    'room': room,
                    'current_booking': room.current_booking,
                    'next_booking': room.next_booking,
                    'availability_slots': room.get_availability_today()
                })

        return available_rooms

    @staticmethod
    def suggest_alternative_slots(room, start_time, end_time, duration_minutes=60):
        """Suggest alternative time slots for a room."""
        from datetime import timedelta

        duration = timedelta(minutes=duration_minutes)

        # Look for slots in the next 7 days
        suggestions = []
        search_date = start_time.date()

        for i in range(7):
            current_date = search_date + timedelta(days=i)

            # Skip weekends
            if current_date.weekday() >= 5:
                continue

            # Working hours: 9 AM to 6 PM
            from datetime import time
            from pytz import timezone as pytz_timezone

            IST = pytz_timezone('Asia/Kolkata')
            day_start = IST.localize(datetime.combine(current_date, time(9, 0)))
            day_end = IST.localize(datetime.combine(current_date, time(18, 0)))

            # Get bookings for this day
            day_bookings = ConferenceBooking.objects.filter(
                room=room,
                start_time__date=current_date,
                status=ConferenceBooking.BookingStatus.CONFIRMED
            ).order_by('start_time')

            # Find gaps
            import pytz
            current_time = max(timezone.now(), day_start.astimezone(pytz.UTC))

            for booking in day_bookings:
                if booking.start_time > current_time:
                    gap_duration = booking.start_time - current_time
                    if gap_duration >= duration:
                        suggestions.append({
                            'start_time': current_time,
                            'end_time': current_time + duration,
                            'date': current_date
                        })
                        break
                current_time = max(current_time, booking.end_time)

            # Check if there's time after the last booking
            day_end_utc = day_end.astimezone(pytz.UTC)
            if current_time + duration <= day_end_utc:
                suggestions.append({
                    'start_time': current_time,
                    'end_time': current_time + duration,
                    'date': current_date
                })

            # Stop after finding 5 suggestions
            if len(suggestions) >= 5:
                break

        return suggestions

    @staticmethod
    def get_room_status_dashboard():
        """Get real-time status of all rooms."""
        rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        dashboard_data = []

        for room in rooms:
            current_booking = room.current_booking
            next_booking = room.next_booking

            status = 'available'
            if current_booking:
                status = 'occupied'
            elif next_booking and next_booking.start_time <= timezone.now() + timedelta(minutes=30):
                status = 'soon_occupied'

            dashboard_data.append({
                'room': room,
                'status': status,
                'current_booking': current_booking,
                'next_booking': next_booking,
                'available_until': next_booking.start_time if next_booking else None,
                'occupancy_percentage': ConferenceBooking.get_room_utilization(
                    room, timezone.now().date(), timezone.now().date()
                )
            })

        return dashboard_data


class BookingValidator:
    """
    Utility class for booking validation logic.
    """

    @staticmethod
    def validate_booking_time(start_time, end_time):
        """Validate booking time constraints - Updated for 24/7 booking."""
        errors = []

        # Check if end time is after start time
        if start_time >= end_time:
            errors.append("End time must be after start time.")

        # Check if booking is not in the past
        if start_time < timezone.now():
            errors.append("Booking cannot be in the past.")

        # Remove working hours restrictions - allow 24/7 booking
        # Remove weekday restrictions - allow weekend booking

        # Check maximum duration (12 hours instead of 8)
        duration = end_time - start_time
        if duration.total_seconds() > 12 * 3600:  # 12 hours in seconds
            errors.append("Maximum booking duration is 12 hours.")

        # Check minimum duration (15 minutes)
        if duration.total_seconds() < 15 * 60:  # 15 minutes in seconds
            errors.append("Minimum booking duration is 15 minutes.")

        return errors


    @staticmethod
    def validate_room_capacity(room, attendees_count):
        """Validate room capacity against number of attendees."""
        if attendees_count > room.capacity:
            return f"Number of attendees ({attendees_count}) exceeds room capacity ({room.capacity})."
        return None

    @staticmethod
    def validate_user_booking_limits(user, start_time, end_time):
        """Validate user booking limits."""
        errors = []

        # Check daily booking limit (max 3 bookings per day)
        day_bookings = ConferenceBooking.objects.filter(
            booked_by=user,
            start_time__date=start_time.date(),
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )

        if day_bookings.count() >= 3:
            errors.append("You can only book a maximum of 3 rooms per day.")

        # Check weekly booking hours (max 20 hours per week)
        week_start = start_time.date() - timedelta(days=start_time.weekday())
        week_end = week_start + timedelta(days=6)

        week_bookings = ConferenceBooking.objects.filter(
            booked_by=user,
            start_time__date__range=[week_start, week_end],
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )

        total_hours = sum([b.duration_hours for b in week_bookings], 0)
        booking_hours = (end_time - start_time).total_seconds() / 3600

        if total_hours + booking_hours > 20:
            errors.append("Weekly booking limit of 20 hours would be exceeded.")

        # Check for overlapping bookings by the same user
        overlapping = ConferenceBooking.objects.filter(
            booked_by=user,
            start_time__lt=end_time,
            end_time__gt=start_time,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )

        if overlapping.exists():
            errors.append("You already have a booking during this time.")

        return errors

    @staticmethod
    def validate_advance_booking(start_time, max_days_advance=30):
        """Validate advance booking limits."""
        max_advance_date = timezone.now() + timedelta(days=max_days_advance)

        if start_time > max_advance_date:
            return f"Bookings can only be made up to {max_days_advance} days in advance."

        return None


class BookingNotification:
    """
    Utility class for managing booking notifications.
    """

    @staticmethod
    def get_reminder_bookings(minutes_before=15):
        """Get bookings that need reminders."""
        reminder_time = timezone.now() + timedelta(minutes=minutes_before)

        return ConferenceBooking.objects.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lte=reminder_time,
            start_time__gt=timezone.now(),
            checked_in=False
        ).select_related('room', 'booked_by')

    @staticmethod
    def get_overdue_checkins():
        """Get bookings where check-in is overdue."""
        overdue_time = timezone.now() - timedelta(minutes=15)

        return ConferenceBooking.objects.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lte=overdue_time,
            start_time__gt=timezone.now() - timedelta(hours=2),  # Within 2 hours of start
            checked_in=False,
            no_show=False
        ).select_related('room', 'booked_by')

    @staticmethod
    def get_no_show_candidates():
        """Get bookings that are candidates for no-show marking."""
        no_show_threshold = timezone.now() - timedelta(minutes=30)

        return ConferenceBooking.objects.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lte=no_show_threshold,
            checked_in=False,
            no_show=False
        ).select_related('room', 'booked_by')

    @staticmethod
    def send_booking_confirmation(booking):
        """Generate booking confirmation data."""
        return {
            'booking': booking,
            'message': f"Your booking for {booking.room.name} has been confirmed.",
            'details': {
                'room': booking.room.name,
                'date': booking.start_time.strftime('%B %d, %Y'),
                'time': f"{booking.start_time.strftime('%I:%M %p')} - {booking.end_time.strftime('%I:%M %p')}",
                'duration': f"{booking.duration_hours} hours",
                'purpose': booking.purpose,
                'attendees': booking.attendees_count
            }
        }

    @staticmethod
    def send_cancellation_notice(booking):
        """Generate cancellation notice data."""
        return {
            'booking': booking,
            'message': f"Your booking for {booking.room.name} has been cancelled.",
            'details': {
                'room': booking.room.name,
                'date': booking.start_time.strftime('%B %d, %Y'),
                'time': f"{booking.start_time.strftime('%I:%M %p')} - {booking.end_time.strftime('%I:%M %p')}",
                'reason': booking.cancellation_reason or 'No reason provided',
                'cancelled_by': booking.cancelled_by.get_full_name() if booking.cancelled_by else 'System',
                'cancelled_at': booking.cancelled_at.strftime('%B %d, %Y at %I:%M %p') if booking.cancelled_at else ''
            }
        }
