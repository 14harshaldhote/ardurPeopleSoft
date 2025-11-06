import pytz
from django.utils import timezone
from datetime import datetime, timedelta
import logging
import json
import re
import socket
import ipaddress
# from user_agents import parse as ua_parse

# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

# Timezone conversion functions
def get_current_time_ist():
    """Get current time in IST timezone"""
    return timezone.now().astimezone(IST_TIMEZONE)

def to_ist(utc_time):
    """Convert UTC time to IST timezone"""
    if utc_time is None:
        return None
    return utc_time.astimezone(IST_TIMEZONE)

def to_utc(ist_time):
    """Convert IST time to UTC for database storage"""
    if ist_time is None:
        return None
    if timezone.is_naive(ist_time):
        ist_time = IST_TIMEZONE.localize(ist_time)
    return ist_time.astimezone(pytz.UTC)

# IP and location utilities
def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def is_internal_ip(ip):
    """Check if IP is internal/private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_location_from_ip(ip):
    """Get location information from IP address"""
    # This is a placeholder. In a real implementation, you would use a geolocation service
    # like MaxMind GeoIP, ipstack, or similar.
    if is_internal_ip(ip):
        return {
            'country': 'Internal Network',
            'region': 'Local',
            'city': 'Office',
            'latitude': 0,
            'longitude': 0
        }

    # Return placeholder data
    return {
        'country': 'Unknown',
        'region': 'Unknown',
        'city': 'Unknown',
        'latitude': 0,
        'longitude': 0
    }

# Device detection utilities
def parse_user_agent(user_agent_string):
    """Parse user agent string to extract device information"""
    if not user_agent_string:
        return {
            'browser': 'Unknown',
            'browser_version': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': True,
            'is_bot': False
        }

    try:
        user_agent = ua_parse(user_agent_string)

        return {
            'browser': user_agent.browser.family,
            'browser_version': user_agent.browser.version_string,
            'os': user_agent.os.family,
            'os_version': user_agent.os.version_string,
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot
        }
    except Exception as e:
        logger.error(f"Error parsing user agent: {e}")
        return {
            'browser': 'Parse Error',
            'browser_version': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': True,
            'is_bot': False
        }

# Session utilities
def calculate_productivity_score(session_data):
    """Calculate productivity score based on session activity"""
    # This is a simple implementation. In a real-world scenario, you would
    # use more sophisticated algorithms based on your specific requirements.

    # Base score
    score = 50

    # Factors that increase score
    if session_data.get('page_views'):
        score += min(len(session_data.get('page_views', [])) * 2, 20)  # Max +20 for page views

    if session_data.get('click_events'):
        score += min(len(session_data.get('click_events', [])) * 1, 15)  # Max +15 for clicks

    if session_data.get('keyboard_events'):
        score += min(len(session_data.get('keyboard_events', [])) * 0.5, 15)  # Max +15 for keyboard

    # Factors that decrease score
    idle_time_value = session_data.get('idle_time', 0)

    # Convert to minutes depending on the type
    if isinstance(idle_time_value, timedelta):
        idle_time = idle_time_value.total_seconds() / 60
    elif isinstance(idle_time_value, (int, float)):
        idle_time = idle_time_value
    else:
        idle_time = 0

    if idle_time > 5:  # If idle for more than 5 minutes
        score -= min(idle_time * 0.5, 30)  # Max -30 for idle time

    # Cap score between 0 and 100
    return max(0, min(100, score))

# Security utilities
def detect_suspicious_activity(session, request_data):
    """Detect potentially suspicious activity based on session and request data"""
    suspicious_indicators = []

    # Check for IP address change
    current_ip = get_client_ip(request_data)
    if session.ip_address and current_ip != session.ip_address:
        # Check if the IP change is significant (e.g., different country)
        current_location = get_location_from_ip(current_ip)
        previous_location = get_location_from_ip(session.ip_address)

        if current_location.get('country') != previous_location.get('country'):
            suspicious_indicators.append({
                'type': 'ip_country_change',
                'severity': 'high',
                'details': {
                    'previous_ip': session.ip_address,
                    'current_ip': current_ip,
                    'previous_country': previous_location.get('country'),
                    'current_country': current_location.get('country')
                }
            })
        else:
            suspicious_indicators.append({
                'type': 'ip_change',
                'severity': 'medium',
                'details': {
                    'previous_ip': session.ip_address,
                    'current_ip': current_ip
                }
            })

    # Check for user agent change
    current_ua = request_data.META.get('HTTP_USER_AGENT', '')
    if session.user_agent and current_ua and current_ua != session.user_agent:
        suspicious_indicators.append({
            'type': 'user_agent_change',
            'severity': 'medium',
            'details': {
                'previous_ua': session.user_agent,
                'current_ua': current_ua
            }
        })

    # Check for rapid location changes
    if session.location_history and len(session.location_history) > 1:
        last_location = session.location_history[-1]
        current_location = get_location_from_ip(current_ip)

        # Calculate time difference
        last_time = datetime.fromisoformat(last_location.get('timestamp'))
        current_time = timezone.now()
        time_diff = (current_time - last_time).total_seconds() / 3600  # hours

        # Calculate distance (simplified)
        if last_location.get('latitude') and current_location.get('latitude'):
            # Very simplified distance calculation
            distance = ((last_location.get('latitude') - current_location.get('latitude'))**2 +
                        (last_location.get('longitude') - current_location.get('longitude'))**2)**0.5 * 111  # km

            # Check if physically impossible travel (e.g., > 800 km/h)
            if distance > 0 and time_diff > 0 and (distance / time_diff) > 800:
                suspicious_indicators.append({
                    'type': 'impossible_travel',
                    'severity': 'high',
                    'details': {
                        'distance_km': distance,
                        'time_hours': time_diff,
                        'speed_kmh': distance / time_diff,
                        'previous_location': f"{last_location.get('city')}, {last_location.get('country')}",
                        'current_location': f"{current_location.get('city')}, {current_location.get('country')}"
                    }
                })

    return suspicious_indicators

# Format utilities
def format_duration(seconds):
    """Format duration in seconds to human-readable string"""
    if seconds is None:
        return "N/A"

    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours > 0:
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    elif minutes > 0:
        return f"{int(minutes)}m {int(seconds)}s"
    else:
        return f"{int(seconds)}s"

def format_datetime(dt, format_str='%d-%b-%Y %I:%M:%S %p'):
    """Format datetime to string in IST timezone"""
    if dt is None:
        return "N/A"

    # Convert to IST
    ist_dt = to_ist(dt)
    return ist_dt.strftime(format_str)
