from django import template

register = template.Library()

@register.filter
def lookup(dictionary, key):
    """
    Template filter to lookup a value in a dictionary by key.
    Usage: {{ dictionary|lookup:key }}
    """
    if dictionary and key is not None:
        return dictionary.get(key)
    return None

@register.filter
def get_item(dictionary, key):
    """
    Alternative filter to get item from dictionary.
    Usage: {{ dictionary|get_item:key }}
    """
    return dictionary.get(key) if dictionary else None

@register.filter
def percentage(value, total):
    """
    Calculate percentage of value from total.
    Usage: {{ value|percentage:total }}
    """
    try:
        if total and float(total) > 0:
            return round((float(value) / float(total)) * 100, 1)
        return 0
    except (ValueError, TypeError, ZeroDivisionError):
        return 0

@register.filter
def duration_minutes(duration):
    """
    Convert duration to minutes.
    Usage: {{ duration|duration_minutes }}
    """
    if duration:
        try:
            return round(duration.total_seconds() / 60, 1)
        except AttributeError:
            return duration
    return 0

@register.filter
def session_status_color(session):
    """
    Return CSS color class based on session status.
    Usage: {{ session|session_status_color }}
    """
    if not session.is_active:
        return 'text-red-600'
    elif session.is_idle:
        return 'text-yellow-600'
    else:
        return 'text-green-600'

@register.filter
def security_score_color(score):
    """
    Return CSS color class based on security score.
    Usage: {{ score|security_score_color }}
    """
    try:
        score = float(score)
        if score >= 80:
            return 'text-green-600'
        elif score >= 60:
            return 'text-yellow-600'
        else:
            return 'text-red-600'
    except (ValueError, TypeError):
        return 'text-gray-600'

@register.filter
def device_icon(device_type):
    """
    Return appropriate icon class for device type.
    Usage: {{ device_type|device_icon }}
    """
    if device_type == 'mobile':
        return 'M12 18h.01M8 21h8a1 1 0 001-1V4a1 1 0 00-1-1H8a1 1 0 00-1 1v16a1 1 0 001 1z'
    elif device_type == 'tablet':
        return 'M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z'
    else:
        return 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z'

@register.simple_tag
def active_sessions_count(sessions):
    """
    Count active sessions from a queryset.
    Usage: {% active_sessions_count sessions %}
    """
    if sessions:
        return sessions.filter(is_active=True).count()
    return 0

@register.simple_tag
def idle_sessions_count(sessions):
    """
    Count idle sessions from a queryset.
    Usage: {% idle_sessions_count sessions %}
    """
    if sessions:
        return sessions.filter(is_active=True, is_idle=True).count()
    return 0

@register.inclusion_tag('sessions/partials/session_status_badge.html')
def session_status_badge(session):
    """
    Render a session status badge.
    Usage: {% session_status_badge session %}
    """
    return {'session': session}

@register.inclusion_tag('sessions/partials/security_score_bar.html')
def security_score_bar(score):
    """
    Render a security score progress bar.
    Usage: {% security_score_bar score %}
    """
    return {'score': score}

@register.filter
def format_anomaly_type(anomaly_type):
    """
    Format anomaly type for display.
    Usage: {{ anomaly_type|format_anomaly_type }}
    """
    return anomaly_type.replace('_', ' ').title() if anomaly_type else 'Unknown'

@register.filter
def truncate_session_id(session_id):
    """
    Truncate session ID for display.
    Usage: {{ session_id|truncate_session_id }}
    """
    if session_id:
        return str(session_id)[:8] + '...'
    return 'N/A'

@register.filter
def user_initials(user):
    """
    Get user initials for avatar.
    Usage: {{ user|user_initials }}
    """
    if user.first_name and user.last_name:
        return f"{user.first_name[0]}{user.last_name[0]}".upper()
    elif user.first_name:
        return user.first_name[0].upper()
    else:
        return user.username[0].upper() if user.username else 'U'

@register.filter
def format_location(session):
    """
    Format location string for session.
    Usage: {{ session|format_location }}
    """
    parts = []
    if session.location_city:
        parts.append(session.location_city)
    if session.location_country:
        parts.append(session.location_country)

    if parts:
        location = ', '.join(parts)
        if session.location_type:
            location += f" ({session.location_type.title()})"
        return location
    return 'Unknown Location'

@register.filter
def session_duration_display(session):
    """
    Display session duration in a human-readable format.
    Usage: {{ session|session_duration_display }}
    """
    if session.ended_at:
        duration = session.ended_at - session.created_at
    else:
        from django.utils import timezone
        duration = timezone.now() - session.created_at

    total_seconds = int(duration.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60

    if hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

@register.filter
def activity_level(session):
    """
    Determine activity level based on session data.
    Usage: {{ session|activity_level }}
    """
    if not session.is_active:
        return 'ended'
    elif session.is_idle:
        return 'idle'
    elif hasattr(session, 'last_activity'):
        from django.utils import timezone
        minutes_since_activity = (timezone.now() - session.last_activity).total_seconds() / 60
        if minutes_since_activity < 5:
            return 'very-active'
        elif minutes_since_activity < 15:
            return 'active'
        else:
            return 'low-activity'
    return 'unknown'
