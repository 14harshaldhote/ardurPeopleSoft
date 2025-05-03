from django.utils import timezone
from datetime import timedelta
from .models import UserSession
import logging

# Set up logging
logger = logging.getLogger(__name__)

class IdleTimeTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only process authenticated users
        if request.user.is_authenticated:
            # Skip certain paths to avoid unnecessary processing
            if not request.path.startswith(('/static/', '/media/', '/update-last-activity/', '/end-session/')):
                try:
                    # Get client IP
                    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                    ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
                    user_agent = request.META.get('HTTP_USER_AGENT')

                    # Get or initialize session
                    user_session = UserSession.objects.filter(
                        user=request.user,
                        is_active=True
                    ).first()

                    if user_session:
                        current_time = timezone.now()
                        
                        # Check if session has timed out (5 minutes)
                        if (current_time - user_session.last_activity) > timedelta(minutes=5):
                            # End the session and create a new one
                            user_session.end_session()
                            UserSession.get_or_create_session(
                                user=request.user,
                                session_key=request.session.session_key,
                                ip_address=ip_address,
                                user_agent=user_agent
                            )
                        else:
                            # IMPORTANT: Don't update activity here as it resets idle time
                            # Only update IP if changed
                            if user_session.ip_address != ip_address:
                                user_session.ip_address = ip_address
                                user_session.location = user_session.determine_location()
                                user_session.save(update_fields=['ip_address', 'location'])
                    else:
                        # Create a new session if none exists
                        UserSession.get_or_create_session(
                            user=request.user,
                            session_key=request.session.session_key,
                            ip_address=ip_address,
                            user_agent=user_agent
                        )
                        
                except Exception as e:
                    logger.error(f"Error in idle tracking middleware: {str(e)}")

        response = self.get_response(request)
        return response