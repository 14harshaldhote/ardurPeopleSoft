from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta
from trueAlign.models import UserSession
import json
from django.db.models import F
import logging

# Set up logging
logger = logging.getLogger(__name__)

class IdleTimeTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Get client IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

            # Get or create user session
            user_session = UserSession.objects.filter(
                user=request.user,
                session_key=request.session.session_key,
                logout_time__isnull=True
            ).last()

            if user_session:
                current_time = timezone.now()
                
                # Calculate idle time
                idle_duration = current_time - user_session.last_activity
                if idle_duration > timedelta(minutes=1):
                    user_session.idle_time += idle_duration
                
                # Update session
                if not request.path.startswith(('/static/', '/media/', '/update-last-activity/')):
                    user_session.last_activity = current_time
                    
                    # Update IP address if it's changed
                    if user_session.ip_address != ip_address:
                        user_session.ip_address = ip_address
                        
                    user_session.save(update_fields=['last_activity', 'idle_time', 'ip_address'])

        response = self.get_response(request)
        return response

@csrf_exempt
def update_last_activity(request):
    if request.method == 'POST' and request.user.is_authenticated:
        try:
            data = json.loads(request.body)
            user_session = UserSession.objects.filter(
                user=request.user,
                session_key=request.session.session_key,
                logout_time__isnull=True
            ).last()

            if user_session:
                current_time = timezone.now()
                
                # Calculate idle time since last activity
                idle_duration = current_time - user_session.last_activity
                if idle_duration > timedelta(minutes=1):
                    user_session.idle_time += idle_duration
                
                user_session.last_activity = current_time
                
                # Update IP address if it's different from the stored value
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
                
                if user_session.ip_address != ip_address:
                    user_session.ip_address = ip_address
                
                # Using atomic update for concurrency control
                user_session.save(update_fields=['last_activity', 'idle_time', 'ip_address'])
                
                return JsonResponse({
                    'status': 'success',
                    'last_activity': current_time.isoformat(),
                    'idle_time': str(user_session.idle_time)
                })

            return JsonResponse({'status': 'error', 'message': 'No active session'}, status=404)

        except Exception as e:
            logger.error(f"Error updating last activity: {str(e)}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
