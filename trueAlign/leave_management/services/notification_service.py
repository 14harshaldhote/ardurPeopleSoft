from trueAlign.models import Notification
import logging

logger = logging.getLogger(__name__)

def create_notification(recipient, title, message, leave_request, link=None):
    """
    Create a notification record for leave management.
    """
    if not recipient:
        return
        
    try:
        # Generate correct link if not provided
        if not link:
            link = f"/leave_management/request/{leave_request.id}/"
            
        Notification.objects.create(
            recipient=recipient,
            title=title,
            message=message,
            module='leave_management',
            reference_id=str(leave_request.id),
            url=link
        )
        logger.info(f"Leave notification created for {recipient.username}: {title}")
    except Exception as e:
        logger.error(f"Failed to create leave notification: {str(e)}")
