from django.core.mail import send_mail
from django.conf import settings
from .storage import NotificationStorage

class NotificationDelivery:
    def __init__(self):
        self.storage = NotificationStorage()

    def send(self, notifications):
        for note in notifications:
            recipient = note['recipient']
            event = note['event']
            
            # Construct message
            if event.name == 'leave_created':
                subject = f"New Leave Request from {event.actor.get_full_name()}"
                message = f"{event.actor.get_full_name()} has applied for leave."
            elif event.name == 'leave_approved':
                subject = "Leave Approved"
                message = f"Your leave request has been approved by {event.actor.get_full_name()}."
            elif event.name == 'leave_rejected':
                subject = "Leave Rejected"
                message = f"Your leave request has been rejected by {event.actor.get_full_name()}."
            else:
                subject = "Leave Notification"
                message = "You have a new notification."

            # Persist
            self.storage.save(recipient, event, message)

            # Send Email
            if recipient.email:
                try:
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [recipient.email],
                        fail_silently=True
                    )
                except Exception:
                    pass
