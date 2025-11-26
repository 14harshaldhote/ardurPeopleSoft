from trueAlign.models import Notification

class NotificationStorage:
    def save(self, recipient, event, message):
        Notification.objects.create(
            recipient=recipient,
            title=event.name.replace('_', ' ').title(),
            message=message,
            module='leave',
            reference_id=str(event.payload['leave_request'].id)
        )
