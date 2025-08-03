from django.db import models
from django.contrib.auth.models import User

class Notification(models.Model):
    """A notification model to store system notifications for users"""

    TYPE_CHOICES = [
        ('EMAIL', 'Email'),
        ('BROWSER', 'Browser'),
        ('SMS', 'SMS'),
        ('SYSTEM', 'System'),
    ]

    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='system_notifications')
    type = models.CharField(choices=TYPE_CHOICES, max_length=10)
    title = models.CharField(max_length=255)
    message = models.TextField()
    read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=100, null=True, blank=True)
    event_reference_id = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.type} Notification to {self.recipient}: {self.title}"
