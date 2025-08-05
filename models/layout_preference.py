from django.db import models
from django.contrib.auth.models import User
from django.contrib.postgres.fields import JSONField

class LayoutPreference(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    layout = JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Layout Preference"
