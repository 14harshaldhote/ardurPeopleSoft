import os
import django
import json
from django.test import RequestFactory
from django.contrib.auth import get_user_model

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import Support, Notification
from trueAlign.notifications.views import get_notifications

User = get_user_model()

def test_notifications():
    print("Setting up test data...")
    # Create users
    user1 = User.objects.get(username='testEmployee')
    user2 = User.objects.get(username='testAdmin')
    # Create a ticket assigned to user2
    print("Creating ticket...")
    ticket = Support.objects.create(
        user=user1,
        subject="Test Ticket for Notification",
        description="This is a test ticket",
        assigned_to_user=user2,
        issue_type=Support.IssueType.SOFTWARE
    )
    
    # Check if notification was created for user2
    print("Checking for notifications...")
    notifications = Notification.objects.filter(recipient=user2, reference_id=str(ticket.id))
    
    if notifications.exists():
        print(f"SUCCESS: Notification created for user2. Count: {notifications.count()}")
        n = notifications.first()
        print(f"Title: {n.title}")
        print(f"Message: {n.message}")
    else:
        print("FAILURE: No notification created for user2")
        
    # Test API
    print("Testing API...")
    factory = RequestFactory()
    request = factory.get('/notifications/api/notifications/')
    request.user = user2
    
    response = get_notifications(request)
    data = json.loads(response.content)
    
    if data['unread_count'] > 0:
        print(f"SUCCESS: API returned {data['unread_count']} unread notifications")
        print("Notifications:", data['notifications'])
    else:
        print("FAILURE: API returned 0 unread notifications")

if __name__ == "__main__":
    try:
        test_notifications()
    except Exception as e:
        print(f"ERROR: {e}")
