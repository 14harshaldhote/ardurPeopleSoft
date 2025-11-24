import os
import django
import sys
from datetime import datetime

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from trueAlign.models import Support, Notification
from trueAlign.support.events import dispatch_event
from trueAlign.support.rules import NOTIFICATION_RULES

def setup_users():
    """Create or get test users"""
    print("\n[SETUP] Setting up users...")
    
    # Create testAdmin (Superuser/Admin)
    admin, _ = User.objects.get_or_create(username='testAdmin')
    if not admin.is_superuser:
        admin.is_superuser = True
        admin.is_staff = True
        admin.save()
    print(f"User: {admin.username} (Admin)")

    # Create testHR (Manager/Agent)
    hr, _ = User.objects.get_or_create(username='testHR')
    # Ensure HR is in 'Support Lead' group for testing high priority notifications if needed
    # But rules.py checks for 'Support Lead' group or superuser. 
    # Let's make testAdmin the superuser who gets high priority alerts.
    # Let's make testHR just a regular user who acts as an agent/assignee.
    print(f"User: {hr.username} (HR/Agent)")

    # Create testEmployee (Standard User/Ticket Owner)
    emp, _ = User.objects.get_or_create(username='testEmployee')
    print(f"User: {emp.username} (Employee)")
    
    # Setup Groups for testing
    support_lead_group, _ = Group.objects.get_or_create(name='Support Lead')
    escalation_group, _ = Group.objects.get_or_create(name='Escalation Manager')
    
    support_lead_group.user_set.add(admin)
    escalation_group.user_set.add(admin)
    
    return admin, hr, emp

def clear_notifications(users):
    """Clear existing notifications for test users"""
    print("\n[SETUP] Clearing notifications...")
    Notification.objects.filter(recipient__in=users).delete()

def verify_notification(recipient, title_contains, expected=True):
    """Verify if a notification exists for the recipient"""
    notifs = Notification.objects.filter(
        recipient=recipient,
        title__icontains=title_contains,
        read=False
    ).order_by('-timestamp')
    
    exists = notifs.exists()
    
    if expected:
        if exists:
            print(f"  [PASS] Notification found for {recipient.username}: '{notifs.first().title}'")
            return True
        else:
            print(f"  [FAIL] Expected notification for {recipient.username} containing '{title_contains}' NOT FOUND")
            return False
    else:
        if not exists:
            print(f"  [PASS] No notification found for {recipient.username} (As expected)")
            return True
        else:
            print(f"  [FAIL] Unexpected notification found for {recipient.username}: '{notifs.first().title}'")
            return False

def run_tests():
    admin, hr, emp = setup_users()
    users = [admin, hr, emp]
    
    print("\n=== STARTING NOTIFICATION TESTS ===")
    
    # --- TEST 1: Ticket Created (Standard Priority) ---
    print("\n--- Test 1: Ticket Created (Standard Priority) ---")
    clear_notifications(users)
    
    ticket1 = Support.objects.create(
        ticket_id=f"TKT-{int(datetime.now().timestamp())}-1",
        user=emp,
        subject="Standard Issue",
        description="This is a standard issue",
        priority=Support.Priority.MEDIUM,
        issue_type=Support.IssueType.SOFTWARE,
        status=Support.Status.NEW
    )
    
    # Event: ticket_created
    dispatch_event('ticket_created', ticket1, emp)
    
    # Verify: No one assigned, so no assignee notification.
    # Priority Medium, so no lead notification.
    verify_notification(emp, "Created", expected=False)
    verify_notification(admin, "High Priority", expected=False)
    verify_notification(hr, "Assigned", expected=False)

    # --- TEST 2: Ticket Created (High Priority) ---
    print("\n--- Test 2: Ticket Created (High Priority) ---")
    clear_notifications(users)
    
    ticket2 = Support.objects.create(
        ticket_id=f"TKT-{int(datetime.now().timestamp())}-2",
        user=emp,
        subject="Critical Issue",
        description="System is down",
        priority=Support.Priority.CRITICAL,
        issue_type=Support.IssueType.SECURITY,
        status=Support.Status.NEW
    )
    
    # Event: ticket_created
    dispatch_event('ticket_created', ticket2, emp)
    
    # Verify: Admin (Superuser) should get High Priority notification
    verify_notification(admin, "High Priority", expected=True)
    verify_notification(emp, "Created", expected=False)

    # --- TEST 3: Ticket Assigned ---
    print("\n--- Test 3: Ticket Assigned ---")
    clear_notifications(users)
    
    # Assign ticket1 to HR
    ticket1.assigned_to_user = hr
    ticket1.save()
    
    # Event: ticket_assigned (Actor: Admin)
    dispatch_event('ticket_assigned', ticket1, admin)
    
    # Verify: HR gets assigned notification
    verify_notification(hr, "Ticket Assigned", expected=True)
    # Verify: Employee (Owner) does NOT get notification for assignment (based on rules)
    verify_notification(emp, "Assigned", expected=False)

    # --- TEST 4: Ticket Reassigned ---
    print("\n--- Test 4: Ticket Reassigned ---")
    clear_notifications(users)
    
    old_assignee = hr
    new_assignee = admin
    
    ticket1.assigned_to_user = new_assignee
    ticket1.save()
    
    # Event: ticket_reassigned (Actor: HR reassigns to Admin)
    dispatch_event('ticket_reassigned', ticket1, hr, old_assignee=old_assignee)
    
    # Verify: New Assignee (Admin) gets notified
    verify_notification(admin, "Ticket Reassigned", expected=True)
    # Verify: Old Assignee (HR) gets notified (if not actor, but HR IS actor here)
    # Wait, if HR reassigns, HR is actor. Rule: "if old_assignee and old_assignee != actor".
    # So HR should NOT get notified.
    verify_notification(hr, "Ticket Unassigned", expected=False)
    
    # Let's try Admin reassigning back to HR to test "Old Assignee" notification
    print("  (Sub-test: Admin reassigns back to HR)")
    clear_notifications(users)
    ticket1.assigned_to_user = hr
    ticket1.save()
    dispatch_event('ticket_reassigned', ticket1, admin, old_assignee=admin) # Admin is old assignee and actor
    
    # Let's try a third party reassigning.
    # Or just verify HR gets "Reassigned" notification
    verify_notification(hr, "Ticket Reassigned", expected=True)

    # --- TEST 5: Status Changed ---
    print("\n--- Test 5: Ticket Status Changed ---")
    clear_notifications(users)
    
    ticket1.status = Support.Status.IN_PROGRESS
    ticket1.save()
    
    # Event: ticket_status_changed (Actor: HR)
    dispatch_event('ticket_status_changed', ticket1, hr, old_status=Support.Status.NEW)
    
    # Verify: Owner (Employee) gets notified
    verify_notification(emp, "Ticket Updated", expected=True)
    # Verify: Assignee (HR) does not get notified (is actor)
    verify_notification(hr, "Status Changed", expected=False)

    # --- TEST 6: Comment Added (Public) ---
    print("\n--- Test 6: Comment Added (Public) ---")
    clear_notifications(users)
    
    # Case A: Agent (HR) comments
    dispatch_event('ticket_comment_added', ticket1, hr, is_internal=False)
    # Verify: Owner (Employee) gets notified
    verify_notification(emp, "New Comment", expected=True)
    
    # Case B: Owner (Employee) comments
    clear_notifications(users)
    dispatch_event('ticket_comment_added', ticket1, emp, is_internal=False)
    # Verify: Assignee (HR) gets notified
    verify_notification(hr, "New Comment", expected=True)

    # --- TEST 7: Comment Added (Internal) ---
    print("\n--- Test 7: Comment Added (Internal) ---")
    clear_notifications(users)
    
    # Admin adds internal note
    dispatch_event('ticket_comment_added', ticket1, admin, is_internal=True)
    
    # Verify: Assignee (HR) gets notified
    verify_notification(hr, "Internal Note", expected=True)
    # Verify: Owner (Employee) does NOT get notified
    verify_notification(emp, "New Comment", expected=False)
    verify_notification(emp, "Internal Note", expected=False)

    # --- TEST 8: Ticket Escalated ---
    print("\n--- Test 8: Ticket Escalated ---")
    clear_notifications(users)
    
    # HR escalates ticket
    ticket1.priority = Support.Priority.HIGH
    ticket1.escalation_level = 1
    ticket1.save()
    
    # Event: ticket_escalated (Actor: HR)
    dispatch_event('ticket_escalated', ticket1, hr, reason="Too complex")
    
    # Verify: Managers (Admin) get notified
    verify_notification(admin, "Ticket Escalated", expected=True)
    # Verify: Owner (Employee) gets notified
    verify_notification(emp, "Ticket Escalated", expected=True)
    # Verify: Assignee (HR) does not get notified (is actor)
    verify_notification(hr, "Ticket Escalated", expected=False)

    # --- TEST 9: HR as Assignee Actions ---
    print("\n--- Test 9: HR as Assignee Actions ---")
    clear_notifications(users)
    
    # Setup: Create a new ticket assigned to HR
    ticket3 = Support.objects.create(
        ticket_id=f"TKT-{int(datetime.now().timestamp())}-3",
        user=emp,
        subject="HR Assignee Test",
        description="Testing HR actions",
        priority=Support.Priority.MEDIUM,
        issue_type=Support.IssueType.SOFTWARE,
        status=Support.Status.OPEN,
        assigned_to_user=hr
    )
    
    # Action 1: HR comments on the ticket
    print("  (Action 1: HR comments)")
    dispatch_event('ticket_comment_added', ticket3, hr, is_internal=False)
    
    # Verify: Owner (Employee) gets notified
    verify_notification(emp, "New Comment", expected=True)
    # Verify: Admin (Manager) does NOT get notified (unless watching, which is not implemented)
    verify_notification(admin, "New Comment", expected=False)
    
    # Action 2: HR resolves the ticket
    print("  (Action 2: HR resolves ticket)")
    clear_notifications(users)
    ticket3.status = Support.Status.RESOLVED
    ticket3.save()
    dispatch_event('ticket_status_changed', ticket3, hr, old_status=Support.Status.OPEN)
    
    # Verify: Owner (Employee) gets notified
    verify_notification(emp, "Ticket Updated", expected=True)
    
    # Action 3: HR escalates ticket back to Admin
    print("  (Action 3: HR escalates to Admin)")
    clear_notifications(users)
    ticket3.priority = Support.Priority.HIGH
    ticket3.escalation_level = 1
    ticket3.save()
    dispatch_event('ticket_escalated', ticket3, hr, reason="Escalating to Admin")
    
    # Verify: Admin (Manager) gets notified
    verify_notification(admin, "Ticket Escalated", expected=True)
    # Verify: Owner (Employee) gets notified
    verify_notification(emp, "Ticket Escalated", expected=True)

    print("\n=== ALL TESTS COMPLETED ===")

if __name__ == "__main__":
    run_tests()
