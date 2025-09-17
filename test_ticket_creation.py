#!/usr/bin/env python
"""
Test script to debug ticket creation issues
Run with: python test_ticket_creation.py
"""

import os
import sys
import django

# Setup Django environment
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User
from trueAlign.models import Support, TicketComment, TicketAttachment, TicketActivity
from trueAlign.support.services import SupportTicketService
from trueAlign.support.forms import TicketCreateForm
from django.test import RequestFactory
from django.contrib.messages.storage.fallback import FallbackStorage
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_model_creation():
    """Test direct model creation"""
    print("\n" + "="*50)
    print("TESTING DIRECT MODEL CREATION")
    print("="*50)

    try:
        # Get a test user
        user = User.objects.first()
        if not user:
            print("❌ No users found in database")
            return False

        print(f"✅ Found test user: {user.username}")

        # Test direct Support model creation
        ticket = Support.objects.create(
            user=user,
            issue_type=Support.IssueType.SOFTWARE,
            subject="Test Ticket Direct Creation",
            description="This is a test ticket created directly via model",
            priority=Support.Priority.MEDIUM,
            location="Test Location",
            asset_id="TEST001"
        )

        print(f"✅ Direct model creation successful!")
        print(f"   Ticket ID: {ticket.ticket_id}")
        print(f"   Status: {ticket.status}")
        print(f"   Priority: {ticket.priority}")
        print(f"   Created at: {ticket.created_at}")

        return True

    except Exception as e:
        print(f"❌ Direct model creation failed: {str(e)}")
        logger.exception("Direct model creation error:")
        return False

def test_service_creation():
    """Test SupportTicketService.create_ticket"""
    print("\n" + "="*50)
    print("TESTING SERVICE LAYER CREATION")
    print("="*50)

    try:
        # Get a test user
        user = User.objects.first()
        if not user:
            print("❌ No users found in database")
            return False

        ticket_data = {
            'issue_type': Support.IssueType.NETWORK,
            'subject': 'Test Ticket Service Creation',
            'description': 'This is a test ticket created via SupportTicketService',
            'priority': Support.Priority.HIGH,
            'location': 'Service Test Location',
            'asset_id': 'SRV001',
        }

        print(f"Creating ticket via service for user: {user.username}")
        print(f"Ticket data: {ticket_data}")

        ticket = SupportTicketService.create_ticket(
            user=user,
            ticket_data=ticket_data
        )

        print(f"✅ Service creation successful!")
        print(f"   Ticket ID: {ticket.ticket_id}")
        print(f"   Status: {ticket.status}")
        print(f"   Priority: {ticket.priority}")
        print(f"   User: {ticket.user}")

        return True

    except Exception as e:
        print(f"❌ Service creation failed: {str(e)}")
        logger.exception("Service creation error:")
        return False

def test_form_validation():
    """Test TicketCreateForm validation"""
    print("\n" + "="*50)
    print("TESTING FORM VALIDATION")
    print("="*50)

    try:
        # Test valid form data
        form_data = {
            'issue_type': Support.IssueType.APPLICATION,
            'subject': 'Test Form Validation Ticket',
            'description': 'This is a test description for form validation with enough characters',
            'priority': Support.Priority.MEDIUM,
            'location': 'Form Test Location',
            'asset_id': 'FORM001',
        }

        print("Testing form with valid data:")
        for key, value in form_data.items():
            print(f"  {key}: {value}")

        form = TicketCreateForm(data
=form_data)

        if form.is_valid():
            print("✅ Form validation successful!")
            print("   Cleaned data:")
            for key, value in form.cleaned_data.items():
                print(f"     {key}: {value}")
            return True
        else:
            print("❌ Form validation failed!")
            print("   Errors:")
            for field, errors in form.errors.items():
                print(f"     {field}: {errors}")
            return False

    except Exception as e:
        print(f"❌ Form validation test failed: {str(e)}")
        logger.exception("Form validation error:")
        return False

def test_view_simulation():
    """Simulate the view process"""
    print("\n" + "="*50)
    print("TESTING VIEW SIMULATION")
    print("="*50)

    try:
        from trueAlign.support.views import TicketCreateView

        # Get a test user
        user = User.objects.first()
        if not user:
            print("❌ No users found in database")
            return False

        # Create a mock request
        factory = RequestFactory()
        request = factory.post('/support/create/', {
            'issue_type': Support.IssueType.SECURITY,
            'subject': 'Test View Simulation Ticket',
            'description': 'This is a test description for view simulation with sufficient characters',
            'priority': Support.Priority.CRITICAL,
            'location': 'View Test Location',
            'asset_id': 'VIEW001',
        })
        request.user = user

        # Add messages framework
        setattr(request, 'session', {})
        setattr(request, '_messages', FallbackStorage(request))

        print("Simulating POST request to TicketCreateView...")

        view = TicketCreateView()
        view.request = request

        # Test form creation
        form_class = view.get_form_class()
        form = form_class(request.POST)

        print(f"Form class: {form_class}")
        print(f"Form data: {request.POST}")
        print(f"Form is valid: {form.is_valid()}")

        if not form.is_valid():
            print("Form errors:")
            for field, errors in form.errors.items():
                print(f"  {field}: {errors}")
            return False

        # Try to call form_valid
        response = view.form_valid(form)
        print(f"✅ View simulation successful!")
        print(f"   Response type: {type(response)}")

        return True

    except Exception as e:
        print(f"❌ View simulation failed: {str(e)}")
        logger.exception("View simulation error:")
        return False

def check_dependencies():
    """Check required dependencies and model structure"""
    print("\n" + "="*50)
    print("CHECKING DEPENDENCIES AND MODEL STRUCTURE")
    print("="*50)

    try:
        # Check if Support model has required methods
        support_methods = dir(Support)
        required_methods = ['save', '__str__']

        print("Support model methods check:")
        for method in required_methods:
            if method in support_methods:
                print(f"  ✅ {method}: Present")
            else:
                print(f"  ❌ {method}: Missing")

        # Check Support model fields
        support_fields = [f.name for f in Support._meta.fields]
        required_fields = ['ticket_id', 'user', 'issue_type', 'subject', 'description', 'status', 'priority']

        print("\nSupport model fields check:")
        for field in required_fields:
            if field in support_fields:
                print(f"  ✅ {field}: Present")
            else:
                print(f"  ❌ {field}: Missing")

        # Check related models
        print("\nRelated models check:")
        try:
            TicketComment._meta
            print("  ✅ TicketComment: Available")
        except:
            print("  ❌ TicketComment: Missing")

        try:
            TicketAttachment._meta
            print("  ✅ TicketAttachment: Available")
        except:
            print("  ❌ TicketAttachment: Missing")

        try:
            TicketActivity._meta
            print("  ✅ TicketActivity: Available")
        except:
            print("  ❌ TicketActivity: Missing")

        return True

    except Exception as e:
        print(f"❌ Dependency check failed: {str(e)}")
        logger.exception("Dependency check error:")
        return False

def main():
    """Main test function"""
    print("SUPPORT TICKET CREATION DEBUG TOOL")
    print("=" * 50)

    test_results = []

    # Run all tests
    test_results.append(("Dependency Check", check_dependencies()))
    test_results.append(("Direct Model Creation", test_model_creation()))
    test_results.append(("Service Layer Creation", test_service_creation()))
    test_results.append(("Form Validation", test_form_validation()))
    test_results.append(("View Simulation", test_view_simulation()))

    # Summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)

    passed = 0
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1

    print(f"\nOverall: {passed}/{len(test_results)} tests passed")

    if passed == len(test_results):
        print("🎉 All tests passed! Ticket creation should work.")
    else:
        print("⚠️  Some tests failed. Check the errors above for details.")

if __name__ == "__main__":
    main()
