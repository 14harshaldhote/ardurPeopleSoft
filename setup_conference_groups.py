#!/usr/bin/env python
"""
Setup script for Conference Room Booking System Groups.
Creates required Django groups for permission management.

Usage:
    python setup_conference_groups.py
"""

import os
import sys
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from trueAlign.models import ConferenceRoom, RoomBooking


def create_groups():
    """Create Admin and HR groups for conference room management."""
    print("🚀 Setting up Conference Room Booking System Groups")
    print("=" * 60)
    
    # Get content types for permissions
    conference_room_ct = ContentType.objects.get_for_model(ConferenceRoom)
    room_booking_ct = ContentType.objects.get_for_model(RoomBooking)
    
    # Define permissions for room management
    room_permissions = Permission.objects.filter(content_type=conference_room_ct)
    booking_permissions = Permission.objects.filter(content_type=room_booking_ct)
    
    # Create Admin Group
    print("\n📋 Creating Admin Group...")
    admin_group, created = Group.objects.get_or_create(name='Admin')
    
    if created:
        print("✓ Admin group created successfully")
    else:
        print("✓ Admin group already exists")
    
    # Add all conference room and booking permissions to Admin
    admin_group.permissions.add(*room_permissions)
    admin_group.permissions.add(*booking_permissions)
    print(f"✓ Assigned {room_permissions.count() + booking_permissions.count()} permissions to Admin group")
    
    # Create HR Group
    print("\n📋 Creating HR Group...")
    hr_group, created = Group.objects.get_or_create(name='HR')
    
    if created:
        print("✓ HR group created successfully")
    else:
        print("✓ HR group already exists")
    
    # Add all conference room and booking permissions to HR
    hr_group.permissions.add(*room_permissions)
    hr_group.permissions.add(*booking_permissions)
    print(f"✓ Assigned {room_permissions.count() + booking_permissions.count()} permissions to HR group")
    
    # Create other common groups (optional)
    print("\n📋 Creating additional groups...")
    
    groups_to_create = ['Manager', 'Employee', 'User']
    for group_name in groups_to_create:
        group, created = Group.objects.get_or_create(name=group_name)
        if created:
            print(f"✓ {group_name} group created")
        else:
            print(f"✓ {group_name} group already exists")
        
        # Employees can view and create bookings
        if group_name in ['Employee', 'User', 'Manager']:
            # Add view permissions for rooms
            view_room = Permission.objects.get(
                codename='view_conferenceroom',
                content_type=conference_room_ct
            )
            group.permissions.add(view_room)
            
            # Add booking permissions (view, add, change own)
            booking_perms = Permission.objects.filter(
                content_type=room_booking_ct,
                codename__in=['view_roombooking', 'add_roombooking', 'change_roombooking', 'delete_roombooking']
            )
            group.permissions.add(*booking_perms)
            print(f"  → Assigned booking permissions to {group_name}")
    
    print("\n" + "=" * 60)
    print("✅ Group setup completed successfully!")
    print("\nGroups created:")
    print("  • Admin - Full conference room management")
    print("  • HR - Full conference room management")
    print("  • Manager - Can book rooms")
    print("  • Employee - Can book rooms")
    print("  • User - Can book rooms")
    
    print("\n📝 Next steps:")
    print("1. Assign users to groups via Django admin:")
    print("   → Go to /admin/auth/user/")
    print("   → Select user → Add to group → Save")
    print("\n2. Or use Django shell:")
    print("   python manage.py shell")
    print("   >>> from django.contrib.auth import get_user_model")
    print("   >>> from django.contrib.auth.models import Group")
    print("   >>> User = get_user_model()")
    print("   >>> user = User.objects.get(username='your_username')")
    print("   >>> admin_group = Group.objects.get(name='Admin')")
    print("   >>> user.groups.add(admin_group)")
    print("\n3. Test permissions:")
    print("   → Admin/HR users can access /conference/admin/rooms/")
    print("   → All users can access /conference/rooms/ and book")
    

def list_current_groups():
    """List all existing groups and their permissions."""
    print("\n" + "=" * 60)
    print("📊 Current Groups and Permissions")
    print("=" * 60)
    
    groups = Group.objects.all()
    for group in groups:
        print(f"\n{group.name}:")
        perms = group.permissions.all()
        if perms.exists():
            for perm in perms:
                print(f"  • {perm.codename}")
        else:
            print("  (No permissions assigned)")
        
        # Show users in this group
        users = group.user_set.all()
        if users.exists():
            print(f"  Users: {', '.join([u.username for u in users])}")
        else:
            print("  Users: (None)")


if __name__ == '__main__':
    try:
        create_groups()
        list_current_groups()
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
