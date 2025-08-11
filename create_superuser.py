#!/usr/bin/env python
"""
Create Django Superuser Script
=============================

This script creates a Django superuser for accessing the admin interface.
Run this script to create an admin user that can access /admin/

Usage:
    python create_superuser.py
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User

def create_superuser():
    """Create a superuser with predefined credentials"""

    # Superuser credentials
    username = 'admin'
    email = 'admin@truealign.com'
    password = 'admin123'  # Change this to a secure password

    print("Creating Django Superuser...")
    print("=" * 40)

    try:
        # Check if superuser already exists
        if User.objects.filter(username=username).exists():
            user = User.objects.get(username=username)
            print(f"✓ Superuser '{username}' already exists!")

            # Make sure they are superuser and staff
            if not user.is_superuser or not user.is_staff:
                user.is_superuser = True
                user.is_staff = True
                user.save()
                print("✓ Updated user permissions to superuser")

            print(f"📧 Email: {user.email}")
            print(f"🔐 Password: Use existing password or reset if needed")

        else:
            # Create new superuser
            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password
            )
            print(f"✓ Superuser '{username}' created successfully!")
            print(f"📧 Email: {email}")
            print(f"🔐 Password: {password}")

        print("\n" + "=" * 40)
        print("ADMIN ACCESS INFORMATION")
        print("=" * 40)
        print(f"URL: http://127.0.0.1:8000/admin/")
        print(f"Username: {username}")
        print(f"Password: {'[existing]' if User.objects.filter(username=username).exists() else password}")
        print("\n🚨 SECURITY NOTE: Change the default password after first login!")

        # Also check for other admin users
        other_admins = User.objects.filter(is_superuser=True).exclude(username=username)
        if other_admins.exists():
            print(f"\nOther admin users found: {', '.join([u.username for u in other_admins])}")

        return True

    except Exception as e:
        print(f"❌ Error creating superuser: {e}")
        return False

def create_additional_users():
    """Create some test users for different roles"""

    print("\n" + "=" * 40)
    print("CREATING TEST USERS")
    print("=" * 40)

    # Get or create groups
    from django.contrib.auth.models import Group

    groups_data = [
        ('ADMIN', 'Administrator'),
        ('HR', 'Human Resources'),
        ('MANAGER', 'Manager'),
        ('EMPLOYEE', 'Employee'),
    ]

    for group_name, description in groups_data:
        group, created = Group.objects.get_or_create(name=group_name)
        if created:
            print(f"✓ Created group: {group_name}")

    # Create test users
    test_users = [
        {
            'username': 'hr_admin',
            'email': 'hr@truealign.com',
            'password': 'hr123',
            'first_name': 'HR',
            'last_name': 'Admin',
            'groups': ['HR'],
            'is_staff': True
        },
        {
            'username': 'manager1
