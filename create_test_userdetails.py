#!/usr/bin/env python
"""
Test script to create UserDetails records for existing users
Run with: python manage.py shell < create_test_userdetails.py
"""

import os
import sys
import django
from datetime import date, timedelta
import random

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User
from trueAlign.models import UserDetails, OfficeLocation

def create_test_userdetails():
    """Create UserDetails for existing users without UserDetails"""

    # Get all users who don't have UserDetails
    users_without_details = User.objects.exclude(id__in=UserDetails.objects.values_list('user_id', flat=True))

    print(f"Found {users_without_details.count()} users without UserDetails")

    # Get available office locations
    office_locations = list(OfficeLocation.objects.all())
    if not office_locations:
        print("No office locations found. Creating default ones...")
        # Create default locations if none exist
        default_locations = [
            {'name': 'Pune', 'code': 'PUN'},
            {'name': 'Betul', 'code': 'BET'},
            {'name': 'Mumbai - Bandra', 'code': 'MUM'},
        ]
        for loc_data in default_locations:
            location, created = OfficeLocation.objects.get_or_create(
                name=loc_data['name'],
                defaults={
                    'code': loc_data['code'],
                    'address_line1': f"Address for {loc_data['name']}",
                    'city': loc_data['name'].split(' - ')[0] if ' - ' in loc_data['name'] else loc_data['name'],
                    'state': 'Maharashtra' if 'Mumbai' in loc_data['name'] or 'Pune' in loc_data['name'] else 'Madhya Pradesh',
                    'country': 'India',
                    'postal_code': '411001',
                    'is_active': True,
                }
            )
            office_locations.append(location)
            if created:
                print(f"Created office location: {location.name}")

    # Employment statuses to choose from
    employment_statuses = ['active', 'active', 'active', 'probation', 'inactive']  # More active users
    employee_types = ['full_time', 'full_time', 'part_time', 'contract', 'intern']
    blood_groups = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
    genders = ['male', 'female', 'other']
    marital_statuses = ['single', 'married', 'divorced', 'widowed']

    created_count = 0

    for user in users_without_details:
        try:
            # Generate realistic data
            hire_date = date.today() - timedelta(days=random.randint(30, 1095))  # 1 month to 3 years ago
            start_date = hire_date + timedelta(days=random.randint(0, 14))  # Start within 2 weeks of hire

            user_details = UserDetails.objects.create(
                user=user,
                # Personal Information
                dob=date(1990, random.randint(1, 12), random.randint(1, 28)),
                blood_group=random.choice(blood_groups),
                gender=random.choice(genders),
                marital_status=random.choice(marital_statuses),

                # Contact Information
                contact_number_primary=f"+91{random.randint(7000000000, 9999999999)}",
                personal_email=f"{user.username.lower()}@personal.com",
                company_email=f"{user.username.lower()}@ardurtechnology.com",

                # Address Information (Current)
                current_address_line1=f"Address {random.randint(1, 999)}, Street {random.randint(1, 50)}",
                current_city=random.choice(['Pune', 'Mumbai', 'Betul', 'Delhi', 'Bangalore']),
                current_state=random.choice(['Maharashtra', 'Madhya Pradesh', 'Delhi', 'Karnataka']),
                current_postal_code=f"{random.randint(400000, 600000)}",
                current_country='India',

                # Emergency Contact
                emergency_contact_name=f"Emergency Contact for {user.first_name}",
                emergency_contact_number=f"+91{random.randint(7000000000, 9999999999)}",
                emergency_contact_relationship=random.choice(['parent', 'spouse', 'sibling', 'friend']),

                # Employment Information
                employee_type=random.choice(employee_types),
                hire_date=hire_date,
                start_date=start_date,
                probation_end_date=start_date + timedelta(days=90) if random.choice([True, False]) else None,
                notice_period_days=random.choice([30, 60, 90]),
                job_description=f"{random.choice(['Software Engineer', 'Data Analyst', 'Project Manager', 'Designer', 'QA Engineer', 'DevOps Engineer', 'Business Analyst'])} - {random.choice(['Frontend', 'Backend', 'Full Stack', 'Mobile', 'Cloud', 'AI/ML'])}",
                office_location=random.choice(office_locations),
                employment_status=random.choice(employment_statuses),

                # System fields
                is_current_same_as_permanent=random.choice([True, False]),
                onboarded_by=User.objects.filter(is_superuser=True).first() or user,
            )

            # If permanent address is different, fill it
            if not user_details.is_current_same_as_permanent:
                user_details.permanent_address_line1 = f"Permanent Address {random.randint(1, 999)}"
                user_details.permanent_city = random.choice(['Pune', 'Mumbai', 'Nagpur', 'Indore'])
                user_details.permanent_state = random.choice(['Maharashtra', 'Madhya Pradesh'])
                user_details.permanent_postal_code = f"{random.randint(400000, 600000)}"
                user_details.permanent_country = 'India'
                user_details.save()

            created_count += 1
            print(f"Created UserDetails for {user.username} ({user.get_full_name()})")

        except Exception as e:
            print(f"Error creating UserDetails for {user.username}: {str(e)}")

    print(f"\nSuccessfully created {created_count} UserDetails records")

    # Print summary statistics
    total_users = User.objects.count()
    total_details = UserDetails.objects.count()
    active_users = UserDetails.objects.filter(employment_status='active').count()
    inactive_users = UserDetails.objects.exclude(employment_status='active').count()

    print(f"\nSummary:")
    print(f"Total Users: {total_users}")
    print(f"Total UserDetails: {total_details}")
    print(f"Active Employees: {active_users}")
    print(f"Inactive Employees: {inactive_users}")

    # Show breakdown by location
    print(f"\nBreakdown by Location:")
    location_stats = UserDetails.objects.values('office_location__name').annotate(count=Count('id')).order_by('-count')
    for stat in location_stats:
        print(f"  {stat['office_location__name']}: {stat['count']} employees")

if __name__ == '__main__':
    from django.db.models import Count
    create_test_userdetails()
