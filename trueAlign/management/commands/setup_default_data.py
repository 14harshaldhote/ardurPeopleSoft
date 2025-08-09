from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group
from trueAlign.models import OfficeLocation
from datetime import time

class Command(BaseCommand):
    help = 'Setup default groups and office locations for the system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset existing data and create fresh setup',
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Setting up default groups and office locations...')
        )

        # Create default groups
        self.create_default_groups(options['reset'])

        # Create default office locations
        self.create_default_office_locations(options['reset'])

        self.stdout.write(
            self.style.SUCCESS('✅ Default data setup completed successfully!')
        )

    def create_default_groups(self, reset=False):
        """Create default user groups with proper permissions"""

        default_groups = [
            {
                'name': 'Admin',
                'description': 'Full system access and administration'
            },
            {
                'name': 'HR',
                'description': 'Human Resources - user management and employee data'
            },
            {
                'name': 'Manager',
                'description': 'Team management and reporting capabilities'
            },
            {
                'name': 'Employee',
                'description': 'Standard employee access'
            },
            {
                'name': 'Finance',
                'description': 'Financial data access and reporting'
            },
            {
                'name': 'Management',
                'description': 'Senior management with strategic access'
            },
            {
                'name': 'Team Lead',
                'description': 'Team leadership with project management access'
            },
            {
                'name': 'Developer',
                'description': 'Development team members'
            },
            {
                'name': 'QA',
                'description': 'Quality Assurance team'
            },
            {
                'name': 'Intern',
                'description': 'Internship and training programs'
            }
        ]

        if reset:
            self.stdout.write('Resetting existing groups...')
            Group.objects.all().delete()

        groups_created = 0
        groups_existing = 0

        for group_data in default_groups:
            group, created = Group.objects.get_or_create(
                name=group_data['name']
            )

            if created:
                groups_created += 1
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created group: {group.name}')
                )
            else:
                groups_existing += 1
                self.stdout.write(
                    self.style.WARNING(f'• Group already exists: {group.name}')
                )

        self.stdout.write(f'\nGroups Summary:')
        self.stdout.write(f'  - Created: {groups_created}')
        self.stdout.write(f'  - Already existed: {groups_existing}')

    def create_default_office_locations(self, reset=False):
        """Create default office locations"""

        default_locations = [
            {
                'name': 'Ardur Technology - Betul',
                'code': 'ATS',
                'address_line1': 'Ardur Technology Solutions',
                'address_line2': 'Near Railway Station',
                'city': 'Betul',
                'state': 'Madhya Pradesh',
                'postal_code': '460001',
                'country': 'India',
                'phone': '+91-7692-234567',
                'email': 'betul@ardurtechnology.com',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 0),
                'working_hours_end': time(18, 0),
                'is_active': True
            },
            {
                'name': 'Ardur Technology - Pune',
                'code': 'ATP',
                'address_line1': 'Ardur Technology Pvt Ltd',
                'address_line2': 'Hinjewadi Phase 2',
                'city': 'Pune',
                'state': 'Maharashtra',
                'postal_code': '411057',
                'country': 'India',
                'phone': '+91-20-2345-6789',
                'email': 'pune@ardurtechnology.com',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 30),
                'working_hours_end': time(18, 30),
                'is_active': True
            },
            {
                'name': 'Ardur Technology - Mumbai',
                'code': 'ATM',
                'address_line1': 'Ardur Corporate Office',
                'address_line2': 'Andheri East',
                'city': 'Mumbai',
                'state': 'Maharashtra',
                'postal_code': '400069',
                'country': 'India',
                'phone': '+91-22-2345-6789',
                'email': 'mumbai@ardurtechnology.com',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(10, 0),
                'working_hours_end': time(19, 0),
                'is_active': True
            },
            {
                'name': 'Ardur Technology - Delhi',
                'code': 'ATD',
                'address_line1': 'Ardur Technology Delhi Branch',
                'address_line2': 'Sector 62, Noida',
                'city': 'Noida',
                'state': 'Uttar Pradesh',
                'postal_code': '201301',
                'country': 'India',
                'phone': '+91-120-2345-678',
                'email': 'delhi@ardurtechnology.com',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 0),
                'working_hours_end': time(18, 0),
                'is_active': True
            },
            {
                'name': 'Ardur Technology - Bangalore',
                'code': 'ATB',
                'address_line1': 'Ardur Tech Hub',
                'address_line2': 'Electronic City Phase 1',
                'city': 'Bangalore',
                'state': 'Karnataka',
                'postal_code': '560100',
                'country': 'India',
                'phone': '+91-80-2345-6789',
                'email': 'bangalore@ardurtechnology.com',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 0),
                'working_hours_end': time(18, 0),
                'is_active': True
            },
            {
                'name': 'Work From Home',
                'code': 'WFH',
                'address_line1': 'Remote Location',
                'address_line2': '',
                'city': 'Remote',
                'state': 'Remote',
                'postal_code': '000000',
                'country': 'India',
                'phone': '',
                'email': 'remote@ardurtechnology.com',
                'timezone': 'Asia/Kolkata',
                'working_hours_start': time(9, 0),
                'working_hours_end': time(18, 0),
                'is_active': True
            }
        ]

        if reset:
            self.stdout.write('Resetting existing office locations...')
            OfficeLocation.objects.all().delete()

        locations_created = 0
        locations_existing = 0

        for location_data in default_locations:
            location, created = OfficeLocation.objects.get_or_create(
                code=location_data['code'],
                defaults=location_data
            )

            if created:
                locations_created += 1
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created office location: {location.name}')
                )
            else:
                locations_existing += 1
                self.stdout.write(
                    self.style.WARNING(f'• Office location already exists: {location.name}')
                )

        self.stdout.write(f'\nOffice Locations Summary:')
        self.stdout.write(f'  - Created: {locations_created}')
        self.stdout.write(f'  - Already existed: {locations_existing}')
