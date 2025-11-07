"""
Management command to seed conference room test data.
Usage: python manage.py seed_conference_data
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import datetime, timedelta
import random

from trueAlign.models import OfficeLocation, ConferenceRoom, RoomBooking

User = get_user_model()


class Command(BaseCommand):
    help = 'Seed database with sample conference room and booking data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing conference room data before seeding',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('Starting conference room data seeding...'))

        # Clear existing data if requested
        if options['clear']:
            self.stdout.write(self.style.WARNING('Clearing existing data...'))
            RoomBooking.objects.all().delete()
            ConferenceRoom.objects.all().delete()
            self.stdout.write(self.style.SUCCESS('✓ Existing data cleared'))

        # Get or create office locations
        office_locations = self._get_or_create_office_locations()
        
        # Get admin user for created_by field
        admin_user = self._get_admin_user()
        
        # Create conference rooms
        rooms = self._create_conference_rooms(office_locations, admin_user)
        
        # Create sample bookings
        self._create_sample_bookings(rooms)
        
        self.stdout.write(self.style.SUCCESS('\n✅ Conference room data seeding completed successfully!'))

    def _get_or_create_office_locations(self):
        """Get existing office locations or create sample ones."""
        self.stdout.write('\nChecking office locations...')
        
        locations = OfficeLocation.objects.filter(is_active=True)
        
        if not locations.exists():
            self.stdout.write(self.style.WARNING('No office locations found. Creating sample locations...'))
            
            sample_locations = [
                {
                    'name': 'Mumbai - Bandra',
                    'code': 'MUM',
                    'address_line1': '123 Linking Road',
                    'city': 'Mumbai',
                    'state': 'Maharashtra',
                    'postal_code': '400050',
                    'country': 'India',
                    'phone': '+91 22 1234 5678',
                    'email': 'mumbai@company.com',
                },
                {
                    'name': 'Delhi - Gurgaon',
                    'code': 'DEL',
                    'address_line1': '456 Cyber City',
                    'city': 'Gurgaon',
                    'state': 'Haryana',
                    'postal_code': '122002',
                    'country': 'India',
                    'phone': '+91 124 1234 5678',
                    'email': 'delhi@company.com',
                },
            ]
            
            for loc_data in sample_locations:
                OfficeLocation.objects.create(**loc_data)
            
            locations = OfficeLocation.objects.filter(is_active=True)
            self.stdout.write(self.style.SUCCESS(f'✓ Created {locations.count()} office locations'))
        else:
            self.stdout.write(self.style.SUCCESS(f'✓ Found {locations.count()} existing office locations'))
        
        return list(locations)

    def _get_admin_user(self):
        """Get the first superuser or staff user."""
        admin_user = User.objects.filter(is_superuser=True).first()
        if not admin_user:
            admin_user = User.objects.filter(is_staff=True).first()
        
        if not admin_user:
            self.stdout.write(self.style.WARNING('No admin user found. Rooms will be created without creator.'))
        
        return admin_user

    def _create_conference_rooms(self, office_locations, admin_user):
        """Create sample conference rooms."""
        self.stdout.write('\nCreating conference rooms...')
        
        room_templates = [
            {
                'name': 'Board Room',
                'floor': '10th Floor',
                'capacity': 20,
                'amenities': ['Projector', 'Whiteboard', 'Video Conference', 'Conference Phone', 'AC'],
                'description': 'Large boardroom for executive meetings and presentations.',
            },
            {
                'name': 'Meeting Room A',
                'floor': '5th Floor',
                'capacity': 10,
                'amenities': ['TV Display', 'Whiteboard', 'Video Conference', 'AC'],
                'description': 'Medium-sized meeting room suitable for team discussions.',
            },
            {
                'name': 'Meeting Room B',
                'floor': '5th Floor',
                'capacity': 8,
                'amenities': ['TV Display', 'Whiteboard', 'AC'],
                'description': 'Cozy meeting space for small team collaborations.',
            },
            {
                'name': 'Conference Hall',
                'floor': 'Ground Floor',
                'capacity': 50,
                'amenities': ['Projector', 'Sound System', 'Microphones', 'Video Conference', 'AC', 'Stage'],
                'description': 'Large hall for company-wide meetings and events.',
            },
            {
                'name': 'Innovation Lab',
                'floor': '3rd Floor',
                'capacity': 12,
                'amenities': ['Smart TV', 'Whiteboard', 'Sticky Notes', 'AC', 'Standing Desks'],
                'description': 'Creative space for brainstorming and innovation sessions.',
            },
            {
                'name': 'Training Room',
                'floor': '4th Floor',
                'capacity': 25,
                'amenities': ['Projector', 'Whiteboard', 'Tables', 'Chairs', 'AC'],
                'description': 'Classroom-style room for training and workshops.',
            },
        ]
        
        created_rooms = []
        
        for office in office_locations:
            for i, template in enumerate(room_templates):
                room = ConferenceRoom.objects.create(
                    name=template['name'],
                    office_location=office,
                    floor=template['floor'],
                    capacity=template['capacity'],
                    amenities=template['amenities'],
                    description=template['description'],
                    buffer_time_minutes=15,
                    min_lead_time_minutes=15,
                    max_booking_duration_hours=3,
                    is_active=True,
                    created_by=admin_user,
                )
                created_rooms.append(room)
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created {len(created_rooms)} conference rooms'))
        return created_rooms

    def _create_sample_bookings(self, rooms):
        """Create sample bookings for the next few days."""
        self.stdout.write('\nCreating sample bookings...')
        
        # Get some users for bookings
        users = list(User.objects.all()[:10])
        if not users:
            self.stdout.write(self.style.WARNING('No users found. Skipping booking creation.'))
            return
        
        booking_templates = [
            {
                'title': 'Team Standup Meeting',
                'purpose': 'Daily standup to discuss progress and blockers.',
                'attendee_count': 8,
                'attendees': 'Team Lead, Developer 1, Developer 2, Designer, QA Lead',
            },
            {
                'title': 'Client Presentation',
                'purpose': 'Presenting Q4 roadmap to client stakeholders.',
                'attendee_count': 12,
                'attendees': 'CEO, CTO, Project Manager, Client Team',
            },
            {
                'title': 'Product Planning',
                'purpose': 'Planning next sprint features and priorities.',
                'attendee_count': 10,
                'attendees': 'Product Manager, Engineering Team, Design Lead',
            },
            {
                'title': 'Training Session',
                'purpose': 'New employee onboarding and training.',
                'attendee_count': 15,
                'attendees': 'HR Manager, New Employees, Training Coordinator',
            },
            {
                'title': 'Board Meeting',
                'purpose': 'Quarterly board meeting with stakeholders.',
                'attendee_count': 18,
                'attendees': 'Board Members, Executive Team, CFO',
            },
        ]
        
        created_bookings = 0
        
        # Create bookings for the next 7 days
        for day_offset in range(7):
            booking_date = timezone.now().date() + timedelta(days=day_offset)
            
            # Skip weekends
            if booking_date.weekday() >= 5:
                continue
            
            # Create 2-4 random bookings per day
            num_bookings = random.randint(2, 4)
            
            for _ in range(num_bookings):
                try:
                    template = random.choice(booking_templates)
                    room = random.choice(rooms)
                    user = random.choice(users)
                    
                    # Random start time between 9 AM and 4 PM
                    start_hour = random.randint(9, 16)
                    start_time = timezone.make_aware(
                        datetime.combine(booking_date, datetime.min.time().replace(hour=start_hour))
                    )
                    
                    # Duration between 1-2 hours
                    duration_hours = random.uniform(1, 2)
                    end_time = start_time + timedelta(hours=duration_hours)
                    
                    # Check if slot is available (simple check)
                    conflicts = RoomBooking.objects.filter(
                        room=room,
                        status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
                        start_time__lt=end_time,
                        end_time__gt=start_time,
                    )
                    
                    if not conflicts.exists() and template['attendee_count'] <= room.capacity:
                        booking = RoomBooking.objects.create(
                            room=room,
                            booked_by=user,
                            title=template['title'],
                            purpose=template['purpose'],
                            attendees=template['attendees'],
                            attendee_count=template['attendee_count'],
                            start_time=start_time,
                            end_time=end_time,
                            status=RoomBooking.STATUS_CONFIRMED,
                        )
                        created_bookings += 1
                
                except Exception as e:
                    # Skip if booking creation fails (likely due to validation)
                    continue
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created {created_bookings} sample bookings'))

    def _print_summary(self):
        """Print a summary of created data."""
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS('Summary:'))
        self.stdout.write(f'Office Locations: {OfficeLocation.objects.count()}')
        self.stdout.write(f'Conference Rooms: {ConferenceRoom.objects.count()}')
        self.stdout.write(f'Total Bookings: {RoomBooking.objects.count()}')
        self.stdout.write(f'Upcoming Bookings: {RoomBooking.objects.filter(start_time__gte=timezone.now()).count()}')
        self.stdout.write('=' * 50 + '\n')
