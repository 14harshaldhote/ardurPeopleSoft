from django.core.management.base import BaseCommand
from django.utils import timezone
from trueAlign.models import Room


class Command(BaseCommand):
    help = 'Setup initial conference rooms for the booking system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete existing rooms and recreate them',
        )
        parser.add_argument(
            '--update',
            action='store_true',
            help='Update existing rooms with new details',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Setting up conference rooms...'))

        # Define the two conference rooms
        rooms_data = [
            {
                'name': 'Conference Room A',
                'room_type': Room.RoomType.CONFERENCE,
                'capacity': 12,
                'location': 'Ground Floor, East Wing',
                'facilities': (
                    '• 65" 4K Smart TV with wireless screen sharing\n'
                    '• Video conferencing system (Zoom Rooms)\n'
                    '• Whiteboard and markers\n'
                    '• High-speed WiFi\n'
                    '• Conference phone\n'
                    '• Air conditioning\n'
                    '• Coffee/tea station\n'
                    '• Flip chart stand'
                ),
                'description': (
                    'Large conference room ideal for team meetings, client presentations, '
                    'and video conferences. Features modern AV equipment and comfortable '
                    'seating for up to 12 people.'
                ),
                'hourly_rate': 0.00,
                'status': Room.RoomStatus.ACTIVE
            },
            {
                'name': 'Conference Room B',
                'room_type': Room.RoomType.CONFERENCE,
                'capacity': 8,
                'location': 'First Floor, West Wing',
                'facilities': (
                    '• 55" Smart TV with HDMI connectivity\n'
                    '• Wireless presentation system\n'
                    '• Whiteboard\n'
                    '• High-speed WiFi\n'
                    '• Conference phone\n'
                    '• Air conditioning\n'
                    '• Natural lighting\n'
                    '• Adjustable lighting controls'
                ),
                'description': (
                    'Medium-sized conference room perfect for team meetings, '
                    'interviews, and small group discussions. Bright and comfortable '
                    'environment with modern amenities.'
                ),
                'hourly_rate': 0.00,
                'status': Room.RoomStatus.ACTIVE
            }
        ]

        if options['reset']:
            self.stdout.write('Deleting existing rooms...')
            deleted_count = Room.objects.all().delete()[0]
            self.stdout.write(
                self.style.WARNING(f'Deleted {deleted_count} existing rooms')
            )

        created_count = 0
        updated_count = 0

        for room_data in rooms_data:
            room_name = room_data['name']

            try:
                room, created = Room.objects.get_or_create(
                    name=room_name,
                    defaults=room_data
                )

                if created:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Created room: {room_name}')
                    )
                    self.stdout.write(f'  - Capacity: {room.capacity} people')
                    self.stdout.write(f'  - Location: {room.location}')
                    self.stdout.write(f'  - Type: {room.get_room_type_display()}')

                elif options['update']:
                    # Update existing room with new data
                    for key, value in room_data.items():
                        if key != 'name':  # Don't update the name
                            setattr(room, key, value)

                    room.updated_at = timezone.now()
                    room.save()
                    updated_count += 1
                    self.stdout.write(
                        self.style.WARNING(f'↻ Updated room: {room_name}')
                    )

                else:
                    self.stdout.write(
                        self.style.HTTP_INFO(f'⚠ Room already exists: {room_name}')
                    )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Error processing room {room_name}: {e}')
                )

        # Summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('SETUP COMPLETE!'))
        self.stdout.write(f'Rooms created: {created_count}')
        if options['update']:
            self.stdout.write(f'Rooms updated: {updated_count}')

        # Display current room status
        self.stdout.write('\nCurrent active rooms:')
        active_rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)

        for room in active_rooms:
            self.stdout.write(f'  • {room.name}')
            self.stdout.write(f'    - Capacity: {room.capacity}')
            self.stdout.write(f'    - Location: {room.location}')
            self.stdout.write(f'    - Status: {room.get_status_display()}')

            # Show current booking status
            if room.is_occupied:
                current_booking = room.current_booking
                self.stdout.write(
                    self.style.HTTP_NOT_FOUND(
                        f'    - Currently OCCUPIED until {current_booking.end_time.strftime("%I:%M %p")}'
                    )
                )
            else:
                next_booking = room.next_booking
                if next_booking:
                    self.stdout.write(
                        self.style.HTTP_INFO(
                            f'    - Next booking at {next_booking.start_time.strftime("%I:%M %p")}'
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS('    - Available for booking')
                    )

        self.stdout.write('\n' + '='*50)
        self.stdout.write(
            self.style.SUCCESS(
                'Your conference room booking system is ready to use!'
            )
        )
        self.stdout.write(
            'Next steps:\n'
            '  1. Run migrations if you haven\'t already: python manage.py migrate\n'
            '  2. Access the admin panel to manage rooms and bookings\n'
            '  3. Users can now book rooms through the booking interface'
        )

    def handle_error(self, message):
        """Helper method to handle and display errors."""
        self.stdout.write(self.style.ERROR(f'Error: {message}'))
