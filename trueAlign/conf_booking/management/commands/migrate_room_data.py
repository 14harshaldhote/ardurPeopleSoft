from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from trueAlign.models import Room, ConferenceBooking
from collections import Counter


class Command(BaseCommand):
    help = 'Migrate existing booking data from room_name to Room model'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually making changes',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force migration even if Room objects already exist',
        )
        parser.add_argument(
            '--create-rooms',
            action='store_true',
            help='Create Room objects for room names that don\'t exist',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting room data migration...'))

        dry_run = options['dry_run']
        force = options['force']
        create_rooms = options['create_rooms']

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

        # Check if we have the room_name field (backward compatibility check)
        try:
            # Try to access room_name field on a booking
            test_booking = ConferenceBooking.objects.first()
            if test_booking and hasattr(test_booking, 'room_name'):
                has_room_name_field = True
            else:
                has_room_name_field = False
        except Exception:
            has_room_name_field = False

        if not has_room_name_field:
            self.stdout.write(
                self.style.WARNING(
                    'No room_name field found. Migration may have already been completed '
                    'or the field has been removed.'
                )
            )
            if not force:
                self.stdout.write('Use --force to proceed anyway.')
                return

        # Get statistics about existing data
        self.show_current_statistics()

        # Analyze existing room names
        room_name_analysis = self.analyze_room_names()

        if not room_name_analysis['unique_rooms']:
            self.stdout.write(self.style.WARNING('No room names found in existing bookings.'))
            return

        # Show what will be migrated
        self.stdout.write('\n' + '='*60)
        self.stdout.write('MIGRATION PLAN:')
        self.stdout.write('='*60)

        for room_name, count in room_name_analysis['room_counts'].items():
            self.stdout.write(f'  • "{room_name}" - {count} bookings')

        self.stdout.write(f'\nTotal unique room names: {len(room_name_analysis["unique_rooms"])}')
        self.stdout.write(f'Total bookings to migrate: {room_name_analysis["total_bookings"]}')

        if dry_run:
            self.stdout.write('\n' + self.style.WARNING('DRY RUN COMPLETE - No changes made'))
            return

        if not force:
            # Ask for confirmation
            confirm = input('\nProceed with migration? (yes/no): ')
            if confirm.lower() not in ['yes', 'y']:
                self.stdout.write('Migration cancelled.')
                return

        # Perform the migration
        try:
            with transaction.atomic():
                self.perform_migration(room_name_analysis, create_rooms)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Migration failed: {e}'))
            raise

        self.stdout.write(self.style.SUCCESS('\nMigration completed successfully!'))
        self.show_final_statistics()

    def show_current_statistics(self):
        """Show current database statistics."""
        total_bookings = ConferenceBooking.objects.count()
        total_rooms = Room.objects.count()

        self.stdout.write('\nCurrent database state:')
        self.stdout.write(f'  • Total bookings: {total_bookings}')
        self.stdout.write(f'  • Total room objects: {total_rooms}')

    def analyze_room_names(self):
        """Analyze existing room names in bookings."""
        self.stdout.write('\nAnalyzing existing room names...')

        # Get all unique room names from existing bookings
        try:
            # Try to get room names from the room_name field
            bookings_with_room_names = ConferenceBooking.objects.exclude(
                room_name__isnull=True
            ).exclude(room_name__exact='')

            room_names = [booking.room_name for booking in bookings_with_room_names]
            room_counts = Counter(room_names)
            unique_rooms = list(set(room_names))

        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Could not access room_name field: {e}'))
            # Fallback - assume standard room names
            room_counts = Counter()
            unique_rooms = []

        return {
            'unique_rooms': unique_rooms,
            'room_counts': room_counts,
            'total_bookings': sum(room_counts.values()) if room_counts else 0
        }

    def perform_migration(self, room_analysis, create_rooms):
        """Perform the actual migration."""
        self.stdout.write('\nStarting migration...')

        created_rooms = 0
        updated_bookings = 0
        errors = 0

        # Step 1: Create or get Room objects
        room_mapping = {}
        for room_name in room_analysis['unique_rooms']:
            try:
                room, created = self.get_or_create_room(room_name, create_rooms)
                if created:
                    created_rooms += 1
                    self.stdout.write(f'  ✓ Created room: {room_name}')
                else:
                    self.stdout.write(f'  ○ Using existing room: {room_name}')

                room_mapping[room_name] = room

            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  ✗ Error creating room "{room_name}": {e}'))
                errors += 1

        if errors > 0:
            raise Exception(f'Failed to create {errors} room(s). Migration aborted.')

        # Step 2: Update existing bookings
        self.stdout.write(f'\nUpdating bookings...')

        try:
            for room_name, room in room_mapping.items():
                # Find bookings with this room name
                bookings_to_update = ConferenceBooking.objects.filter(room_name=room_name)
                count = bookings_to_update.count()

                if count > 0:
                    # Update bookings to reference the Room object
                    bookings_to_update.update(room=room)
                    updated_bookings += count
                    self.stdout.write(f'  ✓ Updated {count} bookings for "{room_name}"')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error updating bookings: {e}'))
            raise

        self.stdout.write(f'\nMigration summary:')
        self.stdout.write(f'  • Rooms created: {created_rooms}')
        self.stdout.write(f'  • Bookings updated: {updated_bookings}')

    def get_or_create_room(self, room_name, create_rooms):
        """Get or create a Room object for the given room name."""
        # First try to find existing room
        try:
            room = Room.objects.get(name=room_name)
            return room, False
        except Room.DoesNotExist:
            pass

        if not create_rooms:
            raise Exception(f'Room "{room_name}" does not exist. Use --create-rooms to create it.')

        # Create room with intelligent defaults based on name
        room_data = self.get_room_defaults(room_name)

        room = Room.objects.create(
            name=room_name,
            **room_data
        )

        return room, True

    def get_room_defaults(self, room_name):
        """Get intelligent defaults based on room name."""
        room_name_lower = room_name.lower()

        # Determine room type
        if 'huddle' in room_name_lower:
            room_type = Room.RoomType.HUDDLE
            default_capacity = 4
        elif 'board' in room_name_lower:
            room_type = Room.RoomType.BOARD
            default_capacity = 16
        elif 'meeting' in room_name_lower:
            room_type = Room.RoomType.MEETING
            default_capacity = 6
        else:
            room_type = Room.RoomType.CONFERENCE
            default_capacity = 8

        # Determine capacity based on name patterns
        if 'small' in room_name_lower or 'mini' in room_name_lower:
            capacity = min(default_capacity, 4)
        elif 'large' in room_name_lower or 'big' in room_name_lower:
            capacity = max(default_capacity, 12)
        else:
            capacity = default_capacity

        return {
            'room_type': room_type,
            'capacity': capacity,
            'location': 'To be determined',
            'facilities': (
                '• Smart TV/Projector\n'
                '• Whiteboard\n'
                '• High-speed WiFi\n'
                '• Conference phone\n'
                '• Air conditioning'
            ),
            'description': f'Conference room migrated from legacy system',
            'status': Room.RoomStatus.ACTIVE,
            'hourly_rate': 0.00
        }

    def show_final_statistics(self):
        """Show final statistics after migration."""
        total_bookings = ConferenceBooking.objects.count()
        total_rooms = Room.objects.count()

        # Count bookings with room references
        try:
            bookings_with_rooms = ConferenceBooking.objects.filter(room__isnull=False).count()
        except Exception:
            bookings_with_rooms = 0

        self.stdout.write('\nFinal database state:')
        self.stdout.write(f'  • Total bookings: {total_bookings}')
        self.stdout.write(f'  • Total room objects: {total_rooms}')
        self.stdout.write(f'  • Bookings with room references: {bookings_with_rooms}')

        if bookings_with_rooms < total_bookings:
            remaining = total_bookings - bookings_with_rooms
            self.stdout.write(
                self.style.WARNING(
                    f'  • Bookings still using room_name: {remaining}'
                )
            )

        self.stdout.write('\n' + '='*60)
        self.stdout.write('MIGRATION NOTES:')
        self.stdout.write('='*60)
        self.stdout.write(
            '1. Review created rooms in the admin panel\n'
            '2. Update room details (location, facilities, capacity) as needed\n'
            '3. Test the booking system with the new Room model\n'
            '4. Once confirmed working, you can remove the room_name field from the model'
        )
