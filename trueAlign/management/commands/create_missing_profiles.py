from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from trueAlign.models import UserDetails
from django.db import transaction
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Create UserDetails profiles for users who do not have them'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating profiles',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation even if user already has a profile',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']

        self.stdout.write(
            self.style.SUCCESS('🚀 Starting UserDetails profile creation process...')
        )

        if dry_run:
            self.stdout.write(
                self.style.WARNING('📋 DRY RUN MODE - No profiles will be created')
            )

        # Get all users
        users = User.objects.all()
        total_users = users.count()

        self.stdout.write(f'📊 Found {total_users} total users')

        users_without_profiles = []
        users_with_profiles = []

        # Check which users don't have profiles
        for user in users:
            try:
                profile = UserDetails.objects.get(user=user)
                users_with_profiles.append(user)
                if force:
                    users_without_profiles.append(user)
            except UserDetails.DoesNotExist:
                users_without_profiles.append(user)

        self.stdout.write(f'✅ Users with profiles: {len(users_with_profiles)}')
        self.stdout.write(f'❌ Users without profiles: {len(users_without_profiles)}')

        if not users_without_profiles:
            self.stdout.write(
                self.style.SUCCESS('🎉 All users already have profiles!')
            )
            return

        if dry_run:
            self.stdout.write('\n📋 Users that would get profiles created:')
            for user in users_without_profiles:
                self.stdout.write(f'  - {user.username} ({user.get_full_name() or "No name"})')
            return

        # Create profiles for users without them
        created_count = 0
        error_count = 0

        self.stdout.write('\n🔄 Creating profiles...')

        for user in users_without_profiles:
            try:
                with transaction.atomic():
                    # Determine default role based on user's groups or permissions
                    default_role = 'developer'  # Default role

                    # Check if user is superuser or staff
                    if user.is_superuser:
                        default_role = 'admin'
                    elif user.is_staff:
                        default_role = 'hr'
                    elif user.groups.filter(name__icontains='admin').exists():
                        default_role = 'admin'
                    elif user.groups.filter(name__icontains='hr').exists():
                        default_role = 'hr'
                    elif user.groups.filter(name__icontains='manager').exists():
                        default_role = 'manager'

                    # Create or update profile
                    if force:
                        profile, created = UserDetails.objects.update_or_create(
                            user=user,
                            defaults={
                                'role': default_role,
                                'employee_type': 'full_time',
                                'employment_status': 'active',
                                'personal_email': user.email,
                            }
                        )
                        action = 'Updated' if not created else 'Created'
                    else:
                        profile = UserDetails.objects.create(
                            user=user,
                            role=default_role,
                            employee_type='full_time',
                            employment_status='active',
                            personal_email=user.email,
                        )
                        action = 'Created'

                    created_count += 1
                    self.stdout.write(
                        f'  ✅ {action} profile for {user.username} with role: {default_role}'
                    )

            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Error creating profile for {user.username}: {str(e)}')
                )
                logger.error(f'Error creating profile for user {user.username}: {str(e)}')

        # Summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS(f'📈 SUMMARY:'))
        self.stdout.write(f'  • Total users processed: {len(users_without_profiles)}')
        self.stdout.write(f'  • Profiles created/updated: {created_count}')
        self.stdout.write(f'  • Errors encountered: {error_count}')

        if created_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f'🎉 Successfully processed {created_count} user profiles!')
            )

        if error_count > 0:
            self.stdout.write(
                self.style.ERROR(f'⚠️  {error_count} errors occurred. Check logs for details.')
            )

        self.stdout.write('\n💡 Note: Users can now access their profile page and update their information.')
