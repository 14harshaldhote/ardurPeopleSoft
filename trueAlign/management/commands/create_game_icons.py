from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from trueAlign.models import GameIcon

class Command(BaseCommand):
    help = 'Creates default game icons for Tic Tac Toe'

    def handle(self, *args, **options):
        # Get or create system admin user
        admin_user, created = User.objects.get_or_create(
            username='system',
            defaults={
                'is_staff': True,
                'is_superuser': True,
                'email': 'system@example.com'
            }
        )
        if created:
            admin_user.set_password('changeme123')
            admin_user.save()
            self.stdout.write(self.style.SUCCESS('Created system user'))

        default_icons = [
            {'name': 'Classic X', 'symbol': '❌'},
            {'name': 'Classic O', 'symbol': '⭕'},
            {'name': 'Star', 'symbol': '⭐'},
            {'name': 'Heart', 'symbol': '❤️'},
            {'name': 'Sun', 'symbol': '☀️'},
            {'name': 'Moon', 'symbol': '🌙'},
            {'name': 'Crown', 'symbol': '👑'},
            {'name': 'Diamond', 'symbol': '💎'},
            {'name': 'Lightning', 'symbol': '⚡'},
            {'name': 'Fire', 'symbol': '🔥'},
        ]

        created_count = 0
        for icon in default_icons:
            obj, created = GameIcon.objects.get_or_create(
                name=icon['name'],
                defaults={
                    'symbol': icon['symbol'],
                    'created_by': admin_user,
                    'is_active': True
                }
            )
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created icon: {icon["name"]} ({icon["symbol"]})')
                )

        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {created_count} game icons')
        )