from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import get_user_model
from trueAlign.models import UserSession, SessionActivity
from datetime import timedelta
import uuid
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class Command(BaseCommand):
    help = 'Fix session tracking issues and clean up duplicate sessions'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to look back for session cleanup (default: 7)',
        )
        parser.add_argument(
            '--close-old',
            action='store_true',
            help='Close sessions older than specified days',
        )
        parser.add_argument(
            '--fix-duplicates',
            action='store_true',
            help='Fix duplicate sessions for same user',
        )
        parser.add_argument(
            '--fix-parent-ids',
            action='store_true',
            help='Fix missing parent_session_id',
        )
        parser.add_argument(
            '--clean-activities',
            action='store_true',
            help='Clean up old session activities',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Run all fixes',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        days_back = options['days']

        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No changes will be made')
            )

        cutoff_date = timezone.now() - timedelta(days=days_back)

        if options['all']:
            options['close_old'] = True
            options['fix_duplicates'] = True
            options['fix_parent_ids'] = True
            options['clean_activities'] = True

        total_fixed = 0

        # 1. Close old sessions
        if options['close_old']:
            total_fixed += self.close_old_sessions(cutoff_date, dry_run)

        # 2. Fix duplicate sessions
        if options['fix_duplicates']:
            total_fixed += self.fix_duplicate_sessions(dry_run)

        # 3. Fix missing parent_session_id
        if options['fix_parent_ids']:
            total_fixed += self.fix_parent_session_ids(dry_run)

        # 4. Clean up old activities
        if options['clean_activities']:
            total_fixed += self.clean_old_activities(cutoff_date, dry_run)

        # 5. Update session statistics
        self.update_session_stats()

        self.stdout.write(
            self.style.SUCCESS(f'Session fix completed. Total changes: {total_fixed}')
        )

    def close_old_sessions(self, cutoff_date, dry_run):
        """Close sessions older than cutoff date"""
        old_sessions = UserSession.objects.filter(
            created_at__lt=cutoff_date,
            is_active=True
        )

        count = old_sessions.count()
        self.stdout.write(f'Found {count} old active sessions to close')

        if not dry_run and count > 0:
            with transaction.atomic():
                old_sessions.update(
                    is_active=False,
                    ended_at=timezone.now(),
                    logout_time=timezone.now(),
                    end_reason='auto_cleanup'
                )
            self.stdout.write(
                self.style.SUCCESS(f'Closed {count} old sessions')
            )

        return count

    def fix_duplicate_sessions(self, dry_run):
        """Fix duplicate sessions for same user"""
        self.stdout.write('Fixing duplicate sessions...')

        fixed_count = 0

        # Get users with multiple active sessions
        from django.db.models import Count
        users_with_duplicates = UserSession.objects.filter(
            is_active=True
        ).values('user').annotate(
            session_count=Count('id')
        ).filter(session_count__gt=1)

        for user_data in users_with_duplicates:
            user_id = user_data['user']
            session_count = user_data['session_count']

            try:
                user = User.objects.get(id=user_id)
                self.stdout.write(f'User {user.username} has {session_count} active sessions')

                # Get all active sessions for this user, ordered by creation time
                user_sessions = UserSession.objects.filter(
                    user=user,
                    is_active=True
                ).order_by('-created_at')

                if user_sessions.count() > 1:
                    # Keep the most recent session, close others
                    sessions_to_close = user_sessions[1:]  # All except the first (most recent)

                    self.stdout.write(f'  Keeping session {user_sessions.first().id}')
                    self.stdout.write(f'  Closing {len(sessions_to_close)} duplicate sessions')

                    if not dry_run:
                        with transaction.atomic():
                            for session in sessions_to_close:
                                session.is_active = False
                                session.ended_at = timezone.now()
                                session.logout_time = timezone.now()
                                session.end_reason = 'duplicate_cleanup'
                                session.save()
                                fixed_count += 1

            except User.DoesNotExist:
                self.stdout.write(f'User with ID {user_id} not found')
                continue

        if fixed_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f'Fixed {fixed_count} duplicate sessions')
            )

        return fixed_count

    def fix_parent_session_ids(self, dry_run):
        """Fix missing parent_session_id values"""
        self.stdout.write('Fixing missing parent_session_id values...')

        sessions_without_parent = UserSession.objects.filter(
            parent_session_id__isnull=True
        )

        count = sessions_without_parent.count()
        self.stdout.write(f'Found {count} sessions without parent_session_id')

        fixed_count = 0

        if not dry_run and count > 0:
            with transaction.atomic():
                for session in sessions_without_parent:
                    # Generate a parent session ID if missing
                    if not session.parent_session_id:
                        session.parent_session_id = uuid.uuid4()
                        session.is_primary_tab = True
                        session.save(update_fields=['parent_session_id', 'is_primary_tab'])
                        fixed_count += 1

            self.stdout.write(
                self.style.SUCCESS(f'Fixed {fixed_count} parent_session_id values')
            )

        return fixed_count

    def clean_old_activities(self, cutoff_date, dry_run):
        """Clean up old session activities"""
        self.stdout.write('Cleaning up old session activities...')

        old_activities = SessionActivity.objects.filter(
            created_at__lt=cutoff_date
        )

        count = old_activities.count()
        self.stdout.write(f'Found {count} old session activities to clean')

        if not dry_run and count > 0:
            deleted_count = old_activities.delete()[0]
            self.stdout.write(
                self.style.SUCCESS(f'Cleaned up {deleted_count} old activities')
            )
            return deleted_count

        return count

    def update_session_stats(self):
        """Update and display current session statistics"""
        self.stdout.write('\n=== Current Session Statistics ===')

        total_sessions = UserSession.objects.count()
        active_sessions = UserSession.objects.filter(is_active=True).count()
        idle_sessions = UserSession.objects.filter(is_active=True, is_idle=True).count()

        # Recent sessions (last 24 hours)
        recent_cutoff = timezone.now() - timedelta(hours=24)
        recent_sessions = UserSession.objects.filter(created_at__gte=recent_cutoff).count()

        # Session activities
        total_activities = SessionActivity.objects.count()
        recent_activities = SessionActivity.objects.filter(
            created_at__gte=recent_cutoff
        ).count()

        self.stdout.write(f'Total sessions: {total_sessions}')
        self.stdout.write(f'Active sessions: {active_sessions}')
        self.stdout.write(f'Idle sessions: {idle_sessions}')
        self.stdout.write(f'Recent sessions (24h): {recent_sessions}')
        self.stdout.write(f'Total activities: {total_activities}')
        self.stdout.write(f'Recent activities (24h): {recent_activities}')

        # Users with active sessions
        active_users = UserSession.objects.filter(
            is_active=True
        ).values('user').distinct().count()
        self.stdout.write(f'Users with active sessions: {active_users}')

        # Show users with multiple active sessions
        from django.db.models import Count
        users_with_multiple = UserSession.objects.filter(
            is_active=True
        ).values('user__username').annotate(
            session_count=Count('id')
        ).filter(session_count__gt=1)

        if users_with_multiple.exists():
            self.stdout.write('\nUsers with multiple active sessions:')
            for user_data in users_with_multiple:
                username = user_data['user__username']
                session_count = user_data['session_count']
                self.stdout.write(f'  {username}: {session_count} sessions')
        else:
            self.stdout.write(self.style.SUCCESS('\nNo users with multiple active sessions'))
