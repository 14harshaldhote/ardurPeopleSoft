"""
Django management command to clean up old sessions and maintain session tracking system.
Optimized for shared hosting environments with minimal resource usage.
"""

import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from django.conf import settings

from trueAlign.models import UserSession
from trueAlign.core.session_config import CONFIG
from trueAlign.core.signals import (
    cleanup_old_sessions, cleanup_inactive_sessions,
    cleanup_orphaned_cache_entries, get_session_stats,
    run_maintenance_tasks
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up old sessions and maintain session tracking system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--mode',
            type=str,
            choices=['inactive', 'old', 'cache', 'all'],
            default='all',
            help='Cleanup mode: inactive (close inactive sessions), old (delete old sessions), cache (clear orphaned cache), all (run all cleanup tasks)'
        )

        parser.add_argument(
            '--days',
            type=int,
            default=CONFIG.CLEANUP_OLD_SESSIONS_DAYS,
            help=f'Number of days to keep old sessions (default: {CONFIG.CLEANUP_OLD_SESSIONS_DAYS})'
        )

        parser.add_argument(
            '--timeout-minutes',
            type=int,
            default=CONFIG.SESSION_TIMEOUT_MINUTES,
            help=f'Session timeout in minutes (default: {CONFIG.SESSION_TIMEOUT_MINUTES})'
        )

        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be cleaned up without actually doing it'
        )

        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show session statistics'
        )

        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Batch size for database operations (default: 100)'
        )

    def handle(self, *args, **options):
        """Main command handler"""
        self.verbosity = options.get('verbosity', 1)
        self.dry_run = options.get('dry_run', False)
        self.verbose = options.get('verbose', False)
        self.mode = options.get('mode', 'all')
        self.days = options.get('days', CONFIG.CLEANUP_OLD_SESSIONS_DAYS)
        self.timeout_minutes = options.get('timeout_minutes', CONFIG.SESSION_TIMEOUT_MINUTES)
        self.batch_size = options.get('batch_size', 100)

        # Set up logging
        if self.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        self.stdout.write(
            self.style.SUCCESS(
                f'Starting session cleanup (mode: {self.mode}, dry_run: {self.dry_run})'
            )
        )

        try:
            # Show initial stats if requested
            if options.get('stats', False):
                self.show_session_stats()

            # Run cleanup based on mode
            results = self.run_cleanup()

            # Show results
            self.show_results(results)

            # Show final stats if requested
            if options.get('stats', False):
                self.stdout.write(self.style.SUCCESS('\n--- After Cleanup ---'))
                self.show_session_stats()

        except Exception as e:
            logger.error(f"Error during session cleanup: {str(e)}")
            raise CommandError(f'Session cleanup failed: {str(e)}')

    def run_cleanup(self):
        """Run cleanup tasks based on mode"""
        results = {
            'inactive_sessions_closed': 0,
            'old_sessions_deleted': 0,
            'cache_entries_cleared': 0,
            'errors': []
        }

        if self.mode in ['inactive', 'all']:
            results['inactive_sessions_closed'] = self.cleanup_inactive_sessions()

        if self.mode in ['old', 'all']:
            results['old_sessions_deleted'] = self.cleanup_old_sessions()

        if self.mode in ['cache', 'all']:
            results['cache_entries_cleared'] = self.cleanup_cache()

        return results

    def cleanup_inactive_sessions(self):
        """Clean up inactive sessions"""
        self.stdout.write('Cleaning up inactive sessions...')

        cutoff_time = timezone.now() - timedelta(minutes=self.timeout_minutes)

        # Find sessions that should be closed
        inactive_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=cutoff_time
        )

        count = inactive_sessions.count()

        if self.verbose:
            self.stdout.write(f'Found {count} inactive sessions to close')

        if self.dry_run:
            self.stdout.write(self.style.WARNING(f'DRY RUN: Would close {count} inactive sessions'))
            return count

        # Close sessions in batches
        closed_count = 0
        for session in inactive_sessions.iterator(chunk_size=self.batch_size):
            try:
                session.is_active = False
                session.session_end_time = timezone.now()
                session.end_reason = 'timeout'
                session.save(update_fields=['is_active', 'session_end_time', 'end_reason'])

                # Clear related cache
                cache_key = f"{CONFIG.SESSION_CACHE_PREFIX}:{session.user.id}"
                cache.delete(cache_key)

                closed_count += 1

                if self.verbose and closed_count % 10 == 0:
                    self.stdout.write(f'Closed {closed_count} sessions...')

            except Exception as e:
                error_msg = f'Error closing session {session.id}: {str(e)}'
                logger.error(error_msg)
                if self.verbose:
                    self.stdout.write(self.style.ERROR(error_msg))

        self.stdout.write(
            self.style.SUCCESS(f'Successfully closed {closed_count} inactive sessions')
        )

        return closed_count

    def cleanup_old_sessions(self):
        """Clean up old sessions"""
        self.stdout.write('Cleaning up old sessions...')

        cutoff_date = timezone.now() - timedelta(days=self.days)

        # Find old inactive sessions
        old_sessions = UserSession.objects.filter(
            is_active=False,
            session_end_time__lt=cutoff_date
        )

        count = old_sessions.count()

        if self.verbose:
            self.stdout.write(f'Found {count} old sessions to delete')

        if self.dry_run:
            self.stdout.write(self.style.WARNING(f'DRY RUN: Would delete {count} old sessions'))
            return count

        # Delete sessions in batches
        deleted_count = 0

        # Use chunked deletion to avoid memory issues
        while True:
            batch = old_sessions[:self.batch_size]
            if not batch:
                break

            try:
                with transaction.atomic():
                    session_ids = list(batch.values_list('id', flat=True))
                    batch_size = len(session_ids)

                    # Delete the batch
                    UserSession.objects.filter(id__in=session_ids).delete()

                    deleted_count += batch_size

                    if self.verbose and deleted_count % 100 == 0:
                        self.stdout.write(f'Deleted {deleted_count} sessions...')

            except Exception as e:
                error_msg = f'Error deleting session batch: {str(e)}'
                logger.error(error_msg)
                if self.verbose:
                    self.stdout.write(self.style.ERROR(error_msg))
                break

        self.stdout.write(
            self.style.SUCCESS(f'Successfully deleted {deleted_count} old sessions')
        )

        return deleted_count

    def cleanup_cache(self):
        """Clean up orphaned cache entries"""
        self.stdout.write('Cleaning up cache entries...')

        if self.dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN: Would clear orphaned cache entries'))
            return 0

        # This is a simplified cache cleanup
        # In a real implementation, you'd need to iterate through cache keys
        # which depends on your cache backend

        try:
            # Clear all session-related cache patterns
            cache_patterns = [
                f"{CONFIG.SESSION_CACHE_PREFIX}:*",
                f"{CONFIG.STATUS_CACHE_PREFIX}:*",
                f"{CONFIG.HEARTBEAT_CACHE_PREFIX}:*",
                f"{CONFIG.ANALYTICS_CACHE_PREFIX}:*",
                f"{CONFIG.THROTTLE_CACHE_PREFIX}:*",
            ]

            cleared_count = 0

            # Get all active user IDs
            active_user_ids = set(
                UserSession.objects.filter(is_active=True)
                .values_list('user_id', flat=True)
                .distinct()
            )

            # This is a simplified approach - in production you'd want to
            # iterate through actual cache keys if your backend supports it
            for user_id in active_user_ids:
                cache_keys = [
                    f"{CONFIG.SESSION_CACHE_PREFIX}:{user_id}",
                    f"{CONFIG.STATUS_CACHE_PREFIX}:{user_id}",
                    f"{CONFIG.HEARTBEAT_CACHE_PREFIX}:{user_id}",
                    f"{CONFIG.ANALYTICS_CACHE_PREFIX}:{user_id}",
                ]

                for key in cache_keys:
                    if cache.get(key) is not None:
                        cache.delete(key)
                        cleared_count += 1

            self.stdout.write(
                self.style.SUCCESS(f'Successfully cleared {cleared_count} cache entries')
            )

            return cleared_count

        except Exception as e:
            error_msg = f'Error cleaning cache: {str(e)}'
            logger.error(error_msg)
            if self.verbose:
                self.stdout.write(self.style.ERROR(error_msg))
            return 0

    def show_session_stats(self):
        """Show session statistics"""
        try:
            stats = get_session_stats()

            self.stdout.write(self.style.SUCCESS('\n--- Session Statistics ---'))
            self.stdout.write(f'Total sessions: {stats.get("total_sessions", 0)}')
            self.stdout.write(f'Active sessions: {stats.get("active_sessions", 0)}')
            self.stdout.write(f'Sessions today: {stats.get("sessions_today", 0)}')
            self.stdout.write(f'Unique users today: {stats.get("unique_users_today", 0)}')

            # Additional stats
            try:
                # Sessions by status
                inactive_count = UserSession.objects.filter(is_active=False).count()
                idle_count = UserSession.objects.filter(is_active=True, is_idle=True).count()

                self.stdout.write(f'Inactive sessions: {inactive_count}')
                self.stdout.write(f'Idle sessions: {idle_count}')

                # Sessions by time period
                now = timezone.now()
                last_hour = UserSession.objects.filter(
                    last_activity__gte=now - timedelta(hours=1)
                ).count()
                last_day = UserSession.objects.filter(
                    last_activity__gte=now - timedelta(days=1)
                ).count()
                last_week = UserSession.objects.filter(
                    last_activity__gte=now - timedelta(days=7)
                ).count()

                self.stdout.write(f'Sessions active in last hour: {last_hour}')
                self.stdout.write(f'Sessions active in last day: {last_day}')
                self.stdout.write(f'Sessions active in last week: {last_week}')

            except Exception as e:
                logger.error(f'Error getting additional stats: {str(e)}')

        except Exception as e:
            error_msg = f'Error getting session stats: {str(e)}'
            logger.error(error_msg)
            self.stdout.write(self.style.ERROR(error_msg))

    def show_results(self, results):
        """Show cleanup results"""
        self.stdout.write(self.style.SUCCESS('\n--- Cleanup Results ---'))

        if results['inactive_sessions_closed'] > 0:
            self.stdout.write(f'Closed {results["inactive_sessions_closed"]} inactive sessions')

        if results['old_sessions_deleted'] > 0:
            self.stdout.write(f'Deleted {results["old_sessions_deleted"]} old sessions')

        if results['cache_entries_cleared'] > 0:
            self.stdout.write(f'Cleared {results["cache_entries_cleared"]} cache entries')

        if results['errors']:
            self.stdout.write(self.style.ERROR(f'Encountered {len(results["errors"])} errors'))
            if self.verbose:
                for error in results['errors']:
                    self.stdout.write(self.style.ERROR(f'  - {error}'))

        total_actions = (
            results['inactive_sessions_closed'] +
            results['old_sessions_deleted'] +
            results['cache_entries_cleared']
        )

        if total_actions == 0:
            self.stdout.write(self.style.WARNING('No cleanup actions performed'))
        else:
            self.stdout.write(
                self.style.SUCCESS(f'Cleanup completed successfully ({total_actions} total actions)')
            )
