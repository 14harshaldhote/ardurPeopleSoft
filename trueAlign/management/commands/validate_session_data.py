#!/usr/bin/env python3
"""
Management command to validate and clean up session tracking data
This command helps ensure data integrity and fixes common issues with null/invalid data
"""

import json
import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db import transaction
from django.db.models import Q, Count
from trueAlign.models import UserSession, SessionActivity
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Validate and clean up session tracking data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix-nulls',
            action='store_true',
            help='Fix null values in JSON fields',
        )
        parser.add_argument(
            '--cleanup-orphaned',
            action='store_true',
            help='Clean up orphaned sessions and activities',
        )
        parser.add_argument(
            '--validate-all',
            action='store_true',
            help='Run all validation and cleanup tasks',
        )
        parser.add_argument(
            '--fix-duplicates',
            action='store_true',
            help='Fix duplicate sessions for same user/tab',
        )
        parser.add_argument(
            '--generate-missing-ids',
            action='store_true',
            help='Generate missing tab_id and parent_session_id values',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to look back for data validation (default: 30)',
        )

    def handle(self, *args, **options):
        self.dry_run = options['dry_run']
        self.days = options['days']
        
        if self.dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))
        
        self.stdout.write(self.style.SUCCESS('Starting session data validation...'))
        
        if options['validate_all']:
            options.update({
                'fix_nulls': True,
                'cleanup_orphaned': True,
                'fix_duplicates': True,
                'generate_missing_ids': True,
            })
        
        # Track statistics
        self.stats = {
            'sessions_fixed': 0,
            'activities_fixed': 0,
            'duplicates_removed': 0,
            'orphaned_cleaned': 0,
            'nulls_fixed': 0,
            'ids_generated': 0,
        }
        
        try:
            if options['fix_nulls']:
                self.fix_null_values()
            
            if options['generate_missing_ids']:
                self.generate_missing_ids()
            
            if options['fix_duplicates']:
                self.fix_duplicate_sessions()
            
            if options['cleanup_orphaned']:
                self.cleanup_orphaned_data()
            
            # Always run basic validation
            self.validate_data_integrity()
            
            self.show_statistics()
            
        except Exception as e:
            logger.error(f"Error during validation: {e}", exc_info=True)
            raise CommandError(f'Validation failed: {e}')

    def fix_null_values(self):
        """Fix null values in JSON fields"""
        self.stdout.write('Fixing null values in JSON fields...')
        
        cutoff_date = timezone.now() - timedelta(days=self.days)
        sessions = UserSession.objects.filter(created_at__gte=cutoff_date)
        
        json_fields = [
            'tab_title', 'tab_url', 'url', 'title', 'referrer', 'page_views',
            'clicks', 'scrolls', 'keyboard_events', 'tab_visibility_log',
            'idle_state_changes', 'network_events', 'error_events', 'related_tabs',
            'security_anomalies'
        ]
        
        dict_fields = ['visited_urls', 'performance_metrics', 'offline_data']
        
        for session in sessions:
            updates = {}
            
            # Fix list fields
            for field in json_fields:
                value = getattr(session, field)
                if value is None:
                    updates[field] = []
                    self.stats['nulls_fixed'] += 1
            
            # Fix dict fields
            for field in dict_fields:
                value = getattr(session, field)
                if value is None:
                    updates[field] = {}
                    self.stats['nulls_fixed'] += 1
            
            if updates and not self.dry_run:
                for field, value in updates.items():
                    setattr(session, field, value)
                session.save(update_fields=list(updates.keys()))
                self.stats['sessions_fixed'] += 1
            elif updates:
                self.stdout.write(f'Would fix {len(updates)} null fields in session {session.id}')

    def generate_missing_ids(self):
        """Generate missing tab_id and parent_session_id values"""
        self.stdout.write('Generating missing IDs...')
        
        cutoff_date = timezone.now() - timedelta(days=self.days)
        sessions = UserSession.objects.filter(created_at__gte=cutoff_date)
        
        for session in sessions:
            updates = {}
            
            # Generate missing tab_id
            if not session.tab_id:
                import uuid
                updates['tab_id'] = str(uuid.uuid4())
                self.stats['ids_generated'] += 1
            
            # Generate missing parent_session_id
            if not session.parent_session_id:
                import uuid
                updates['parent_session_id'] = uuid.uuid4()
                updates['is_primary_tab'] = True
                self.stats['ids_generated'] += 1
            
            if updates and not self.dry_run:
                for field, value in updates.items():
                    setattr(session, field, value)
                session.save(update_fields=list(updates.keys()))
                self.stats['sessions_fixed'] += 1
            elif updates:
                self.stdout.write(f'Would generate {len(updates)} missing IDs for session {session.id}')

    def fix_duplicate_sessions(self):
        """Fix duplicate sessions for the same user/tab combination"""
        self.stdout.write('Fixing duplicate sessions...')
        
        cutoff_date = timezone.now() - timedelta(days=self.days)
        
        # Find duplicate sessions (same user + tab_id + active)
        duplicates = UserSession.objects.filter(
            created_at__gte=cutoff_date,
            is_active=True
        ).values('user', 'tab_id').annotate(
            count=Count('id')
        ).filter(count__gt=1)
        
        for duplicate in duplicates:
            user_id = duplicate['user']
            tab_id = duplicate['tab_id']
            
            # Get all sessions for this user/tab combination
            sessions = UserSession.objects.filter(
                user_id=user_id,
                tab_id=tab_id,
                is_active=True,
                created_at__gte=cutoff_date
            ).order_by('-last_activity')
            
            # Keep the most recently active session, deactivate others
            sessions_to_deactivate = sessions[1:]  # All except the first (most recent)
            
            for session in sessions_to_deactivate:
                if not self.dry_run:
                    session.is_active = False
                    session.ended_at = timezone.now()
                    session.end_reason = 'duplicate_cleanup'
                    session.save(update_fields=['is_active', 'ended_at', 'end_reason'])
                    self.stats['duplicates_removed'] += 1
                else:
                    self.stdout.write(f'Would deactivate duplicate session {session.id}')

    def cleanup_orphaned_data(self):
        """Clean up orphaned activities and old inactive sessions"""
        self.stdout.write('Cleaning up orphaned data...')
        
        # Clean up activities for sessions that no longer exist
        orphaned_activities = SessionActivity.objects.filter(
            session__isnull=True
        )
        
        if not self.dry_run:
            count = orphaned_activities.count()
            orphaned_activities.delete()
            self.stats['orphaned_cleaned'] += count
            self.stdout.write(f'Deleted {count} orphaned activities')
        else:
            count = orphaned_activities.count()
            self.stdout.write(f'Would delete {count} orphaned activities')
        
        # Clean up very old inactive sessions (older than specified days)
        old_cutoff = timezone.now() - timedelta(days=self.days * 2)  # Double the cutoff for safety
        old_sessions = UserSession.objects.filter(
            is_active=False,
            created_at__lt=old_cutoff
        )
        
        if not self.dry_run:
            count = old_sessions.count()
            old_sessions.delete()
            self.stats['orphaned_cleaned'] += count
            self.stdout.write(f'Deleted {count} old inactive sessions')
        else:
            count = old_sessions.count()
            self.stdout.write(f'Would delete {count} old inactive sessions')

    def validate_data_integrity(self):
        """Validate overall data integrity"""
        self.stdout.write('Validating data integrity...')
        
        cutoff_date = timezone.now() - timedelta(days=self.days)
        
        # Check for sessions with invalid user references
        invalid_user_sessions = UserSession.objects.filter(
            created_at__gte=cutoff_date,
            user__isnull=True
        )
        
        if invalid_user_sessions.exists():
            count = invalid_user_sessions.count()
            self.stdout.write(
                self.style.WARNING(f'Found {count} sessions with invalid user references')
            )
        
        # Check for activities with invalid session references
        invalid_session_activities = SessionActivity.objects.filter(
            created_at__gte=cutoff_date,
            session__is_active=False
        )
        
        if invalid_session_activities.exists():
            count = invalid_session_activities.count()
            self.stdout.write(
                self.style.WARNING(f'Found {count} activities linked to inactive sessions')
            )
        
        # Check for sessions with missing required fields
        sessions_missing_data = UserSession.objects.filter(
            created_at__gte=cutoff_date
        ).filter(
            Q(session_key__isnull=True) | Q(session_key='') |
            Q(user_agent__isnull=True) | Q(user_agent='')
        )
        
        if sessions_missing_data.exists():
            count = sessions_missing_data.count()
            self.stdout.write(
                self.style.WARNING(f'Found {count} sessions with missing required data')
            )
        
        # Check for inconsistent time data
        time_inconsistent_sessions = UserSession.objects.filter(
            created_at__gte=cutoff_date,
            last_activity__lt=timezone.now() - timedelta(hours=24),
            is_active=True
        )
        
        if time_inconsistent_sessions.exists():
            count = time_inconsistent_sessions.count()
            self.stdout.write(
                self.style.WARNING(f'Found {count} active sessions with very old last_activity times')
            )
            
            # Fix these inconsistencies
            if not self.dry_run:
                time_inconsistent_sessions.update(
                    is_active=False,
                    ended_at=timezone.now(),
                    end_reason='stale_session_cleanup'
                )
                self.stats['sessions_fixed'] += count
                self.stdout.write(f'Fixed {count} stale active sessions')

    def show_statistics(self):
        """Show validation and cleanup statistics"""
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('VALIDATION COMPLETE'))
        self.stdout.write('='*50)
        
        if self.dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN - No actual changes were made'))
        
        self.stdout.write(f"Sessions fixed: {self.stats['sessions_fixed']}")
        self.stdout.write(f"Activities fixed: {self.stats['activities_fixed']}")
        self.stdout.write(f"Null values fixed: {self.stats['nulls_fixed']}")
        self.stdout.write(f"IDs generated: {self.stats['ids_generated']}")
        self.stdout.write(f"Duplicates removed: {self.stats['duplicates_removed']}")
        self.stdout.write(f"Orphaned data cleaned: {self.stats['orphaned_cleaned']}")
        
        # Show some current statistics
        cutoff_date = timezone.now() - timedelta(days=self.days)
        total_sessions = UserSession.objects.filter(created_at__gte=cutoff_date).count()
        active_sessions = UserSession.objects.filter(created_at__gte=cutoff_date, is_active=True).count()
        total_activities = SessionActivity.objects.filter(created_at__gte=cutoff_date).count()
        
        self.stdout.write('\nCurrent Statistics:')
        self.stdout.write(f"Total sessions (last {self.days} days): {total_sessions}")
        self.stdout.write(f"Active sessions: {active_sessions}")
        self.stdout.write(f"Total activities (last {self.days} days): {total_activities}")
        
        if total_sessions > 0:
            avg_activities = total_activities / total_sessions
            self.stdout.write(f"Average activities per session: {avg_activities:.2f}")
