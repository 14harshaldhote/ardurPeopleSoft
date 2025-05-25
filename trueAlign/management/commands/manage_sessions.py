from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db import transaction
from django.db.models import Count, Avg, Sum, Max, Min
from django.contrib.sessions.models import Session
from datetime import timedelta, datetime
import logging
import json
import os
from ...models import UserSession

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Manage user sessions: cleanup old sessions, generate analytics, and maintain session health'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['cleanup', 'analytics', 'health-check', 'auto-logout', 'all'],
            default='all',
            help='Action to perform (default: all)'
        )
        
        parser.add_argument(
            '--cleanup-hours',
            type=int,
            default=48,
            help='Hours after which to cleanup inactive sessions (default: 48)'
        )
        
        parser.add_argument(
            '--analytics-days',
            type=int,
            default=7,
            help='Number of days to include in analytics (default: 7)'
        )
        
        parser.add_argument(
            '--auto-logout-threshold',
            type=int,
            default=30,
            help='Minutes of inactivity before auto-logout (default: 30)'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        parser.add_argument(
            '--export-analytics',
            type=str,
            help='Export analytics to JSON file (provide file path)'
        )

    def handle(self, *args, **options):
        self.verbosity = options.get('verbosity', 1)
        self.dry_run = options.get('dry_run', False)
        self.verbose = options.get('verbose', False)
        
        if self.dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No changes will be made')
            )
        
        action = options['action']
        
        try:
            if action == 'cleanup' or action == 'all':
                self.cleanup_sessions(options['cleanup_hours'])
            
            if action == 'analytics' or action == 'all':
                analytics = self.generate_analytics(options['analytics_days'])
                if options.get('export_analytics'):
                    self.export_analytics_to_file(analytics, options['export_analytics'])
            
            if action == 'health-check' or action == 'all':
                self.health_check()
            
            if action == 'auto-logout' or action == 'all':
                self.auto_logout_inactive_sessions(options['auto_logout_threshold'])
                
            self.stdout.write(
                self.style.SUCCESS('Session management completed successfully')
            )
            
        except Exception as e:
            logger.error(f"Error in session management: {str(e)}")
            raise CommandError(f'Session management failed: {str(e)}')

    def cleanup_sessions(self, cleanup_hours):
        """Clean up old expired sessions"""
        self.stdout.write(f'Cleaning up sessions older than {cleanup_hours} hours...')
        
        cutoff_time = timezone.now() - timedelta(hours=cleanup_hours)
        
        # Get sessions to cleanup
        expired_sessions = UserSession.objects.filter(
            is_active=False,
            logout_time__lt=cutoff_time
        )
        
        # Also clean up sessions that are marked active but very old
        stale_active_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=timezone.now() - timedelta(hours=cleanup_hours * 2)
        )
        
        expired_count = expired_sessions.count()
        stale_count = stale_active_sessions.count()
        
        if self.verbose:
            self.stdout.write(f'Found {expired_count} expired sessions to clean up')
            self.stdout.write(f'Found {stale_count} stale active sessions to clean up')
        
        if not self.dry_run:
            with transaction.atomic():
                # Clean expired sessions
                deleted_expired = expired_sessions.delete()[0]
                
                # End and clean stale active sessions
                for session in stale_active_sessions:
                    session.end_session()
                
                deleted_stale = stale_active_sessions.delete()[0]
                
                total_deleted = deleted_expired + deleted_stale
                
                self.stdout.write(
                    self.style.SUCCESS(f'Cleaned up {total_deleted} sessions')
                )
                
                # Also clean up Django sessions
                django_sessions_deleted = self.cleanup_django_sessions(cleanup_hours)
                if django_sessions_deleted > 0:
                    self.stdout.write(
                        self.style.SUCCESS(f'Cleaned up {django_sessions_deleted} Django sessions')
                    )
        else:
            self.stdout.write(f'Would clean up {expired_count + stale_count} sessions')

    def cleanup_django_sessions(self, hours):
        """Clean up expired Django sessions"""
        try:
            cutoff_time = timezone.now() - timedelta(hours=hours)
            expired_sessions = Session.objects.filter(expire_date__lt=cutoff_time)
            count = expired_sessions.count()
            expired_sessions.delete()
            return count
        except Exception as e:
            logger.warning(f"Could not clean Django sessions: {str(e)}")
            return 0

    def auto_logout_inactive_sessions(self, threshold_minutes):
        """Auto-logout sessions that have been inactive for too long"""
        self.stdout.write(f'Auto-logging out sessions inactive for {threshold_minutes} minutes...')
        
        cutoff_time = timezone.now() - timedelta(minutes=threshold_minutes)
        
        inactive_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=cutoff_time
        )
        
        count = inactive_sessions.count()
        
        if self.verbose:
            self.stdout.write(f'Found {count} inactive sessions to auto-logout')
        
        if not self.dry_run and count > 0:
            with transaction.atomic():
                for session in inactive_sessions:
                    session.end_session()
                    if self.verbose:
                        self.stdout.write(
                            f'Auto-logged out session for user {session.user.username} '
                            f'(inactive for {timezone.now() - session.last_activity})'
                        )
                
                self.stdout.write(
                    self.style.SUCCESS(f'Auto-logged out {count} inactive sessions')
                )
        else:
            self.stdout.write(f'Would auto-logout {count} inactive sessions')

    def generate_analytics(self, days):
        """Generate comprehensive session analytics"""
        self.stdout.write(f'Generating analytics for the last {days} days...')
        
        start_date = timezone.now() - timedelta(days=days)
        
        # Get sessions in the date range
        sessions = UserSession.objects.filter(
            login_time__gte=start_date
        )
        
        # Basic statistics
        total_sessions = sessions.count()
        active_sessions = sessions.filter(is_active=True).count()
        completed_sessions = sessions.filter(is_active=False).count()
        
        # User statistics
        unique_users = sessions.values('user').distinct().count()
        
        # Duration statistics
        duration_stats = sessions.filter(
            session_duration__isnull=False
        ).aggregate(
            avg_duration=Avg('session_duration'),
            max_duration=Max('session_duration'),
            min_duration=Min('session_duration'),
            total_duration=Sum('session_duration')
        )
        
        # Working hours statistics
        working_hours_stats = sessions.filter(
            working_hours__isnull=False
        ).aggregate(
            total_working_seconds=Sum('working_hours'),
            avg_working_seconds=Avg('working_hours')
        )
        
        # Idle time statistics
        idle_stats = sessions.aggregate(
            total_idle_seconds=Sum('idle_time'),
            avg_idle_seconds=Avg('idle_time')
        )
        
        # Productivity statistics
        productivity_stats = sessions.filter(
            productivity_score__isnull=False
        ).aggregate(
            avg_productivity=Avg('productivity_score'),
            max_productivity=Max('productivity_score'),
            min_productivity=Min('productivity_score')
        )
        
        # Multi-tab analytics
        multi_tab_stats = self.calculate_multi_tab_analytics(sessions)
        
        # Device type breakdown
        device_breakdown = sessions.values('device_type').annotate(
            count=Count('id'),
            avg_duration=Avg('session_duration')
        ).order_by('-count')
        
        # Location breakdown
        location_breakdown = sessions.values('location').annotate(
            count=Count('id'),
            total_hours=Sum('working_hours')
        ).order_by('-count')
        
        # Daily pattern analysis
        daily_patterns = self.calculate_daily_patterns(sessions)
        
        # Security incidents
        security_incidents = sessions.exclude(
            security_incidents={}
        ).count()
        
        # Compile analytics
        analytics = {
            'period_days': days,
            'generated_at': timezone.now().isoformat(),
            'overview': {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'completed_sessions': completed_sessions,
                'unique_users': unique_users,
                'security_incidents': security_incidents
            },
            'duration_stats': {
                'avg_duration_minutes': duration_stats['avg_duration'] or 0,
                'max_duration_minutes': duration_stats['max_duration'] or 0,
                'min_duration_minutes': duration_stats['min_duration'] or 0,
                'total_duration_hours': (duration_stats['total_duration'] or 0) / 60
            },
            'productivity_stats': {
                'avg_productivity_score': productivity_stats['avg_productivity'] or 0,
                'max_productivity_score': productivity_stats['max_productivity'] or 0,
                'min_productivity_score': productivity_stats['min_productivity'] or 0,
                'total_working_hours': self.seconds_to_hours(
                    working_hours_stats['total_working_seconds'] or 0
                ),
                'avg_working_hours': self.seconds_to_hours(
                    working_hours_stats['avg_working_seconds'] or 0
                ),
                'total_idle_hours': self.seconds_to_hours(
                    idle_stats['total_idle_seconds'] or 0
                ),
                'avg_idle_hours': self.seconds_to_hours(
                    idle_stats['avg_idle_seconds'] or 0
                )
            },
            'multi_tab_stats': multi_tab_stats,
            'device_breakdown': list(device_breakdown),
            'location_breakdown': list(location_breakdown),
            'daily_patterns': daily_patterns
        }
        
        # Display analytics
        self.display_analytics(analytics)
        
        return analytics

    def calculate_multi_tab_analytics(self, sessions):
        """Calculate multi-tab usage analytics"""
        # Group sessions by parent session ID
        parent_sessions = {}
        for session in sessions:
            parent_id = session.parent_session_id or session.tab_id
            if parent_id not in parent_sessions:
                parent_sessions[parent_id] = []
            parent_sessions[parent_id].append(session)
        
        total_parent_sessions = len(parent_sessions)
        multi_tab_sessions = sum(1 for tabs in parent_sessions.values() if len(tabs) > 1)
        
        if total_parent_sessions > 0:
            multi_tab_percentage = (multi_tab_sessions / total_parent_sessions) * 100
            avg_tabs_per_session = sum(len(tabs) for tabs in parent_sessions.values()) / total_parent_sessions
            max_tabs_in_session = max(len(tabs) for tabs in parent_sessions.values()) if parent_sessions else 0
        else:
            multi_tab_percentage = 0
            avg_tabs_per_session = 0
            max_tabs_in_session = 0
        
        return {
            'total_parent_sessions': total_parent_sessions,
            'multi_tab_sessions': multi_tab_sessions,
            'multi_tab_percentage': multi_tab_percentage,
            'avg_tabs_per_session': avg_tabs_per_session,
            'max_tabs_in_session': max_tabs_in_session
        }

    def calculate_daily_patterns(self, sessions):
        """Calculate daily usage patterns"""
        daily_data = {}
        
        for session in sessions:
            day = session.login_time.date().isoformat()
            if day not in daily_data:
                daily_data[day] = {
                    'sessions': 0,
                    'unique_users': set(),
                    'total_duration': 0,
                    'total_working_hours': 0
                }
            
            daily_data[day]['sessions'] += 1
            daily_data[day]['unique_users'].add(session.user_id)
            daily_data[day]['total_duration'] += session.session_duration or 0
            daily_data[day]['total_working_hours'] += self.seconds_to_hours(
                session.working_hours.total_seconds() if session.working_hours else 0
            )
        
        # Convert sets to counts
        for day_data in daily_data.values():
            day_data['unique_users'] = len(day_data['unique_users'])
        
        return daily_data

    def health_check(self):
        """Perform health check on session system"""
        self.stdout.write('Performing session system health check...')
        
        issues = []
        
        # Check for sessions with missing data
        sessions_missing_data = UserSession.objects.filter(
            login_time__isnull=True
        ).count()
        if sessions_missing_data > 0:
            issues.append(f'{sessions_missing_data} sessions missing login_time')
        
        # Check for very long active sessions
        long_active_sessions = UserSession.objects.filter(
            is_active=True,
            login_time__lt=timezone.now() - timedelta(days=1)
        ).count()
        if long_active_sessions > 0:
            issues.append(f'{long_active_sessions} sessions active for more than 24 hours')
        
        # Check for sessions with negative working hours
        negative_working_hours = UserSession.objects.filter(
            working_hours__lt=timedelta(0)
        ).count()
        if negative_working_hours > 0:
            issues.append(f'{negative_working_hours} sessions with negative working hours')
        
        # Check for orphaned sessions (user no longer exists)
        try:
            orphaned_sessions = UserSession.objects.filter(
                user__isnull=True
            ).count()
            if orphaned_sessions > 0:
                issues.append(f'{orphaned_sessions} orphaned sessions (user deleted)')
        except Exception:
            pass
        
        # Check database performance
        start_time = timezone.now()
        UserSession.objects.filter(is_active=True).count()
        query_time = (timezone.now() - start_time).total_seconds()
        
        if query_time > 1.0:
            issues.append(f'Slow query performance: {query_time:.2f}s for active sessions count')
        
        # Report health status
        if issues:
            self.stdout.write(
                self.style.WARNING(f'Found {len(issues)} health issues:')
            )
            for issue in issues:
                self.stdout.write(f'  - {issue}')
        else:
            self.stdout.write(
                self.style.SUCCESS('Session system health check passed')
            )
        
        return issues

    def display_analytics(self, analytics):
        """Display analytics in a readable format"""
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('SESSION ANALYTICS REPORT'))
        self.stdout.write('='*60)
        
        # Overview
        overview = analytics['overview']
        self.stdout.write(f'Period: {analytics["period_days"]} days')
        self.stdout.write(f'Total Sessions: {overview["total_sessions"]}')
        self.stdout.write(f'Active Sessions: {overview["active_sessions"]}')
        self.stdout.write(f'Unique Users: {overview["unique_users"]}')
        self.stdout.write(f'Security Incidents: {overview["security_incidents"]}')
        
        # Duration stats
        duration = analytics['duration_stats']
        self.stdout.write(f'\nAverage Session Duration: {duration["avg_duration_minutes"]:.1f} minutes')
        self.stdout.write(f'Total Session Hours: {duration["total_duration_hours"]:.1f} hours')
        
        # Productivity stats
        productivity = analytics['productivity_stats']
        self.stdout.write(f'\nAverage Productivity Score: {productivity["avg_productivity_score"]:.1f}%')
        self.stdout.write(f'Total Working Hours: {productivity["total_working_hours"]:.1f} hours')
        self.stdout.write(f'Total Idle Hours: {productivity["total_idle_hours"]:.1f} hours')
        
        # Multi-tab stats
        multi_tab = analytics['multi_tab_stats']
        self.stdout.write(f'\nMulti-tab Usage: {multi_tab["multi_tab_percentage"]:.1f}%')
        self.stdout.write(f'Average Tabs per Session: {multi_tab["avg_tabs_per_session"]:.1f}')
        self.stdout.write(f'Max Tabs in Session: {multi_tab["max_tabs_in_session"]}')
        
        # Device breakdown
        self.stdout.write('\nDevice Type Breakdown:')
        for device in analytics['device_breakdown']:
            self.stdout.write(f'  {device["device_type"] or "Unknown"}: {device["count"]} sessions')
        
        # Location breakdown
        self.stdout.write('\nLocation Breakdown:')
        for location in analytics['location_breakdown']:
            self.stdout.write(f'  {location["location"] or "Unknown"}: {location["count"]} sessions')

    def export_analytics_to_file(self, analytics, file_path):
        """Export analytics to JSON file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                json.dump(analytics, f, indent=2, default=str)
            
            self.stdout.write(
                self.style.SUCCESS(f'Analytics exported to {file_path}')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to export analytics: {str(e)}')
            )

    def seconds_to_hours(self, seconds):
        """Convert seconds to hours"""
        if isinstance(seconds, timedelta):
            seconds = seconds.total_seconds()
        return seconds / 3600 if seconds else 0