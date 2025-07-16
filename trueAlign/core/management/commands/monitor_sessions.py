"""
Django management command to monitor active sessions and system health.
Provides real-time insights into session tracking performance and user activity.
"""

import time
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.core.cache import cache
from django.db import connection
from django.conf import settings
from django.db.models import Count, Avg, Max, Min

from trueAlign.models import UserSession
from trueAlign.core.session_config import CONFIG
from trueAlign.core.signals import get_session_stats
from trueAlign.core.utils import format_duration, get_current_time_ist

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Monitor active sessions and system health in real-time'

    def add_arguments(self, parser):
        parser.add_argument(
            '--mode',
            type=str,
            choices=['dashboard', 'continuous', 'snapshot', 'health', 'performance'],
            default='dashboard',
            help='Monitoring mode: dashboard (interactive), continuous (streaming), snapshot (one-time), health (health checks), performance (performance metrics)'
        )

        parser.add_argument(
            '--interval',
            type=int,
            default=30,
            help='Update interval in seconds for continuous monitoring (default: 30)'
        )

        parser.add_argument(
            '--duration',
            type=int,
            default=0,
            help='Duration to monitor in minutes (0 for indefinite, default: 0)'
        )

        parser.add_argument(
            '--format',
            type=str,
            choices=['table', 'json', 'csv'],
            default='table',
            help='Output format (default: table)'
        )

        parser.add_argument(
            '--alert-threshold',
            type=int,
            default=100,
            help='Alert threshold for active sessions (default: 100)'
        )

        parser.add_argument(
            '--include-idle',
            action='store_true',
            help='Include idle sessions in monitoring'
        )

        parser.add_argument(
            '--user-id',
            type=int,
            help='Monitor specific user ID only'
        )

        parser.add_argument(
            '--export-file',
            type=str,
            help='Export monitoring data to file'
        )

    def handle(self, *args, **options):
        """Main command handler"""
        self.mode = options.get('mode', 'dashboard')
        self.interval = options.get('interval', 30)
        self.duration = options.get('duration', 0)
        self.format = options.get('format', 'table')
        self.alert_threshold = options.get('alert_threshold', 100)
        self.include_idle = options.get('include_idle', False)
        self.user_id = options.get('user_id')
        self.export_file = options.get('export_file')
        self.verbosity = options.get('verbosity', 1)

        # Initialize monitoring data storage
        self.monitoring_data = deque(maxlen=100)  # Keep last 100 snapshots
        self.start_time = timezone.now()

        try:
            if self.mode == 'dashboard':
                self.run_dashboard()
            elif self.mode == 'continuous':
                self.run_continuous()
            elif self.mode == 'snapshot':
                self.run_snapshot()
            elif self.mode == 'health':
                self.run_health_check()
            elif self.mode == 'performance':
                self.run_performance_check()

        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nMonitoring interrupted by user'))
            self.cleanup()
        except Exception as e:
            logger.error(f"Error during session monitoring: {str(e)}")
            raise CommandError(f'Session monitoring failed: {str(e)}')

    def run_dashboard(self):
        """Run interactive dashboard"""
        self.stdout.write(self.style.SUCCESS('Starting Session Monitoring Dashboard'))
        self.stdout.write('Press Ctrl+C to exit\n')

        end_time = None
        if self.duration > 0:
            end_time = timezone.now() + timedelta(minutes=self.duration)

        iteration = 0
        while True:
            # Check if we should stop
            if end_time and timezone.now() >= end_time:
                break

            # Clear screen (works on most terminals)
            if iteration > 0:
                self.stdout.write('\033[2J\033[H')

            # Get and display current data
            data = self.collect_monitoring_data()
            self.display_dashboard(data)

            # Store data for export
            self.monitoring_data.append(data)

            # Wait for next iteration
            time.sleep(self.interval)
            iteration += 1

    def run_continuous(self):
        """Run continuous monitoring with streaming output"""
        self.stdout.write(self.style.SUCCESS('Starting Continuous Session Monitoring'))
        self.stdout.write('Press Ctrl+C to exit\n')

        end_time = None
        if self.duration > 0:
            end_time = timezone.now() + timedelta(minutes=self.duration)

        while True:
            # Check if we should stop
            if end_time and timezone.now() >= end_time:
                break

            # Get and display current data
            data = self.collect_monitoring_data()
            self.display_continuous(data)

            # Store data for export
            self.monitoring_data.append(data)

            # Wait for next iteration
            time.sleep(self.interval)

    def run_snapshot(self):
        """Run single snapshot"""
        self.stdout.write(self.style.SUCCESS('Session Monitoring Snapshot'))

        data = self.collect_monitoring_data()
        self.display_snapshot(data)

        if self.export_file:
            self.export_data([data])

    def run_health_check(self):
        """Run system health check"""
        self.stdout.write(self.style.SUCCESS('Session Tracking System Health Check'))

        health_data = self.collect_health_data()
        self.display_health_check(health_data)

    def run_performance_check(self):
        """Run performance analysis"""
        self.stdout.write(self.style.SUCCESS('Session Tracking Performance Analysis'))

        perf_data = self.collect_performance_data()
        self.display_performance_check(perf_data)

    def collect_monitoring_data(self):
        """Collect current monitoring data"""
        now = timezone.now()

        # Base query
        sessions_query = UserSession.objects.all()

        if self.user_id:
            sessions_query = sessions_query.filter(user_id=self.user_id)

        # Active sessions
        active_sessions = sessions_query.filter(is_active=True)

        if not self.include_idle:
            active_sessions = active_sessions.filter(is_idle=False)

        # Get session statistics
        stats = {
            'timestamp': now,
            'total_sessions': sessions_query.count(),
            'active_sessions': active_sessions.count(),
            'idle_sessions': sessions_query.filter(is_active=True, is_idle=True).count(),
            'inactive_sessions': sessions_query.filter(is_active=False).count(),
        }

        # Recent activity
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)

        stats.update({
            'sessions_last_hour': sessions_query.filter(last_activity__gte=last_hour).count(),
            'sessions_last_day': sessions_query.filter(last_activity__gte=last_day).count(),
            'new_sessions_today': sessions_query.filter(start_time__date=now.date()).count(),
        })

        # User statistics
        active_users = active_sessions.values('user_id').distinct().count()
        stats['active_users'] = active_users

        # Session duration statistics
        active_session_durations = []
        for session in active_sessions.iterator():
            if session.start_time:
                duration = (now - session.start_time).total_seconds()
                active_session_durations.append(duration)

        if active_session_durations:
            stats.update({
                'avg_session_duration': sum(active_session_durations) / len(active_session_durations),
                'max_session_duration': max(active_session_durations),
                'min_session_duration': min(active_session_durations),
            })
        else:
            stats.update({
                'avg_session_duration': 0,
                'max_session_duration': 0,
                'min_session_duration': 0,
            })

        # Activity breakdown
        activity_stats = self.get_activity_breakdown(active_sessions)
        stats.update(activity_stats)

        # System metrics
        system_stats = self.get_system_metrics()
        stats.update(system_stats)

        return stats

    def get_activity_breakdown(self, sessions):
        """Get activity breakdown for sessions"""
        activity_stats = {
            'total_page_views': 0,
            'total_clicks': 0,
            'total_keystrokes': 0,
            'avg_productivity_score': 0,
            'avg_engagement_score': 0,
        }

        productivity_scores = []
        engagement_scores = []

        for session in sessions.iterator():
            # Count activities
            if session.page_views:
                activity_stats['total_page_views'] += len(session.page_views)
            if session.clicks:
                activity_stats['total_clicks'] += len(session.clicks)
            if session.keyboard_events:
                activity_stats['total_keystrokes'] += len(session.keyboard_events)

            # Collect scores
            if session.productivity_score:
                productivity_scores.append(session.productivity_score)
            if session.engagement_score:
                engagement_scores.append(session.engagement_score)

        # Calculate averages
        if productivity_scores:
            activity_stats['avg_productivity_score'] = sum(productivity_scores) / len(productivity_scores)
        if engagement_scores:
            activity_stats['avg_engagement_score'] = sum(engagement_scores) / len(engagement_scores)

        return activity_stats

    def get_system_metrics(self):
        """Get system performance metrics"""
        metrics = {
            'cache_hits': 0,
            'cache_misses': 0,
            'db_connections': 0,
            'memory_usage': 0,
        }

        try:
            # Database connection count
            metrics['db_connections'] = len(connection.queries)

            # Cache statistics (if available)
            cache_stats = cache.get('session_tracker_stats', {})
            metrics.update(cache_stats)

            # Memory usage (basic estimation)
            import psutil
            process = psutil.Process()
            metrics['memory_usage'] = process.memory_info().rss / 1024 / 1024  # MB

        except Exception as e:
            logger.warning(f"Error collecting system metrics: {str(e)}")

        return metrics

    def collect_health_data(self):
        """Collect system health data"""
        health_data = {
            'timestamp': timezone.now(),
            'status': 'healthy',
            'issues': [],
            'recommendations': []
        }

        try:
            # Check database connectivity
            UserSession.objects.count()
            health_data['db_status'] = 'connected'
        except Exception as e:
            health_data['db_status'] = 'error'
            health_data['issues'].append(f'Database connectivity issue: {str(e)}')
            health_data['status'] = 'unhealthy'

        # Check cache connectivity
        try:
            cache.set('health_check', 'ok', 60)
            cache.get('health_check')
            health_data['cache_status'] = 'connected'
        except Exception as e:
            health_data['cache_status'] = 'error'
            health_data['issues'].append(f'Cache connectivity issue: {str(e)}')
            health_data['status'] = 'degraded'

        # Check for stuck sessions
        stuck_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=timezone.now() - timedelta(hours=2)
        ).count()

        if stuck_sessions > 0:
            health_data['issues'].append(f'{stuck_sessions} sessions appear stuck (no activity for 2+ hours)')
            health_data['recommendations'].append('Consider running cleanup command')

        # Check for excessive active sessions
        active_count = UserSession.objects.filter(is_active=True).count()
        if active_count > self.alert_threshold:
            health_data['issues'].append(f'High number of active sessions: {active_count}')
            health_data['recommendations'].append('Monitor system resources and consider scaling')

        # Check configuration
        if not CONFIG.ENABLE_ANALYTICS:
            health_data['recommendations'].append('Analytics disabled - consider enabling for better insights')

        return health_data

    def collect_performance_data(self):
        """Collect performance analysis data"""
        perf_data = {
            'timestamp': timezone.now(),
            'query_performance': {},
            'cache_performance': {},
            'session_performance': {},
            'recommendations': []
        }

        try:
            # Query performance analysis
            from django.db import connection
            query_count = len(connection.queries)
            perf_data['query_performance'] = {
                'total_queries': query_count,
                'avg_query_time': 0,
                'slow_queries': 0
            }

            # Analyze recent queries
            if connection.queries:
                query_times = [float(q['time']) for q in connection.queries[-100:]]
                perf_data['query_performance']['avg_query_time'] = sum(query_times) / len(query_times)
                perf_data['query_performance']['slow_queries'] = len([t for t in query_times if t > 1.0])

            # Session performance metrics
            recent_sessions = UserSession.objects.filter(
                start_time__gte=timezone.now() - timedelta(hours=1)
            )

            session_count = recent_sessions.count()
            if session_count > 0:
                avg_duration = recent_sessions.aggregate(
                    avg_duration=Avg('last_activity') - Avg('start_time')
                )
                perf_data['session_performance'] = {
                    'sessions_last_hour': session_count,
                    'avg_session_duration': avg_duration['avg_duration'].total_seconds() if avg_duration['avg_duration'] else 0,
                    'sessions_per_minute': session_count / 60
                }

            # Generate recommendations
            if perf_data['query_performance']['avg_query_time'] > 0.5:
                perf_data['recommendations'].append('Consider optimizing slow database queries')

            if perf_data['session_performance'].get('sessions_per_minute', 0) > 2:
                perf_data['recommendations'].append('High session creation rate - monitor system load')

        except Exception as e:
            logger.error(f"Error collecting performance data: {str(e)}")
            perf_data['error'] = str(e)

        return perf_data

    def display_dashboard(self, data):
        """Display dashboard format"""
        self.stdout.write(self.style.SUCCESS('=' * 80))
        self.stdout.write(self.style.SUCCESS('SESSION MONITORING DASHBOARD'))
        self.stdout.write(self.style.SUCCESS('=' * 80))

        # Header info
        self.stdout.write(f"Time: {data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        self.stdout.write(f"Monitoring Duration: {format_duration((data['timestamp'] - self.start_time).total_seconds())}")
        self.stdout.write("")

        # Main statistics
        self.stdout.write(self.style.SUCCESS("SESSION STATISTICS"))
        self.stdout.write("-" * 40)
        self.stdout.write(f"Total Sessions:     {data['total_sessions']:>10}")
        self.stdout.write(f"Active Sessions:    {data['active_sessions']:>10}")
        self.stdout.write(f"Idle Sessions:      {data['idle_sessions']:>10}")
        self.stdout.write(f"Inactive Sessions:  {data['inactive_sessions']:>10}")
        self.stdout.write(f"Active Users:       {data['active_users']:>10}")
        self.stdout.write("")

        # Activity statistics
        self.stdout.write(self.style.SUCCESS("ACTIVITY STATISTICS"))
        self.stdout.write("-" * 40)
        self.stdout.write(f"Sessions Last Hour: {data['sessions_last_hour']:>10}")
        self.stdout.write(f"Sessions Last Day:  {data['sessions_last_day']:>10}")
        self.stdout.write(f"New Sessions Today: {data['new_sessions_today']:>10}")
        self.stdout.write("")

        # Performance metrics
        self.stdout.write(self.style.SUCCESS("PERFORMANCE METRICS"))
        self.stdout.write("-" * 40)
        self.stdout.write(f"Avg Session Duration: {format_duration(data['avg_session_duration'])}")
        self.stdout.write(f"Max Session Duration: {format_duration(data['max_session_duration'])}")
        self.stdout.write(f"Total Page Views:     {data['total_page_views']:>10}")
        self.stdout.write(f"Total Clicks:         {data['total_clicks']:>10}")
        self.stdout.write(f"Total Keystrokes:     {data['total_keystrokes']:>10}")
        self.stdout.write("")

        # Scores
        self.stdout.write(self.style.SUCCESS("ENGAGEMENT SCORES"))
        self.stdout.write("-" * 40)
        self.stdout.write(f"Avg Productivity:   {data['avg_productivity_score']:>8.1f}")
        self.stdout.write(f"Avg Engagement:     {data['avg_engagement_score']:>8.1f}")
        self.stdout.write("")

        # System metrics
        self.stdout.write(self.style.SUCCESS("SYSTEM METRICS"))
        self.stdout.write("-" * 40)
        self.stdout.write(f"Memory Usage:       {data['memory_usage']:>8.1f} MB")
        self.stdout.write(f"DB Connections:     {data['db_connections']:>10}")
        self.stdout.write("")

        # Alerts
        if data['active_sessions'] > self.alert_threshold:
            self.stdout.write(self.style.ERROR(f"ALERT: High active session count ({data['active_sessions']})"))

    def display_continuous(self, data):
        """Display continuous monitoring format"""
        timestamp = data['timestamp'].strftime('%H:%M:%S')

        line = (
            f"[{timestamp}] "
            f"Active: {data['active_sessions']:>4} | "
            f"Idle: {data['idle_sessions']:>3} | "
            f"Users: {data['active_users']:>3} | "
            f"Memory: {data['memory_usage']:>5.1f}MB | "
            f"Productivity: {data['avg_productivity_score']:>4.1f} | "
            f"Engagement: {data['avg_engagement_score']:>4.1f}"
        )

        # Add alert indicator
        if data['active_sessions'] > self.alert_threshold:
            line += " [ALERT]"
            self.stdout.write(self.style.ERROR(line))
        else:
            self.stdout.write(line)

    def display_snapshot(self, data):
        """Display snapshot format"""
        if self.format == 'json':
            # Convert datetime to string for JSON serialization
            json_data = {k: v.isoformat() if isinstance(v, datetime) else v for k, v in data.items()}
            self.stdout.write(json.dumps(json_data, indent=2))
        elif self.format == 'csv':
            # CSV header
            if not hasattr(self, '_csv_header_written'):
                self.stdout.write(','.join(data.keys()))
                self._csv_header_written = True

            # CSV data
            values = [str(v) for v in data.values()]
            self.stdout.write(','.join(values))
        else:
            # Table format (default)
            self.display_dashboard(data)

    def display_health_check(self, health_data):
        """Display health check results"""
        status_style = self.style.SUCCESS if health_data['status'] == 'healthy' else self.style.ERROR

        self.stdout.write(status_style(f"Overall Status: {health_data['status'].upper()}"))
        self.stdout.write(f"Database: {health_data['db_status']}")
        self.stdout.write(f"Cache: {health_data['cache_status']}")
        self.stdout.write("")

        if health_data['issues']:
            self.stdout.write(self.style.ERROR("ISSUES DETECTED:"))
            for issue in health_data['issues']:
                self.stdout.write(f"  • {issue}")
            self.stdout.write("")

        if health_data['recommendations']:
            self.stdout.write(self.style.WARNING("RECOMMENDATIONS:"))
            for rec in health_data['recommendations']:
                self.stdout.write(f"  • {rec}")

    def display_performance_check(self, perf_data):
        """Display performance check results"""
        self.stdout.write(self.style.SUCCESS("PERFORMANCE ANALYSIS"))
        self.stdout.write("-" * 40)

        # Query performance
        qp = perf_data['query_performance']
        self.stdout.write(f"Database Queries:     {qp['total_queries']}")
        self.stdout.write(f"Avg Query Time:       {qp['avg_query_time']:.3f}s")
        self.stdout.write(f"Slow Queries (>1s):   {qp['slow_queries']}")
        self.stdout.write("")

        # Session performance
        sp = perf_data['session_performance']
        self.stdout.write(f"Sessions/Hour:        {sp['sessions_last_hour']}")
        self.stdout.write(f"Sessions/Minute:      {sp['sessions_per_minute']:.2f}")
        self.stdout.write(f"Avg Session Duration: {format_duration(sp['avg_session_duration'])}")
        self.stdout.write("")

        # Recommendations
        if perf_data['recommendations']:
            self.stdout.write(self.style.WARNING("RECOMMENDATIONS:"))
            for rec in perf_data['recommendations']:
                self.stdout.write(f"  • {rec}")

    def export_data(self, data_list):
        """Export monitoring data to file"""
        if not self.export_file:
            return

        try:
            with open(self.export_file, 'w') as f:
                if self.format == 'json':
                    # Convert datetime objects for JSON serialization
                    json_data = []
                    for data in data_list:
                        json_item = {k: v.isoformat() if isinstance(v, datetime) else v for k, v in data.items()}
                        json_data.append(json_item)
                    json.dump(json_data, f, indent=2)

                elif self.format == 'csv':
                    # CSV format
                    if data_list:
                        # Header
                        f.write(','.join(data_list[0].keys()) + '\n')

                        # Data rows
                        for data in data_list:
                            values = [str(v) for v in data.values()]
                            f.write(','.join(values) + '\n')

            self.stdout.write(self.style.SUCCESS(f"Data exported to {self.export_file}"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error exporting data: {str(e)}"))

    def cleanup(self):
        """Cleanup before exit"""
        if self.export_file and self.monitoring_data:
            self.export_data(list(self.monitoring_data))

        self.stdout.write(self.style.SUCCESS("Monitoring session completed"))
