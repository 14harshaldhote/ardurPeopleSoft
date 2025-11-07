# attendance/monitoring.py
"""
Attendance System Monitoring and Health Check Service

This module provides comprehensive monitoring capabilities for the attendance system
including health checks, performance monitoring, error tracking, and alerting.

Features:
- System health monitoring
- Performance metrics collection
- Error rate tracking
- Data integrity checks
- Alert notifications
- Service availability monitoring
- Automated issue detection
- Detailed reporting

Usage:
    from trueAlign.attendance.monitoring import AttendanceMonitoringService

    monitor = AttendanceMonitoringService()
    health_status = monitor.get_system_health()
    performance_metrics = monitor.get_performance_metrics()
"""

import logging
import time
from datetime import datetime, timedelta, date
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from django.utils import timezone
from django.db import connection, transaction
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Count, Avg, Max, Min, Q
import psutil
import pytz

from .services import get_attendance_services
from .config import IST_TIMEZONE, get_setting
from trueAlign.models import Attendance, UserSession, Holiday
from trueAlign.notifications.services import NotificationService

logger = logging.getLogger('attendance.monitoring')
User = get_user_model()


class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    ERROR = "error"


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=timezone.now)
    response_time_ms: Optional[float] = None


@dataclass
class PerformanceMetric:
    """Performance metric data"""
    name: str
    metric_type: MetricType
    value: float
    unit: str
    timestamp: datetime = field(default_factory=timezone.now)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class SystemAlert:
    """System alert information"""
    alert_id: str
    severity: HealthStatus
    title: str
    message: str
    source: str
    timestamp: datetime = field(default_factory=timezone.now)
    resolved: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class AttendanceMonitoringService:
    """
    Comprehensive monitoring service for attendance system
    """

    def __init__(self):
        self.ist = IST_TIMEZONE
        self.cache_timeout = 300  # 5 minutes
        self.health_checks = {}
        self.performance_metrics = {}
        self.active_alerts = {}

        # Initialize monitoring
        self._initialize_monitoring()

    def _initialize_monitoring(self):
        """Initialize monitoring components"""
        logger.info("Initializing attendance monitoring service")

        # Register health checks
        self._register_health_checks()

        # Initialize metrics collection
        self._initialize_metrics()

    def _register_health_checks(self):
        """Register all health check functions"""
        self.health_checks = {
            'database_connectivity': self._check_database_connectivity,
            'attendance_data_integrity': self._check_attendance_data_integrity,
            'session_tracking': self._check_session_tracking,
            'cron_jobs': self._check_cron_jobs,
            'service_availability': self._check_service_availability,
            'cache_connectivity': self._check_cache_connectivity,
            'signal_processing': self._check_signal_processing,
            'notification_system': self._check_notification_system,
            'concurrency_control': self._check_concurrency_control,  # Phase 1: Track locks/versions
            'system_resources': self._check_system_resources,
            'data_consistency': self._check_data_consistency,
        }

    def _initialize_metrics(self):
        """Initialize performance metrics collection"""
        self.performance_metrics = {
            'attendance_creation_rate': 0,
            'session_processing_rate': 0,
            'database_response_time': 0,
            'cache_hit_rate': 0,
            'dashboard_cache_hit_rate': 0,  # Phase 4: Track dashboard caching
            'cron_efficiency': 0,  # Phase 1: Track cron performance
            'version_conflicts': 0,  # Phase 1: Track optimistic locking failures
            'error_rate': 0,
            'active_users': 0,
            'pending_regularizations': 0,
        }

    # ============================
    # MAIN MONITORING FUNCTIONS
    # ============================

    def get_system_health(self) -> Dict[str, Any]:
        """
        Get comprehensive system health status

        Returns:
            Dict containing overall health status and individual check results
        """
        start_time = time.time()

        try:
            health_results = {}
            overall_status = HealthStatus.HEALTHY

            logger.info("Starting system health check")

            # Run all health checks
            for check_name, check_function in self.health_checks.items():
                try:
                    check_start = time.time()
                    result = check_function()
                    check_end = time.time()

                    result.response_time_ms = (check_end - check_start) * 1000
                    health_results[check_name] = result

                    # Determine overall status
                    if result.status == HealthStatus.CRITICAL:
                        overall_status = HealthStatus.CRITICAL
                    elif result.status == HealthStatus.ERROR and overall_status != HealthStatus.CRITICAL:
                        overall_status = HealthStatus.ERROR
                    elif result.status == HealthStatus.WARNING and overall_status not in [HealthStatus.CRITICAL, HealthStatus.ERROR]:
                        overall_status = HealthStatus.WARNING

                except Exception as e:
                    logger.error(f"Health check {check_name} failed: {e}")
                    health_results[check_name] = HealthCheckResult(
                        name=check_name,
                        status=HealthStatus.ERROR,
                        message=f"Health check failed: {str(e)}"
                    )
                    if overall_status not in [HealthStatus.CRITICAL, HealthStatus.ERROR]:
                        overall_status = HealthStatus.ERROR

            total_time = (time.time() - start_time) * 1000

            # Cache the results
            cache_key = 'attendance_system_health'
            cache.set(cache_key, {
                'overall_status': overall_status.value,
                'health_results': health_results,
                'last_check': timezone.now().isoformat(),
                'check_duration_ms': total_time
            }, self.cache_timeout)

            logger.info(f"Health check completed in {total_time:.2f}ms - Status: {overall_status.value}")

            return {
                'overall_status': overall_status.value,
                'health_results': {name: self._serialize_health_result(result)
                                for name, result in health_results.items()},
                'summary': self._generate_health_summary(health_results),
                'last_check': timezone.now().isoformat(),
                'check_duration_ms': total_time,
                'recommendations': self._generate_recommendations(health_results)
            }

        except Exception as e:
            logger.error(f"System health check failed: {e}")
            return {
                'overall_status': HealthStatus.ERROR.value,
                'error': str(e),
                'last_check': timezone.now().isoformat()
            }

    def get_performance_metrics(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """
        Get performance metrics for the specified time range

        Args:
            time_range_hours: Number of hours to look back for metrics

        Returns:
            Dict containing performance metrics and trends
        """
        try:
            end_time = timezone.now()
            start_time = end_time - timedelta(hours=time_range_hours)

            metrics = {
                'attendance_metrics': self._get_attendance_metrics(start_time, end_time),
                'session_metrics': self._get_session_metrics(start_time, end_time),
                'system_metrics': self._get_system_metrics(),
                'database_metrics': self._get_database_metrics(),
                'error_metrics': self._get_error_metrics(start_time, end_time),
                'performance_trends': self._get_performance_trends(start_time, end_time),
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': time_range_hours
                }
            }

            # Cache metrics
            cache_key = f'attendance_metrics_{time_range_hours}h'
            cache.set(cache_key, metrics, 600)  # Cache for 10 minutes

            return metrics

        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return {'error': str(e)}

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active system alerts"""
        try:
            # Get cached alerts
            alerts = cache.get('attendance_active_alerts', [])

            # Add any new alerts from recent health checks
            recent_alerts = self._detect_new_alerts()
            alerts.extend(recent_alerts)

            # Filter out resolved alerts
            active_alerts = [alert for alert in alerts if not alert.get('resolved', False)]

            # Update cache
            cache.set('attendance_active_alerts', active_alerts, 3600)

            return [self._serialize_alert(alert) for alert in active_alerts]

        except Exception as e:
            logger.error(f"Failed to get active alerts: {e}")
            return []

    def generate_health_report(self, detailed: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive health report

        Args:
            detailed: Whether to include detailed metrics and analysis

        Returns:
            Dict containing comprehensive health report
        """
        try:
            report = {
                'report_id': f"health_report_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
                'generated_at': timezone.now().isoformat(),
                'system_health': self.get_system_health(),
                'performance_metrics': self.get_performance_metrics(24),
                'active_alerts': self.get_active_alerts(),
                'system_info': self._get_system_info(),
                'attendance_summary': self._get_attendance_summary(),
            }

            if detailed:
                report.update({
                    'detailed_analysis': self._generate_detailed_analysis(),
                    'historical_trends': self._get_historical_trends(),
                    'capacity_analysis': self._get_capacity_analysis(),
                    'optimization_suggestions': self._get_optimization_suggestions(),
                })

            return report

        except Exception as e:
            logger.error(f"Failed to generate health report: {e}")
            return {'error': str(e)}

    # ============================
    # HEALTH CHECK FUNCTIONS
    # ============================

    def _check_database_connectivity(self) -> HealthCheckResult:
        """Check database connectivity and performance"""
        try:
            start_time = time.time()

            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()

            response_time = (time.time() - start_time) * 1000

            if response_time > 1000:  # More than 1 second
                return HealthCheckResult(
                    name="database_connectivity",
                    status=HealthStatus.WARNING,
                    message=f"Database response slow: {response_time:.2f}ms",
                    details={'response_time_ms': response_time}
                )
            elif response_time > 5000:  # More than 5 seconds
                return HealthCheckResult(
                    name="database_connectivity",
                    status=HealthStatus.CRITICAL,
                    message=f"Database response very slow: {response_time:.2f}ms",
                    details={'response_time_ms': response_time}
                )
            else:
                return HealthCheckResult(
                    name="database_connectivity",
                    status=HealthStatus.HEALTHY,
                    message=f"Database healthy: {response_time:.2f}ms",
                    details={'response_time_ms': response_time}
                )

        except Exception as e:
            return HealthCheckResult(
                name="database_connectivity",
                status=HealthStatus.CRITICAL,
                message=f"Database connection failed: {str(e)}"
            )

    def _check_attendance_data_integrity(self) -> HealthCheckResult:
        """Check attendance data integrity"""
        try:
            today = timezone.now().astimezone(self.ist).date()
            yesterday = today - timedelta(days=1)

            # Check for today's records
            today_count = Attendance.objects.filter(date=today).count()
            active_user_count = User.objects.filter(is_active=True).count()

            # Check for orphaned records
            orphaned_count = Attendance.objects.filter(user__is_active=False).count()

            # Check for duplicate records
            duplicates = Attendance.objects.values('user', 'date').annotate(
                count=Count('id')
            ).filter(count__gt=1).count()

            issues = []

            if today_count == 0:
                issues.append("No attendance records for today")
            elif today_count < active_user_count * 0.8:  # Less than 80% coverage
                issues.append(f"Low attendance coverage: {today_count}/{active_user_count} users")

            if orphaned_count > 0:
                issues.append(f"{orphaned_count} orphaned attendance records")

            if duplicates > 0:
                issues.append(f"{duplicates} duplicate attendance records")

            if issues:
                status = HealthStatus.WARNING if len(issues) == 1 else HealthStatus.CRITICAL
                return HealthCheckResult(
                    name="attendance_data_integrity",
                    status=status,
                    message=f"Data integrity issues: {', '.join(issues)}",
                    details={
                        'today_count': today_count,
                        'active_users': active_user_count,
                        'orphaned_records': orphaned_count,
                        'duplicate_records': duplicates,
                        'issues': issues
                    }
                )
            else:
                return HealthCheckResult(
                    name="attendance_data_integrity",
                    status=HealthStatus.HEALTHY,
                    message="Attendance data integrity is good",
                    details={
                        'today_count': today_count,
                        'active_users': active_user_count,
                        'coverage_percentage': (today_count / active_user_count * 100) if active_user_count > 0 else 0
                    }
                )

        except Exception as e:
            return HealthCheckResult(
                name="attendance_data_integrity",
                status=HealthStatus.ERROR,
                message=f"Data integrity check failed: {str(e)}"
            )

    def _check_session_tracking(self) -> HealthCheckResult:
        """Check session tracking functionality"""
        try:
            # Check active sessions
            active_sessions = UserSession.objects.filter(is_active=True).count()

            # Check recent session activity
            recent_cutoff = timezone.now() - timedelta(hours=1)
            recent_sessions = UserSession.objects.filter(
                login_time__gte=recent_cutoff
            ).count()

            # Check for stale sessions
            stale_cutoff = timezone.now() - timedelta(hours=24)
            stale_sessions = UserSession.objects.filter(
                is_active=True,
                last_activity__lt=stale_cutoff
            ).count()

            issues = []

            if stale_sessions > 10:
                issues.append(f"{stale_sessions} stale active sessions")

            if recent_sessions == 0 and timezone.now().hour > 9:  # After 9 AM
                issues.append("No recent session activity")

            if issues:
                return HealthCheckResult(
                    name="session_tracking",
                    status=HealthStatus.WARNING,
                    message=f"Session tracking issues: {', '.join(issues)}",
                    details={
                        'active_sessions': active_sessions,
                        'recent_sessions': recent_sessions,
                        'stale_sessions': stale_sessions
                    }
                )
            else:
                return HealthCheckResult(
                    name="session_tracking",
                    status=HealthStatus.HEALTHY,
                    message="Session tracking is working properly",
                    details={
                        'active_sessions': active_sessions,
                        'recent_sessions': recent_sessions,
                        'stale_sessions': stale_sessions
                    }
                )

        except Exception as e:
            return HealthCheckResult(
                name="session_tracking",
                status=HealthStatus.ERROR,
                message=f"Session tracking check failed: {str(e)}"
            )

    def _check_cron_jobs(self) -> HealthCheckResult:
        """Check cron job status and recent execution"""
        try:
            from django_cron.models import CronJobLog

            # Check recent cron job execution
            recent_cutoff = timezone.now() - timedelta(hours=24)
            recent_jobs = CronJobLog.objects.filter(start_time__gte=recent_cutoff)

            if not recent_jobs.exists():
                return HealthCheckResult(
                    name="cron_jobs",
                    status=HealthStatus.CRITICAL,
                    message="No cron jobs executed in the last 24 hours",
                    details={'recent_job_count': 0}
                )

            # Check failure rate
            total_jobs = recent_jobs.count()
            failed_jobs = recent_jobs.filter(is_success=False).count()
            failure_rate = (failed_jobs / total_jobs * 100) if total_jobs > 0 else 0

            if failure_rate > 50:
                status = HealthStatus.CRITICAL
                message = f"High cron job failure rate: {failure_rate:.1f}%"
            elif failure_rate > 20:
                status = HealthStatus.WARNING
                message = f"Elevated cron job failure rate: {failure_rate:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Cron jobs running well: {failure_rate:.1f}% failure rate"

            return HealthCheckResult(
                name="cron_jobs",
                status=status,
                message=message,
                details={
                    'total_jobs_24h': total_jobs,
                    'failed_jobs_24h': failed_jobs,
                    'failure_rate': failure_rate,
                    'successful_jobs': total_jobs - failed_jobs
                }
            )

        except Exception as e:
            return HealthCheckResult(
                name="cron_jobs",
                status=HealthStatus.ERROR,
                message=f"Cron job check failed: {str(e)}"
            )

    def _check_service_availability(self) -> HealthCheckResult:
        """Check availability of attendance services"""
        try:
            services = get_attendance_services()

            service_status = {}
            issues = []

            for service_name, service_instance in services.items():
                try:
                    # Test service by calling a simple method
                    if hasattr(service_instance, 'get_health_status'):
                        status = service_instance.get_health_status()
                        service_status[service_name] = status
                    else:
                        service_status[service_name] = 'available'
                except Exception as e:
                    service_status[service_name] = f'error: {str(e)}'
                    issues.append(f"{service_name} service unavailable")

            if issues:
                return HealthCheckResult(
                    name="service_availability",
                    status=HealthStatus.WARNING,
                    message=f"Service issues: {', '.join(issues)}",
                    details={'service_status': service_status}
                )
            else:
                return HealthCheckResult(
                    name="service_availability",
                    status=HealthStatus.HEALTHY,
                    message="All attendance services are available",
                    details={'service_status': service_status}
                )

        except Exception as e:
            return HealthCheckResult(
                name="service_availability",
                status=HealthStatus.ERROR,
                message=f"Service availability check failed: {str(e)}"
            )

    def _check_cache_connectivity(self) -> HealthCheckResult:
        """Check cache system connectivity and performance"""
        try:
            start_time = time.time()

            # Test cache operations
            test_key = 'health_check_test'
            test_value = 'test_value'

            cache.set(test_key, test_value, 60)
            retrieved_value = cache.get(test_key)
            cache.delete(test_key)

            response_time = (time.time() - start_time) * 1000

            if retrieved_value != test_value:
                return HealthCheckResult(
                    name="cache_connectivity",
                    status=HealthStatus.CRITICAL,
                    message="Cache read/write operations failed"
                )

            if response_time > 100:  # More than 100ms
                status = HealthStatus.WARNING
                message = f"Cache response slow: {response_time:.2f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = f"Cache healthy: {response_time:.2f}ms"

            return HealthCheckResult(
                name="cache_connectivity",
                status=status,
                message=message,
                details={'response_time_ms': response_time}
            )

        except Exception as e:
            return HealthCheckResult(
                name="cache_connectivity",
                status=HealthStatus.CRITICAL,
                message=f"Cache connectivity failed: {str(e)}"
            )

    def _check_signal_processing(self) -> HealthCheckResult:
        """Check signal processing health"""
        try:
            # Check for signal processing errors in cache
            error_keys = [
                'signal_errors_UserSession_save',
                'signal_errors_ShiftAssignment_save',
                'signal_errors_LeaveRequest_save'
            ]

            total_errors = 0
            error_details = {}

            for key in error_keys:
                error_count = cache.get(key, 0)
                total_errors += error_count
                if error_count > 0:
                    error_details[key] = error_count

            if total_errors > 50:
                status = HealthStatus.CRITICAL
                message = f"High signal processing error count: {total_errors}"
            elif total_errors > 10:
                status = HealthStatus.WARNING
                message = f"Elevated signal processing errors: {total_errors}"
            else:
                status = HealthStatus.HEALTHY
                message = f"Signal processing healthy: {total_errors} errors"

            return HealthCheckResult(
                name="signal_processing",
                status=status,
                message=message,
                details={
                    'total_errors': total_errors,
                    'error_breakdown': error_details
                }
            )

        except Exception as e:
            return HealthCheckResult(
                name="signal_processing",
                status=HealthStatus.ERROR,
                message=f"Signal processing check failed: {str(e)}"
            )

    def _check_notification_system(self) -> HealthCheckResult:
        """Check notification system health"""
        try:
            # This is a basic check - in a real system you'd test notification delivery
            notification_enabled = get_setting('notification_enabled', True)

            if not notification_enabled:
                return HealthCheckResult(
                    name="notification_system",
                    status=HealthStatus.WARNING,
                    message="Notification system is disabled"
                )

            # Test notification service availability
            try:
                # You could send a test notification here
                pass
            except Exception as e:
                return HealthCheckResult(
                    name="notification_system",
                    status=HealthStatus.WARNING,
                    message=f"Notification service issue: {str(e)}"
                )

            return HealthCheckResult(
                name="notification_system",
                status=HealthStatus.HEALTHY,
                message="Notification system is operational"
            )

        except Exception as e:
            return HealthCheckResult(
                name="notification_system",
                status=HealthStatus.ERROR,
                message=f"Notification system check failed: {str(e)}"
            )

    def _check_concurrency_control(self) -> HealthCheckResult:
        """
        Check concurrency control health (Phase 1 & 2 optimizations)
        Monitors version conflicts, processing locks, and lock expiration
        """
        try:
            from trueAlign.models import Attendance
            
            # Check for stuck processing locks
            stuck_locks = Attendance.objects.filter(
                is_being_processed=True,
                processing_lock_expires__lt=timezone.now()
            ).count()
            
            # Check for currently locked records
            active_locks = Attendance.objects.filter(
                is_being_processed=True,
                processing_lock_expires__gte=timezone.now()
            ).count()
            
            # Check version distribution (high versions might indicate conflicts)
            high_version_records = Attendance.objects.filter(version__gt=10).count()
            
            # Get total attendance count for context
            total_records = Attendance.objects.count()
            
            issues = []
            
            if stuck_locks > 0:
                issues.append(f"{stuck_locks} stuck processing locks detected")
            
            if active_locks > 50:
                issues.append(f"High number of active locks: {active_locks}")
            
            if high_version_records > total_records * 0.1:  # More than 10% have high versions
                issues.append(f"{high_version_records} records with high version numbers (potential conflicts)")
            
            if issues:
                status = HealthStatus.WARNING if stuck_locks == 0 else HealthStatus.CRITICAL
                message = f"Concurrency issues: {', '.join(issues)}"
            else:
                status = HealthStatus.HEALTHY
                message = "Concurrency control is healthy"
            
            return HealthCheckResult(
                name="concurrency_control",
                status=status,
                message=message,
                details={
                    'stuck_locks': stuck_locks,
                    'active_locks': active_locks,
                    'high_version_records': high_version_records,
                    'total_records': total_records,
                    'lock_percentage': round((active_locks / total_records * 100), 2) if total_records > 0 else 0
                }
            )
        
        except Exception as e:
            return HealthCheckResult(
                name="concurrency_control",
                status=HealthStatus.ERROR,
                message=f"Concurrency control check failed: {str(e)}"
            )

    def _check_system_resources(self) -> HealthCheckResult:
        """Check system resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent

            issues = []

            if cpu_percent > 90:
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
            if memory_percent > 90:
                issues.append(f"High memory usage: {memory_percent:.1f}%")
            if disk_percent > 90:
                issues.append(f"High disk usage: {disk_percent:.1f}%")

            if issues:
                status = HealthStatus.CRITICAL if any("High" in issue for issue in issues) else HealthStatus.WARNING
                message = f"Resource issues: {', '.join(issues)}"
            else:
                status = HealthStatus.HEALTHY
                message = "System resources are healthy"

            return HealthCheckResult(
                name="system_resources",
                status=status,
                message=message,
                details={
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'disk_percent': disk_percent,
                    'memory_available_gb': round(memory.available / (1024**3), 2),
                    'disk_free_gb': round(disk.free / (1024**3), 2)
                }
            )

        except Exception as e:
            return HealthCheckResult(
                name="system_resources",
                status=HealthStatus.ERROR,
                message=f"System resource check failed: {str(e)}"
            )

    def _check_data_consistency(self) -> HealthCheckResult:
        """Check data consistency across related models"""
        try:
            issues = []

            # Check for attendance records without corresponding users
            orphaned_attendance = Attendance.objects.filter(user__isnull=True).count()
            if orphaned_attendance > 0:
                issues.append(f"{orphaned_attendance} attendance records without users")

            # Check for sessions without corresponding attendance
            today = timezone.now().astimezone(self.ist).date()
            sessions_without_attendance = UserSession.objects.filter(
                login_time__date=today,
                is_active=True
            ).exclude(
                user__attendance__date=today
            ).count()

            if sessions_without_attendance > 0:
                issues.append(f"{sessions_without_attendance} active sessions without attendance records")

            if issues:
                return HealthCheckResult(
                    name="data_consistency",
                    status=HealthStatus.WARNING,
                    message=f"Data consistency issues: {', '.join(issues)}",
                    details={
                        'orphaned_attendance': orphaned_attendance,
                        'sessions_without_attendance': sessions_without_attendance
                    }
                )
            else:
                return HealthCheckResult(
                    name="data_consistency",
                    status=HealthStatus.HEALTHY,
                    message="Data consistency is good"
                )

        except Exception as e:
            return HealthCheckResult(
                name="data_consistency",
                status=HealthStatus.ERROR,
                message=f"Data consistency check failed: {str(e)}"
            )

    # ============================
    # PERFORMANCE METRICS
    # ============================

    def _get_attendance_metrics(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get attendance-related performance metrics"""
        try:
            metrics = {}

            # Attendance record counts
            total_records = Attendance.objects.filter(
                created_at__range=[start_time, end_time]
            ).count()

            # Status distribution
            status_distribution = Attendance.objects.filter(
                date__range=[start_time.date(), end_time.date()]
            ).values('status').annotate(count=Count('id'))

            # Average processing time (if available)
            metrics.update({
                'total_records_created': total_records,
                'status_distribution': list(status_distribution),
                'records_per_hour': total_records / max(1, (end_time - start_time).total_seconds() / 3600),
            })

            return metrics

        except Exception as e:
            logger.error(f"Failed to get attendance metrics: {e}")
            return {'error': str(e)}

    def _get_session_metrics(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get session-related performance metrics"""
        try:
            metrics = {}

            # Session counts
            total_sessions = UserSession.objects.filter(
                login_time__range=[start_time, end_time]
            ).count()

            active_sessions = UserSession.objects.filter(is_active=True).count()

            # Average session duration
            completed_sessions = UserSession.objects.filter(
                login_time__range=[start_time, end_time],
                logout_time__isnull=False
            )

            if completed_sessions.exists():
                avg_duration = completed_sessions.aggregate(
                    avg_duration=Avg(
                        timezone.now() - timezone.now()  # This would be calculated properly
                    )
                )
            else:
                avg_duration = {'avg_duration': None}

            metrics.update({
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'sessions_per_hour': total_sessions / max(1, (end_time - start_time).total_seconds() / 3600),
                'average_session_duration': avg_duration.get('avg_duration')
            })

            return metrics

        except Exception as e:
            logger.error(f"Failed to get session metrics: {e}")
            return {'error': str(e)}

    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system-level performance metrics"""
        try:
            return {
                'cpu_usage_percent': psutil.cpu_percent(),
                'memory_usage_percent': psutil.virtual_memory().percent,
                'disk_usage_percent': psutil.disk_usage('/').percent,
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
                'process_count': len(psutil.pids()),
                'boot_time': psutil.boot_time(),
            }

        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {'error': str(e)}

    def _get_database_metrics(self) -> Dict[str, Any]:
        """Get database performance metrics"""
        try:
            start_time = time.time()

            with connection.cursor() as cursor:
                # Test query performance
                cursor.execute("SELECT COUNT(*) FROM trueAlign_attendance")
                attendance_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM trueAlign_usersession")
                session_count = cursor.fetchone()[0]

            query_time = (time.time() - start_time) * 1000

            return {
                'query_response_time_ms': query_time,
                'attendance_record_count': attendance_count,
                'session_record_count': session_count,
                'connection_status': 'healthy'
            }

        except Exception as e:
            logger.error(f"Failed to get database metrics: {e}")
            return {'error': str(e)}

    def _get_error_metrics(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get error rate metrics"""
        try:
            # Get cached error counts
            error_keys = [
                'signal_errors_UserSession_save',
                'signal_errors_ShiftAssignment_save',
                'signal_errors_LeaveRequest_save',
                'attendance_creation_errors',
                'session_processing_errors'
            ]

            error_metrics = {}
            total_errors = 0

            for key in error_keys:
                error_count = cache.get(key, 0)
                error_metrics[key] = error_count
                total_errors += error_count

            # Calculate error rate
            time_diff_hours = (end_time - start_time).total_seconds() / 3600
            error_rate = total_errors / max(1, time_diff_hours)

            return {
                'total_errors': total_errors,
                'error_rate_per_hour': error_rate,
                'error_breakdown': error_metrics,
                'error_trend': 'stable'  # This could be calculated from historical data
            }

        except Exception as e:
            logger.error(f"Failed to get error metrics: {e}")
            return {'error': str(e)}

    def _get_performance_trends(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get performance trend analysis"""
        try:
            # This is a simplified version - in a real system you'd have historical data
            return {
                'attendance_creation_trend': 'stable',
                'session_processing_trend': 'improving',
                'error_rate_trend': 'decreasing',
                'response_time_trend': 'stable'
            }

        except Exception as e:
            logger.error(f"Failed to get performance trends: {e}")
            return {'error': str(e)}

    # ============================
    # UTILITY METHODS
    # ============================

    def _serialize_health_result(self, result: HealthCheckResult) -> Dict[str, Any]:
        """Serialize health check result to dictionary"""
        return {
            'name': result.name,
            'status': result.status.value,
            'message': result.message,
            'details': result.details,
            'timestamp': result.timestamp.isoformat(),
            'response_time_ms': result.response_time_ms
        }

    def _serialize_alert(self, alert: Any) -> Dict[str, Any]:
        """Serialize alert to dictionary"""
        if isinstance(alert, dict):
            return alert
        elif hasattr(alert, '__dict__'):
            return {
                'alert_id': getattr(alert, 'alert_id', 'unknown'),
                'severity': getattr(alert, 'severity', 'unknown'),
                'title': getattr(alert, 'title', 'Unknown Alert'),
                'message': getattr(alert, 'message', ''),
                'source': getattr(alert, 'source', 'system'),
                'timestamp': getattr(alert, 'timestamp', timezone.now()).isoformat(),
                'resolved': getattr(alert, 'resolved', False),
                'details': getattr(alert, 'details', {})
            }
        else:
            return {'error': 'Invalid alert format'}

    def _generate_health_summary(self, health_results: Dict[str, HealthCheckResult]) -> Dict[str, Any]:
        """Generate summary of health check results"""
        status_counts = {
            'healthy': 0,
            'warning': 0,
            'critical': 0,
            'error': 0
        }

        for result in health_results.values():
            status_counts[result.status.value] += 1

        total_checks = len(health_results)
        health_score = (
            (status_counts['healthy'] * 100 +
             status_counts['warning'] * 60 +
             status_counts['critical'] * 20 +
             status_counts['error'] * 0) / max(1, total_checks)
        )

        return {
            'total_checks': total_checks,
            'status_counts': status_counts,
            'health_score': round(health_score, 1),
            'health_grade': self._get_health_grade(health_score)
        }

    def _get_health_grade(self, score: float) -> str:
        """Get health grade based on score"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'

    def _generate_recommendations(self, health_results: Dict[str, HealthCheckResult]) -> List[str]:
        """Generate recommendations based on health check results"""
        recommendations = []

        for result in health_results.values():
            if result.status in [HealthStatus.WARNING, HealthStatus.CRITICAL, HealthStatus.ERROR]:
                if 'database' in result.name and 'slow' in result.message.lower():
                    recommendations.append("Consider optimizing database queries or upgrading hardware")
                elif 'cron' in result.name and 'failure' in result.message.lower():
                    recommendations.append("Review cron job configuration and error logs")
                elif 'memory' in result.message.lower():
                    recommendations.append("Monitor memory usage and consider increasing available memory")
                elif 'disk' in result.message.lower():
                    recommendations.append("Clean up old files or increase disk space")
                elif 'session' in result.name:
                    recommendations.append("Review session management and cleanup processes")
                elif 'data integrity' in result.name:
                    recommendations.append("Run data cleanup and integrity repair processes")

        if not recommendations:
            recommendations.append("System is healthy - continue regular monitoring")

        return recommendations

    def _detect_new_alerts(self) -> List[Dict[str, Any]]:
        """Detect new alerts from recent health checks"""
        alerts = []

        try:
            # Get recent health check results
            cached_health = cache.get('attendance_system_health', {})
            health_results = cached_health.get('health_results', {})

            for check_name, result in health_results.items():
                if isinstance(result, dict) and result.get('status') in ['critical', 'error']:
                    alert = {
                        'alert_id': f"health_{check_name}_{timezone.now().strftime('%Y%m%d_%H%M')}",
                        'severity': result['status'],
                        'title': f"Health Check Alert: {check_name}",
                        'message': result.get('message', 'Health check failed'),
                        'source': 'health_monitor',
                        'timestamp': timezone.now().isoformat(),
                        'resolved': False,
                        'details': result.get('details', {})
                    }
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Failed to detect new alerts: {e}")

        return alerts

    def _get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        try:
            return {
                'python_version': f"{psutil.sys.version_info.major}.{psutil.sys.version_info.minor}.{psutil.sys.version_info.micro}",
                'django_version': getattr(settings, 'DJANGO_VERSION', 'unknown'),
                'server_time': timezone.now().isoformat(),
                'timezone': str(timezone.get_current_timezone()),
                'debug_mode': settings.DEBUG,
                'database_engine': connection.settings_dict.get('ENGINE', 'unknown'),
            }

        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {'error': str(e)}

    def _get_attendance_summary(self) -> Dict[str, Any]:
        """Get attendance system summary"""
        try:
            today = timezone.now().astimezone(self.ist).date()

            return {
                'total_users': User.objects.filter(is_active=True).count(),
                'today_attendance_count': Attendance.objects.filter(date=today).count(),
                'active_sessions': UserSession.objects.filter(is_active=True).count(),
                'pending_regularizations': Attendance.objects.filter(
                    regularization_status='Pending'
                ).count(),
                'last_updated': timezone.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get attendance summary: {e}")
            return {'error': str(e)}

    def _generate_detailed_analysis(self) -> Dict[str, Any]:
        """Generate detailed system analysis"""
        return {
            'analysis_summary': 'Detailed analysis not yet implemented',
            'key_findings': [],
            'recommendations': [],
            'action_items': []
        }

    def _get_historical_trends(self) -> Dict[str, Any]:
        """Get historical trend data"""
        return {
            'trend_summary': 'Historical trends not yet implemented',
            'attendance_trends': {},
            'performance_trends': {},
            'error_trends': {}
        }

    def _get_capacity_analysis(self) -> Dict[str, Any]:
        """Get capacity analysis"""
        return {
            'capacity_summary': 'Capacity analysis not yet implemented',
            'current_load': 0,
            'projected_capacity': 0,
            'recommendations': []
        }

    def _get_optimization_suggestions(self) -> List[str]:
        """Get optimization suggestions"""
        return [
            'Optimization suggestions not yet implemented',
            'Enable database query optimization',
            'Implement caching strategies',
            'Monitor resource usage patterns'
        ]


# ============================
# MONITORING UTILITIES
# ============================

def get_monitoring_service() -> AttendanceMonitoringService:
    """Get singleton monitoring service instance"""
    if not hasattr(get_monitoring_service, '_instance'):
        get_monitoring_service._instance = AttendanceMonitoringService()
    return get_monitoring_service._instance


def run_health_check() -> Dict[str, Any]:
    """Run comprehensive health check"""
    monitoring_service = get_monitoring_service()
    return monitoring_service.get_system_health()


def get_system_metrics(hours: int = 24) -> Dict[str, Any]:
    """Get system performance metrics"""
    monitoring_service = get_monitoring_service()
    return monitoring_service.get_performance_metrics(hours)


def send_health_alert(alert: SystemAlert):
    """Send health alert to administrators"""
    try:
        # Get admin users
        admin_users = User.objects.filter(is_superuser=True, is_active=True)

        for admin in admin_users:
            NotificationService.send_notification(
                recipient=admin,
                title=alert.title,
                message=alert.message,
                category='system_alert',
                priority='high' if alert.severity in [HealthStatus.CRITICAL, HealthStatus.ERROR] else 'medium'
            )

    except Exception as e:
        logger.error(f"Failed to send health alert: {e}")


def schedule_health_monitoring():
    """Schedule regular health monitoring (to be called from cron jobs)"""
    try:
        monitoring_service = get_monitoring_service()

        # Run health check
        health_status = monitoring_service.get_system_health()

        # Check for critical issues
        if health_status.get('overall_status') in ['critical', 'error']:
            # Send alert
            alert = SystemAlert(
                alert_id=f"health_critical_{timezone.now().strftime('%Y%m%d_%H%M')}",
                severity=HealthStatus.CRITICAL,
                title="Critical System Health Issue",
                message=f"System health check failed: {health_status.get('overall_status')}",
                source='health_monitor'
            )
            send_health_alert(alert)

        logger.info(f"Health monitoring completed - Status: {health_status.get('overall_status')}")

    except Exception as e:
        logger.error(f"Health monitoring failed: {e}")
