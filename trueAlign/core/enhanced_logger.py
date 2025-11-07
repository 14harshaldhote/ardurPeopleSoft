import logging
import threading
import time
import json
from datetime import datetime, timedelta
from collections import deque, defaultdict
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
import traceback
import sys

class EnhancedSessionLogger:
    """
    Enhanced logging system for session tracking with:
    - Real-time issue detection
    - Performance monitoring
    - Anomaly detection
    - Structured logging
    - Alert generation
    """

    def __init__(self):
        # Configuration
        self.config = {
            'log_level': getattr(settings, 'SESSION_LOG_LEVEL', logging.INFO),
            'max_buffer_size': getattr(settings, 'SESSION_LOG_BUFFER_SIZE', 1000),
            'alert_threshold': getattr(settings, 'SESSION_ALERT_THRESHOLD', 10),
            'anomaly_window': getattr(settings, 'SESSION_ANOMALY_WINDOW', 300),  # 5 minutes
            'enable_real_time_alerts': getattr(settings, 'SESSION_ENABLE_ALERTS', True),
            'log_file_path': getattr(settings, 'SESSION_LOG_FILE', '/logs/session_tracking.log'),
        }

        # Thread-safe data structures
        self._buffer_lock = threading.RLock()
        self._metrics_lock = threading.RLock()
        self._alerts_lock = threading.RLock()

        # Log buffers by category
        self._log_buffers = {
            'session_creation': deque(maxlen=self.config['max_buffer_size']),
            'session_activity': deque(maxlen=self.config['max_buffer_size']),
            'race_conditions': deque(maxlen=self.config['max_buffer_size']),
            'location_updates': deque(maxlen=self.config['max_buffer_size']),
            'performance': deque(maxlen=self.config['max_buffer_size']),
            'errors': deque(maxlen=self.config['max_buffer_size']),
            'security': deque(maxlen=self.config['max_buffer_size']),
        }

        # Real-time metrics
        self._real_time_metrics = {
            'duplicate_sessions_per_minute': deque(maxlen=60),
            'short_sessions_per_minute': deque(maxlen=60),
            'location_failures_per_minute': deque(maxlen=60),
            'batch_write_failures_per_minute': deque(maxlen=60),
            'race_conditions_per_minute': deque(maxlen=60),
            'response_times': deque(maxlen=100),
            'error_rates': defaultdict(lambda: deque(maxlen=60)),
        }

        # Alert tracking
        self._active_alerts = {}
        self._alert_history = deque(maxlen=100)

        # Performance tracking
        self._performance_stats = {
            'total_sessions_created': 0,
            'total_race_conditions': 0,
            'total_short_sessions': 0,
            'total_location_failures': 0,
            'avg_session_duration': 0,
            'avg_response_time': 0,
            'error_rate': 0,
        }

        # Logger setup
        self._setup_logger()

        # Start background monitoring
        self._start_monitoring_thread()

        self.logger.info("Enhanced Session Logger initialized", extra={
            'event_type': 'system_init',
            'config': self.config
        })

    def _setup_logger(self):
        """
        Setup structured logger with custom formatter
        """
        self.logger = logging.getLogger('session_tracker')
        self.logger.setLevel(self.config['log_level'])

        # Avoid duplicate handlers
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.config['log_level'])

            # File handler
            try:
                file_handler = logging.FileHandler(self.config['log_file_path'])
                file_handler.setLevel(self.config['log_level'])
            except Exception:
                file_handler = None

            # Custom formatter for structured logging
            formatter = SessionLogFormatter()
            console_handler.setFormatter(formatter)
            if file_handler:
                file_handler.setFormatter(formatter)

            self.logger.addHandler(console_handler)
            if file_handler:
                self.logger.addHandler(file_handler)

    def log_session_creation(self, user, session_id, tab_id, duration_ms, created=True, race_condition=False):
        """
        Log session creation with anomaly detection
        """
        event_data = {
            'event_type': 'session_creation',
            'user_id': user.id,
            'username': user.username,
            'session_id': str(session_id),
            'tab_id': tab_id,
            'duration_ms': duration_ms,
            'created': created,
            'race_condition': race_condition,
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['session_creation'].append(event_data)

        # Update real-time metrics
        self._update_session_metrics(event_data)

        # Log message
        level = logging.WARNING if race_condition else logging.INFO
        message = f"Session {'created' if created else 'reused'} for {user.username}"
        if race_condition:
            message += " (race condition detected)"

        self.logger.log(level, message, extra=event_data)

        # Check for anomalies
        self._check_session_anomalies(user, event_data)

    def log_duplicate_session(self, user, tab_id, existing_session_id, duration_between_requests):
        """
        Log duplicate session creation attempts
        """
        event_data = {
            'event_type': 'duplicate_session',
            'user_id': user.id,
            'username': user.username,
            'tab_id': tab_id,
            'existing_session_id': str(existing_session_id),
            'duration_between_requests': duration_between_requests,
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['race_conditions'].append(event_data)

        # Update metrics
        with self._metrics_lock:
            self._real_time_metrics['duplicate_sessions_per_minute'].append(time.time())
            self._performance_stats['total_race_conditions'] += 1

        self.logger.warning(
            f"Duplicate session creation attempt for {user.username}, tab_id: {tab_id}",
            extra=event_data
        )

        # Generate alert if threshold exceeded
        self._check_duplicate_session_alert(user)

    def log_short_session(self, user, session_id, duration_seconds, reason):
        """
        Log short-lived sessions for analysis
        """
        event_data = {
            'event_type': 'short_session',
            'user_id': user.id,
            'username': user.username,
            'session_id': str(session_id),
            'duration_seconds': duration_seconds,
            'reason': reason,
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['session_activity'].append(event_data)

        # Update metrics
        with self._metrics_lock:
            self._real_time_metrics['short_sessions_per_minute'].append(time.time())
            self._performance_stats['total_short_sessions'] += 1

        self.logger.warning(
            f"Short session detected for {user.username}: {duration_seconds}s",
            extra=event_data
        )

        # Check for patterns
        self._check_short_session_patterns(user)

    def log_location_update(self, user, session_id, location_data, success=True, error=None):
        """
        Log location update attempts
        """
        event_data = {
            'event_type': 'location_update',
            'user_id': user.id,
            'username': user.username,
            'session_id': str(session_id),
            'success': success,
            'has_coordinates': bool(location_data and 'latitude' in location_data),
            'accuracy': location_data.get('accuracy') if location_data else None,
            'error': str(error) if error else None,
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['location_updates'].append(event_data)

        # Update metrics
        if not success:
            with self._metrics_lock:
                self._real_time_metrics['location_failures_per_minute'].append(time.time())
                self._performance_stats['total_location_failures'] += 1

        level = logging.ERROR if not success else logging.DEBUG
        message = f"Location update {'succeeded' if success else 'failed'} for {user.username}"

        self.logger.log(level, message, extra=event_data)

        # Alert on frequent location failures
        if not success:
            self._check_location_failure_alert(user)

    def log_batch_write_performance(self, user_id, activity_count, duration_ms, success=True, error=None):
        """
        Log batch write performance
        """
        event_data = {
            'event_type': 'batch_write_performance',
            'user_id': user_id,
            'activity_count': activity_count,
            'duration_ms': duration_ms,
            'success': success,
            'activities_per_second': (activity_count / (duration_ms / 1000)) if duration_ms > 0 else 0,
            'error': str(error) if error else None,
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['performance'].append(event_data)

        # Update performance metrics
        with self._metrics_lock:
            self._real_time_metrics['response_times'].append(duration_ms)
            if not success:
                self._real_time_metrics['batch_write_failures_per_minute'].append(time.time())

        level = logging.ERROR if not success else logging.DEBUG
        message = f"Batch write {'completed' if success else 'failed'}: {activity_count} activities in {duration_ms}ms"

        self.logger.log(level, message, extra=event_data)

    def log_error(self, error_type, message, user=None, session_id=None, details=None):
        """
        Log errors with context and stack trace
        """
        event_data = {
            'event_type': 'error',
            'error_type': error_type,
            'error_detail': message,  # Renamed from 'message' to avoid LogRecord conflict
            'user_id': user.id if user else None,
            'username': user.username if user else None,
            'session_id': str(session_id) if session_id else None,
            'details': details or {},
            'stack_trace': traceback.format_exc(),
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['errors'].append(event_data)

        # Update error metrics
        with self._metrics_lock:
            self._real_time_metrics['error_rates'][error_type].append(time.time())

        self.logger.error(f"Session tracking error: {error_type} - {message}", extra=event_data)

        # Generate alert for critical errors
        self._check_error_alert(error_type, message)

    def log_security_event(self, event_type, user, details, severity='medium'):
        """
        Log security-related events
        """
        event_data = {
            'event_type': 'security_event',
            'security_event_type': event_type,
            'user_id': user.id,
            'username': user.username,
            'severity': severity,
            'details': details,
            'timestamp': timezone.now().isoformat()
        }

        with self._buffer_lock:
            self._log_buffers['security'].append(event_data)

        level = logging.CRITICAL if severity == 'high' else logging.WARNING
        self.logger.log(level, f"Security event: {event_type} for {user.username}", extra=event_data)

        # Generate immediate alert for high severity
        if severity == 'high':
            self._generate_alert('security_alert', f"High severity security event: {event_type}", event_data)

    def _update_session_metrics(self, event_data):
        """
        Update session-related metrics
        """
        with self._metrics_lock:
            self._performance_stats['total_sessions_created'] += 1

            if event_data.get('race_condition'):
                self._real_time_metrics['race_conditions_per_minute'].append(time.time())

    def _check_session_anomalies(self, user, event_data):
        """
        Check for session creation anomalies
        """
        if not self.config['enable_real_time_alerts']:
            return

        # Check for rapid session creation
        recent_sessions = [
            log for log in self._log_buffers['session_creation']
            if (log['user_id'] == user.id and
                (time.time() - datetime.fromisoformat(log['timestamp']).timestamp()) < 60)
        ]

        if len(recent_sessions) > 5:  # More than 5 sessions in 1 minute
            self._generate_alert(
                'rapid_session_creation',
                f"User {user.username} created {len(recent_sessions)} sessions in 1 minute",
                {'user_id': user.id, 'session_count': len(recent_sessions)}
            )

    def _check_duplicate_session_alert(self, user):
        """
        Check if duplicate session rate exceeds threshold
        """
        current_time = time.time()
        recent_duplicates = [
            t for t in self._real_time_metrics['duplicate_sessions_per_minute']
            if current_time - t < 300  # 5 minutes
        ]

        if len(recent_duplicates) > self.config['alert_threshold']:
            self._generate_alert(
                'excessive_duplicates',
                f"User {user.username} has {len(recent_duplicates)} duplicate sessions in 5 minutes",
                {'user_id': user.id, 'duplicate_count': len(recent_duplicates)}
            )

    def _check_short_session_patterns(self, user):
        """
        Check for patterns in short sessions
        """
        recent_short = [
            log for log in self._log_buffers['session_activity']
            if (log['user_id'] == user.id and
                log['event_type'] == 'short_session' and
                (time.time() - datetime.fromisoformat(log['timestamp']).timestamp()) < 300)
        ]

        if len(recent_short) > 3:  # More than 3 short sessions in 5 minutes
            self._generate_alert(
                'frequent_short_sessions',
                f"User {user.username} has {len(recent_short)} short sessions in 5 minutes",
                {'user_id': user.id, 'short_session_count': len(recent_short)}
            )

    def _check_location_failure_alert(self, user):
        """
        Check for location update failure patterns
        """
        current_time = time.time()
        recent_failures = [
            t for t in self._real_time_metrics['location_failures_per_minute']
            if current_time - t < 300  # 5 minutes
        ]

        if len(recent_failures) > 5:
            self._generate_alert(
                'location_update_failures',
                f"User {user.username} has {len(recent_failures)} location failures in 5 minutes",
                {'user_id': user.id, 'failure_count': len(recent_failures)}
            )

    def _check_error_alert(self, error_type, message):
        """
        Check if error rate exceeds threshold
        """
        current_time = time.time()
        recent_errors = [
            t for t in self._real_time_metrics['error_rates'][error_type]
            if current_time - t < 300  # 5 minutes
        ]

        if len(recent_errors) > self.config['alert_threshold']:
            self._generate_alert(
                f'error_spike_{error_type}',
                f"Error spike detected: {error_type} occurred {len(recent_errors)} times in 5 minutes",
                {'error_type': error_type, 'error_count': len(recent_errors), 'error_detail': message}  # Renamed from 'message'
            )

    def _generate_alert(self, alert_type, message, data=None):
        """
        Generate alert and store in alert tracking
        """
        alert_id = f"{alert_type}_{int(time.time())}"

        alert = {
            'id': alert_id,
            'type': alert_type,
            'alert_message': message,  # Renamed from 'message' to avoid LogRecord conflict
            'data': data or {},
            'timestamp': timezone.now().isoformat(),
            'resolved': False
        }

        with self._alerts_lock:
            self._active_alerts[alert_id] = alert
            self._alert_history.append(alert)

        # Log the alert
        self.logger.critical(f"ALERT: {message}", extra={
            'event_type': 'alert',
            'alert_type': alert_type,
            'alert_id': alert_id,
            **alert
        })

        # Store in cache for external access
        cache.set(f"session_alert_{alert_id}", alert, 3600)  # 1 hour

    def _start_monitoring_thread(self):
        """
        Start background thread for continuous monitoring
        """
        self._shutdown_event = threading.Event()
        self._monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True)
        self._monitor_thread.start()

    def _monitor_worker(self):
        """
        Background worker for monitoring and cleanup
        """
        while not self._shutdown_event.is_set():
            try:
                # Clean old metrics
                self._cleanup_old_metrics()

                # Generate periodic performance reports
                self._generate_performance_report()

                # Auto-resolve old alerts
                self._auto_resolve_alerts()

                # Sleep for 30 seconds
                self._shutdown_event.wait(30)

            except Exception as e:
                self.logger.error(f"Error in monitoring worker: {str(e)}")
                self._shutdown_event.wait(30)

    def _cleanup_old_metrics(self):
        """
        Clean old metrics data
        """
        current_time = time.time()
        cutoff_time = current_time - 3600  # 1 hour

        with self._metrics_lock:
            for metric_name, metric_deque in self._real_time_metrics.items():
                if isinstance(metric_deque, deque):
                    # Remove old entries
                    while metric_deque and metric_deque[0] < cutoff_time:
                        metric_deque.popleft()
                elif isinstance(metric_deque, defaultdict):
                    for sub_metric in metric_deque.values():
                        while sub_metric and sub_metric[0] < cutoff_time:
                            sub_metric.popleft()

    def _generate_performance_report(self):
        """
        Generate periodic performance report
        """
        try:
            current_time = time.time()
            hour_ago = current_time - 3600

            # Calculate metrics for last hour
            recent_response_times = [
                t for t in self._real_time_metrics['response_times']
                if isinstance(t, (int, float))
            ]

            if recent_response_times:
                avg_response_time = sum(recent_response_times) / len(recent_response_times)
            else:
                avg_response_time = 0

            # Count recent events
            recent_duplicates = len([
                t for t in self._real_time_metrics['duplicate_sessions_per_minute']
                if t > hour_ago
            ])

            recent_short_sessions = len([
                t for t in self._real_time_metrics['short_sessions_per_minute']
                if t > hour_ago
            ])

            report = {
                'event_type': 'performance_report',
                'period': 'last_hour',
                'avg_response_time_ms': avg_response_time,
                'duplicate_sessions': recent_duplicates,
                'short_sessions': recent_short_sessions,
                'active_alerts': len(self._active_alerts),
                'timestamp': timezone.now().isoformat()
            }

            self.logger.info("Hourly performance report", extra=report)

        except Exception as e:
            self.logger.error(f"Error generating performance report: {str(e)}")

    def _auto_resolve_alerts(self):
        """
        Auto-resolve old alerts
        """
        current_time = time.time()
        cutoff_time = current_time - 3600  # 1 hour

        with self._alerts_lock:
            resolved_alerts = []
            for alert_id, alert in self._active_alerts.items():
                alert_time = datetime.fromisoformat(alert['timestamp']).timestamp()
                if alert_time < cutoff_time and not alert['resolved']:
                    alert['resolved'] = True
                    alert['resolved_at'] = timezone.now().isoformat()
                    resolved_alerts.append(alert_id)

            for alert_id in resolved_alerts:
                del self._active_alerts[alert_id]

    def get_recent_logs(self, category=None, limit=100):
        """
        Get recent logs for analysis
        """
        with self._buffer_lock:
            if category and category in self._log_buffers:
                return list(self._log_buffers[category])[-limit:]
            else:
                all_logs = []
                for buffer in self._log_buffers.values():
                    all_logs.extend(list(buffer))
                return sorted(all_logs, key=lambda x: x['timestamp'])[-limit:]

    def get_active_alerts(self):
        """
        Get currently active alerts
        """
        with self._alerts_lock:
            return list(self._active_alerts.values())

    def get_performance_metrics(self):
        """
        Get current performance metrics
        """
        with self._metrics_lock:
            metrics = self._performance_stats.copy()

        # Add real-time calculations
        current_time = time.time()
        hour_ago = current_time - 3600

        metrics.update({
            'recent_response_times': len([
                t for t in self._real_time_metrics['response_times']
                if isinstance(t, (int, float))
            ]),
            'duplicates_last_hour': len([
                t for t in self._real_time_metrics['duplicate_sessions_per_minute']
                if t > hour_ago
            ]),
            'short_sessions_last_hour': len([
                t for t in self._real_time_metrics['short_sessions_per_minute']
                if t > hour_ago
            ]),
            'active_alerts_count': len(self._active_alerts),
        })

        return metrics

    def shutdown(self):
        """
        Graceful shutdown
        """
        self.logger.info("Shutting down Enhanced Session Logger")

        if hasattr(self, '_shutdown_event'):
            self._shutdown_event.set()

        if hasattr(self, '_monitor_thread') and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10)

class SessionLogFormatter(logging.Formatter):
    """
    Custom formatter for structured session logs
    """

    def format(self, record):
        # Base log entry
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'log_message': record.getMessage(),  # Renamed from 'message' to avoid LogRecord conflict
        }

        # Add extra fields
        if hasattr(record, 'event_type'):
            log_entry['event_type'] = record.event_type

        # Add all extra attributes
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info', 'message']:
                log_entry[key] = value

        return json.dumps(log_entry)

# Global instance
_session_logger_instance = None

def get_session_logger():
    """
    Get singleton session logger instance
    """
    global _session_logger_instance
    if _session_logger_instance is None:
        _session_logger_instance = EnhancedSessionLogger()
    return _session_logger_instance
