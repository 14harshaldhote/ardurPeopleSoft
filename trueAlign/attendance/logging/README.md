# Attendance Logging System Documentation

## Overview

The Attendance Logging System provides comprehensive logging capabilities for all attendance-related operations in the TrueAlign system. It offers structured, categorized logging with automatic file rotation, performance monitoring, and security event tracking.

## Features

- **Component-based logging**: Separate loggers for different attendance components
- **Operation-specific logging**: Dedicated loggers for specific operations (clock in/out, regularization, etc.)
- **Automatic log rotation**: Prevents log files from growing too large
- **Performance monitoring**: Tracks operation timing and metrics
- **Security event logging**: Monitors unauthorized access and suspicious activities
- **Structured log format**: Consistent, parseable log entries
- **Error handling**: Comprehensive error logging with context

## Log File Structure

All attendance logs are stored in `logs/attendance/` directory:

```
logs/attendance/
├── attendance.log                    # Main attendance system logs
├── attendance_api.log               # API requests and responses
├── attendance_operations.log        # Clock in/out and user operations
├── attendance_cron.log             # Scheduled tasks and cron jobs
├── attendance_errors.log           # System errors and exceptions
├── attendance_security.log         # Security events and alerts
├── attendance_performance.log      # Performance metrics and timing
├── attendance_regularization.log   # Regularization requests and approvals
└── attendance_exports.log          # Data exports and report generation
```

## Logger Categories

### Component Loggers

| Logger Name | Purpose | Log Files |
|-------------|---------|-----------|
| `trueAlign.attendance` | Main attendance system | attendance.log |
| `trueAlign.attendance.views` | Django views | attendance.log, attendance_operations.log |
| `trueAlign.attendance.api_views` | API endpoints | attendance_api.log, attendance.log |
| `trueAlign.attendance.services` | Business logic services | attendance.log, attendance_operations.log |
| `trueAlign.attendance.cron` | Scheduled tasks | attendance_cron.log |
| `trueAlign.attendance.security` | Security events | attendance_security.log, attendance_errors.log |
| `trueAlign.attendance.performance` | Performance metrics | attendance_performance.log |

### Operation Loggers

| Operation | Logger Name | Use Case |
|-----------|-------------|----------|
| Clock In | `trueAlign.attendance.operations.clock_in` | User clock-in events |
| Clock Out | `trueAlign.attendance.operations.clock_out` | User clock-out events |
| Regularization | `trueAlign.attendance.operations.regularization_request` | Regularization requests |
| Data Export | `trueAlign.attendance.operations.data_export` | Report and data exports |
| Bulk Updates | `trueAlign.attendance.operations.bulk_update` | Bulk data operations |
| Cron Jobs | `trueAlign.attendance.operations.cron_jobs` | Automated tasks |

## Usage Examples

### Basic Logging

```python
from trueAlign.attendance.logging import get_attendance_logger, log_attendance_action

# Get a logger for your component
logger = get_attendance_logger('views')
logger.info("Dashboard accessed")

# Log user actions with structured data
log_attendance_action(
    user=request.user,
    action="Clock in successful",
    details={
        'timestamp': timezone.now().isoformat(),
        'location': 'Office Building A',
        'device': 'Web Browser'
    },
    level='info',
    operation='clock_in'
)
```

### Error Logging

```python
from trueAlign.attendance.logging import log_attendance_error

try:
    # Your attendance operation
    process_attendance(user)
except Exception as e:
    log_attendance_error(
        user=user,
        operation='attendance_processing',
        error=e,
        context={
            'function': 'process_attendance',
            'input_data': 'user_attendance_records'
        }
    )
```

### Performance Monitoring

```python
from trueAlign.attendance.logging import log_performance_metric
import time

start_time = time.time()
# Your operation
result = generate_attendance_report(user)
duration = time.time() - start_time

log_performance_metric(
    operation='report_generation',
    duration=duration,
    user=user,
    additional_metrics={
        'record_count': len(result),
        'report_type': 'monthly'
    }
)
```

### Using Decorators

```python
from trueAlign.attendance.logging.utils import log_attendance_operation

@log_attendance_operation('clock_in', level='info')
def clock_in_user(user, timestamp=None):
    # Your clock-in logic here
    # Timing and error handling are automatic
    return clock_in_result
```

### Using Context Manager

```python
from trueAlign.attendance.logging.utils import AttendanceOperationLogger

def bulk_update_attendance(user, records):
    with AttendanceOperationLogger('bulk_update', user=user) as op_logger:
        for record in records:
            # Process each record
            update_attendance_record(record)
            op_logger.logger.debug(f"Updated record {record.id}")
```

### Using Mixin in Classes

```python
from trueAlign.attendance.logging import AttendanceLoggerMixin

class AttendanceService(AttendanceLoggerMixin):
    def calculate_hours(self, user, date_range):
        self.log_info(f"Calculating hours for {user.username}")
        
        try:
            hours = self._perform_calculation(date_range)
            self.log_info(f"Calculation completed: {hours} hours")
            return hours
        except Exception as e:
            self.log_error(f"Calculation failed: {e}")
            raise
```

## Django Views Integration

### API Views

```python
from trueAlign.attendance.logging.utils import log_api_access
import time

def attendance_dashboard_api(request):
    start_time = time.time()
    
    try:
        # Your API logic here
        data = get_dashboard_data(request.user)
        
        duration = time.time() - start_time
        log_api_access(
            request=request,
            endpoint='attendance_dashboard',
            response_status=200,
            duration=duration,
            data_count=len(data)
        )
        
        return JsonResponse({'data': data})
        
    except Exception as e:
        duration = time.time() - start_time
        log_api_access(
            request=request,
            endpoint='attendance_dashboard',
            response_status=500,
            duration=duration
        )
        # Handle error...
```

### Regular Views

```python
from trueAlign.attendance.logging import log_data_access

@login_required
def attendance_report_view(request):
    # Log data access
    log_data_access(
        user=request.user,
        data_type='attendance_reports',
        action='view',
        filters={
            'date_range': request.GET.get('date_range'),
            'department': request.GET.get('department')
        }
    )
    
    # Your view logic...
```

## Cron Jobs and Management Commands

```python
from trueAlign.attendance.logging.utils import log_cron_job_execution
import time

def daily_attendance_processing():
    job_name = "daily_attendance_auto_marking"
    start_time = time.time()
    
    try:
        log_cron_job_execution(job_name, 'started')
        
        # Your cron job logic
        processed_count = process_daily_attendance()
        
        duration = time.time() - start_time
        log_cron_job_execution(
            job_name=job_name,
            status='completed',
            duration=duration,
            records_processed=processed_count
        )
        
    except Exception as e:
        duration = time.time() - start_time
        log_cron_job_execution(
            job_name=job_name,
            status='failed',
            duration=duration,
            errors=[str(e)]
        )
```

## Security Event Logging

```python
from trueAlign.attendance.logging import log_security_event
from trueAlign.attendance.logging.utils import log_authentication_event

# Log suspicious activity
log_security_event(
    user=request.user,
    event_type='suspicious_activity',
    description='Multiple rapid API calls detected',
    severity='warning',
    ip_address=get_client_ip(request)
)

# Log authentication events
log_authentication_event(
    user=user,
    event_type='login',
    request=request,
    success=True
)
```

## Configuration

### Django Settings

The logging configuration is automatically included in `settings.py`. The system creates the following handlers:

- **attendance_file**: Main attendance logs
- **attendance_api_file**: API-specific logs
- **attendance_operations_file**: User operations
- **attendance_cron_file**: Scheduled tasks
- **attendance_errors_file**: Error logs
- **attendance_security_file**: Security events
- **attendance_performance_file**: Performance metrics
- **attendance_regularization_file**: Regularization workflows
- **attendance_exports_file**: Data exports

### Log Rotation

- **Max file size**: 15-20MB per file
- **Backup count**: 5-10 backup files
- **Retention**: 90 days (configurable)
- **Compression**: Automatic for old files

## Best Practices

### 1. Use Appropriate Log Levels

```python
logger.debug("Detailed debugging information")
logger.info("General information about operations")
logger.warning("Something unexpected happened")
logger.error("A serious error occurred")
logger.critical("System failure")
```

### 2. Include Relevant Context

```python
log_attendance_action(
    user=user,
    action="Clock in",
    details={
        'timestamp': timezone.now().isoformat(),
        'location': location,
        'device_type': device_type,
        'ip_address': ip_address
    }
)
```

### 3. Monitor Performance

```python
# For operations that might be slow
start_time = time.time()
result = expensive_operation()
duration = time.time() - start_time

log_performance_metric('expensive_operation', duration, user)
```

### 4. Security Logging

```python
# Log security-sensitive operations
log_security_event(
    user=user,
    event_type='data_access',
    description=f'Accessed sensitive attendance data for {target_user.username}',
    severity='info'
)
```

## Management Commands

### Initialize Logging System

```bash
python manage.py setup_attendance_logging --action=init
```

### Check System Status

```bash
python manage.py setup_attendance_logging --action=status --verbose
```

### Clean Up Old Logs

```bash
python manage.py setup_attendance_logging --action=cleanup --max-age=90
```

### Test Logging

```bash
python manage.py setup_attendance_logging --action=test
```

### Validate Configuration

```bash
python manage.py setup_attendance_logging --action=validate
```

## Testing

Run the test script to validate your logging setup:

```bash
python test_attendance_logging.py
```

This will:
- Verify all loggers are working
- Test log file creation
- Generate sample log entries
- Validate error handling
- Show log file contents

## Monitoring and Maintenance

### Log File Monitoring

Check log file sizes regularly:

```bash
ls -lh logs/attendance/
```

### Performance Threshold Alerts

The system logs warnings for:
- Operations taking > 5 seconds
- API responses > 2 seconds
- Database queries > 1 second

### Security Monitoring

Security events are logged for:
- Failed login attempts
- Unauthorized access attempts
- Suspicious activity patterns
- Data access by administrators

## Troubleshooting

### Common Issues

1. **Log files not created**
   - Check directory permissions: `ls -la logs/`
   - Verify Django settings: `python manage.py check`

2. **Logs not appearing**
   - Check log level settings
   - Verify logger names match configuration
   - Test with: `python test_attendance_logging.py`

3. **Large log files**
   - Run cleanup: `python manage.py setup_attendance_logging --action=cleanup`
   - Check rotation settings in `settings.py`

4. **Permission errors**
   - Ensure web server can write to log directory
   - Check SELinux/AppArmor policies if applicable

### Debug Mode

Enable debug logging temporarily:

```python
import logging
logging.getLogger('trueAlign.attendance').setLevel(logging.DEBUG)
```

## Log Analysis

### Useful Commands

```bash
# View recent attendance errors
tail -f logs/attendance/attendance_errors.log

# Search for specific user activities
grep "User: john.doe" logs/attendance/attendance.log

# Monitor API performance
grep "Duration:" logs/attendance/attendance_performance.log | tail -20

# Check security events
tail -f logs/attendance/attendance_security.log

# Monitor cron job execution
grep "Cron job:" logs/attendance/attendance_cron.log
```

### Log Format Examples

**Standard Log Entry:**
```
[2024-12-12 14:30:15] INFO - trueAlign.attendance.views - User: john.doe | Action: Clock in successful | Details: location: Office A | device: Web Browser
```

**Performance Log Entry:**
```
INFO|2024-12-12 14:30:15|performance|12345|67890|User: john.doe | Operation: dashboard_load | Duration: 0.245s | Metrics: record_count: 150
```

**Error Log Entry:**
```
[2024-12-12 14:30:15] ERROR - trueAlign.attendance.services - User: john.doe | Operation: calculate_hours | Error: Division by zero | Context: date_range: 2024-12-01 to 2024-12-12
```

## Integration Checklist

- [ ] Import logging functions in your modules
- [ ] Add logging calls to critical operations
- [ ] Test logging functionality
- [ ] Set up log monitoring
- [ ] Configure log rotation
- [ ] Set up alerting for critical errors
- [ ] Document logging conventions for your team

## Support

For issues with the attendance logging system:

1. Run the test script: `python test_attendance_logging.py`
2. Check the Django logs for configuration errors
3. Verify file permissions on the logs directory
4. Review the examples in `logging/examples.py`

## Version

Version: 1.0  
Created: December 2024  
Last Updated: December 2024