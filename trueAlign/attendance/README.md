# Attendance Module

A comprehensive attendance management system built with Django, providing advanced analytics, reporting, and real-time tracking capabilities.

## Features

- **Dashboard** - Real-time attendance overview with charts
- **Regularization** - Request and approve attendance corrections
- **Reports** - Generate detailed attendance reports (Excel, CSV, PDF)
- **Analytics** - Trends, patterns, and performance metrics
- **Auto-Marking** - Automatic attendance status updates
- **API** - RESTful API with OpenAPI documentation

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Start development server
python manage.py runserver
```

## Architecture

```
attendance/
├── services/           # Business logic
│   ├── analytics.py    # Analytics calculations  
│   ├── reports.py      # Report generation
│   ├── regularization.py  # Request processing
│   ├── auto_marking.py # Status automation
│   └── bulk_ops.py     # Bulk operations
├── api/               # API infrastructure
│   ├── versioning.py  # API version management
│   └── v1_urls.py     # v1 endpoint routing
├── tests/             # Test suite
│   ├── factories.py   # Test data factories
│   ├── test_utils.py  # Utility tests
│   ├── test_services.py  # Service tests
│   ├── test_api.py    # API endpoint tests
│   └── test_integration.py  # E2E tests
├── utils.py           # Utility functions
├── config.py          # Configuration
├── exceptions.py      # Custom exceptions
├── api_responses.py   # Standard API responses
├── cache.py           # Caching utilities
└── monitoring.py      # Performance monitoring
```

## API Documentation

Interactive API documentation is available at:
- **Swagger UI**: `/api/docs/`
- **ReDoc**: `/api/redoc/`

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/attendance/dashboard/` | GET | Dashboard data |
| `/api/v1/attendance/employee/personal/` | GET | Personal attendance |
| `/api/v1/attendance/hr/analytics/` | GET | HR analytics |
| `/api/v1/attendance/export/excel/` | GET | Export to Excel |
| `/api/v1/attendance/regularization/request/` | POST | Submit regularization |
| `/api/v1/attendance/health-check/` | GET | Health check |

### API Response Format

All responses follow a standard format:

```json
{
  "success": true,
  "data": {...},
  "message": "Operation successful"
}
```

Error responses:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Description of error",
    "details": {...}
  }
}
```

## Services

### AttendanceAnalyticsService
Provides attendance analytics and statistics.

```python
from trueAlign.attendance.services.analytics import AttendanceAnalyticsService

service = AttendanceAnalyticsService()
result = service.get_status_analytics(date.today())
```

### AttendanceReportService
Generates attendance reports.

```python
from trueAlign.attendance.services.reports import AttendanceReportService

service = AttendanceReportService()
result = service.generate_monthly_report(year=2025, month=12)
```

### AttendanceRegularizationService
Handles regularization requests.

```python
from trueAlign.attendance.services.regularization import AttendanceRegularizationService

service = AttendanceRegularizationService()
result = service.submit_regularization_request(
    attendance=attendance_obj,
    requested_status='Present',
    reason='Forgot to mark',
    requested_by=user
)
```

## Caching

The module includes comprehensive caching support:

```python
from trueAlign.attendance.cache import cache_dashboard, invalidate_user_cache

@cache_dashboard(timeout=300)
def get_dashboard_data(user_id):
    ...

# Invalidate on data change
invalidate_user_cache(user.id)
```

## Monitoring

Built-in performance monitoring:

```python
from trueAlign.attendance.monitoring import monitor_performance, get_health_status

@monitor_performance('report_generation')
def generate_report():
    ...

# Check system health
status = get_health_status()
```

## Testing

Run the test suite:

```bash
# All tests
python manage.py test trueAlign.attendance.tests

# Specific test file
python manage.py test trueAlign.attendance.tests.test_utils

# With verbosity
python manage.py test trueAlign.attendance.tests -v 2
```

## Configuration

Key settings in `settings.py`:

```python
# Cache (Redis or LocMem fallback)
CACHES = {...}

# Celery (background jobs)
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'

# Sentry (optional error tracking)
SENTRY_DSN = os.environ.get('SENTRY_DSN', None)
```

## Dependencies

- Django 5.0+
- Django REST Framework
- Celery (background jobs)
- Redis (caching, optional)
- factory-boy (testing)

## License

Internal use only.
