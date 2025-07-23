# Leave Management System - Comprehensive Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation](#installation)
5. [User Guides](#user-guides)
6. [API Documentation](#api-documentation)
7. [Testing](#testing)
8. [Development Guide](#development-guide)
9. [Troubleshooting](#troubleshooting)
10. [Contributing](#contributing)

## Overview

The Leave Management System is a comprehensive, modernized Django-based application designed to handle all aspects of employee leave management for organizations. Built with modern web technologies and best practices, it provides role-based dashboards, automated workflows, and real-time analytics.

### Key Highlights
- **Modern Architecture**: Uses Class-Based Views (CBVs), service layers, and separation of concerns
- **Role-Based Access**: Different dashboards and permissions for Employee, Manager, HR, Finance, and Management roles
- **Real-time Updates**: HTMX integration for dynamic UI updates without page reloads
- **Comprehensive API**: RESTful APIs for all operations with AJAX/HTMX support
- **Advanced Analytics**: Detailed reporting and analytics for workforce planning
- **Mobile Responsive**: Tailwind CSS for modern, responsive design
- **Scalable**: Designed to handle large organizations with thousands of employees

## Architecture

### Design Patterns
- **Model-View-Controller (MVC)**: Clean separation of concerns
- **Service Layer Pattern**: Business logic encapsulated in service classes
- **Repository Pattern**: Data access abstraction through Django ORM
- **Decorator Pattern**: Permission and validation decorators
- **Observer Pattern**: Notification system for leave events

### Technology Stack
- **Backend**: Django 4.x, Python 3.8+
- **Frontend**: HTML5, Tailwind CSS, HTMX, Chart.js
- **Database**: PostgreSQL (recommended), MySQL, SQLite
- **Caching**: Redis (optional)
- **Task Queue**: Celery (for background tasks)
- **Testing**: Django TestCase, Factory Boy, Mock

### Project Structure
```
trueAlign/leave/
├── api_views.py           # API endpoints for AJAX/HTMX
├── api_urls.py            # API URL configuration
├── decorators.py          # Permission and utility decorators
├── forms.py               # Form classes with validation
├── mixins.py              # Reusable view mixins
├── models.py              # Database models (in main models.py)
├── services.py            # Business logic services
├── urls.py                # URL configuration
├── views.py               # View classes
├── templates/leave/       # Template files
│   ├── dashboards/        # Role-based dashboard templates
│   ├── requests/          # Leave request templates
│   ├── admin/             # Admin interface templates
│   └── reports/           # Report templates
└── tests/                 # Comprehensive test suite
    ├── test_api_views.py  # API endpoint tests
    ├── test_comprehensive_*.py # Integration tests
    └── test_runner.py     # Test utilities
```

## Features

### 1. Role-Based Dashboards

#### Employee Dashboard
- Personal leave balance overview
- Quick leave application
- Leave history and status tracking
- Upcoming leave reminders
- Leave calendar view

#### Manager Dashboard
- Team leave overview
- Pending approval notifications
- Team availability tracking
- Quick approval/rejection actions
- Team calendar and scheduling

#### HR Dashboard
- Organization-wide leave statistics
- Policy and allocation management
- Bulk operations and imports
- Advanced reporting and analytics
- User balance management

#### Finance Dashboard
- Leave cost analysis
- Budget tracking and alerts
- Financial impact reporting
- Cost optimization insights
- Budget utilization metrics

#### Management Dashboard
- Strategic leave insights
- Workforce planning analytics
- Compliance monitoring
- Executive reporting
- Risk indicators

### 2. Leave Management Features

#### Leave Types
- Configurable leave types (Annual, Sick, Personal, etc.)
- Customizable rules per leave type
- Documentation requirements
- Approval workflows
- Half-day support

#### Leave Policies
- Group-based policy assignment
- Flexible allocation rules
- Carry-forward configurations
- Advance notice requirements
- Consecutive day limits

#### Approval Workflow
- Multi-level approval support
- Automatic routing based on rules
- Bulk approval capabilities
- Email/notification integration
- Audit trail maintenance

#### Balance Management
- Automatic balance calculations
- Manual balance adjustments
- Carry-forward processing
- Comp-off management
- Real-time balance updates

### 3. Advanced Features

#### Calendar Integration
- Personal leave calendar
- Team availability view
- Organization-wide calendar
- Holiday management
- Conflict detection

#### Reporting & Analytics
- Comprehensive leave reports
- Trend analysis
- Departmental insights
- Executive summaries
- Custom report generation

#### API & Integration
- RESTful API endpoints
- HTMX for dynamic updates
- Webhook support
- Third-party integrations
- Mobile app ready

## Installation

### Prerequisites
- Python 3.8+
- Django 4.x
- PostgreSQL 12+ (recommended)
- Redis (optional, for caching)
- Node.js (for frontend build tools)

### Step 1: Environment Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Database Configuration
```python
# settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'leave_management',
        'USER': 'your_username',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### Step 3: Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Step 4: Create User Groups
```bash
python manage.py shell
```

```python
from django.contrib.auth.models import Group

# Create required groups
Group.objects.get_or_create(name='Employee')
Group.objects.get_or_create(name='Manager')
Group.objects.get_or_create(name='HR')
Group.objects.get_or_create(name='Admin')
Group.objects.get_or_create(name='Finance')
```

### Step 5: Create Sample Data
```bash
python manage.py loaddata leave/fixtures/sample_data.json
```

### Step 6: Start Development Server
```bash
python manage.py runserver
```

## User Guides

### Employee Guide

#### Applying for Leave
1. Navigate to the Employee Dashboard
2. Click "Apply Leave" or use the quick action button
3. Fill in the leave application form:
   - Select leave type
   - Choose dates
   - Provide reason
   - Add emergency contact if required
4. Submit the application
5. Track status in "My Requests" section

#### Checking Leave Balance
1. View balance cards on the dashboard
2. Click on any leave type for detailed view
3. See allocated, used, and available days
4. View carry-forward and additional allocations

### Manager Guide

#### Approving Leave Requests
1. Check "Pending Approvals" on the dashboard
2. Review request details
3. Click "Approve" or "Reject"
4. Add comments if needed
5. Use bulk actions for multiple requests

#### Team Management
1. Use the Team Calendar to view availability
2. Monitor team leave patterns
3. Generate team reports
4. Apply leave on behalf of team members

### HR Guide

#### Managing Leave Policies
1. Go to Leave → Policies
2. Create new policies or edit existing ones
3. Set up allocations per leave type
4. Configure approval workflows
5. Assign policies to user groups

#### User Balance Management
1. Navigate to Leave → Balances
2. View all employee balances
3. Make manual adjustments when needed
4. Process carry-forwards at year-end
5. Generate balance reports

### Finance Guide

#### Cost Monitoring
1. Monitor monthly leave costs
2. Track budget utilization
3. Generate financial reports
4. Set up budget alerts
5. Analyze cost trends

## API Documentation

### Authentication
All API endpoints require authentication. Include the session cookie or use token-based authentication.

### Base URL
```
/leave/api/v1/
```

### Dashboard APIs

#### Get Dashboard Data
```http
GET /dashboard/data/?role=employee
```

**Response:**
```json
{
  "success": true,
  "data": {
    "balances": [...],
    "recent_requests": [...],
    "upcoming_leaves": [...]
  }
}
```

### Leave Request APIs

#### Create Leave Request
```http
POST /requests/
Content-Type: application/json

{
  "leave_type_id": 1,
  "start_date": "2024-06-15",
  "end_date": "2024-06-17",
  "reason": "Family vacation",
  "is_half_day": false
}
```

#### Update Leave Request
```http
PUT /requests/{request_id}/
Content-Type: application/json

{
  "reason": "Updated reason"
}
```

#### Cancel Leave Request
```http
DELETE /requests/{request_id}/
```

### Approval APIs

#### Approve/Reject Request
```http
POST /approvals/{request_id}/
Content-Type: application/json

{
  "action": "approve",
  "comments": "Approved for vacation"
}
```

#### Bulk Approval
```http
POST /approvals/bulk/
Content-Type: application/json

{
  "request_ids": [1, 2, 3],
  "action": "approve"
}
```

### Calendar APIs

#### Get Calendar Events
```http
GET /calendar/events/?start=2024-01-01&end=2024-12-31
```

### Export APIs

#### Export Reports
```http
GET /reports/export/?type=leave_history&format=csv&start_date=2024-01-01
```

## Testing

### Running Tests
```bash
# Run all tests
python manage.py test trueAlign.leave.tests

# Run specific test case
python manage.py test trueAlign.leave.tests.test_api_views.DashboardAPITestCase

# Run with coverage
coverage run --source='.' manage.py test trueAlign.leave.tests
coverage report
coverage html
```

### Test Categories

#### Unit Tests
- Service layer tests
- Model validation tests
- Form validation tests
- Utility function tests

#### Integration Tests
- API endpoint tests
- View integration tests
- Database transaction tests
- Permission integration tests

#### Performance Tests
- Load testing for dashboard APIs
- Search performance tests
- Database query optimization tests

### Test Data
Use the provided test fixtures or create test data using Factory Boy:

```python
from trueAlign.leave.tests.factories import UserFactory, LeaveRequestFactory

user = UserFactory()
leave_request = LeaveRequestFactory(user=user)
```

## Development Guide

### Code Style
- Follow PEP 8 guidelines
- Use Black for code formatting
- Use isort for import sorting
- Maximum line length: 88 characters

### Git Workflow
1. Create feature branches from `main`
2. Write tests for new features
3. Ensure all tests pass
4. Submit pull requests for review
5. Merge after approval

### Adding New Features

#### 1. Create Service Methods
```python
# services.py
class NewFeatureService:
    @staticmethod
    def process_new_feature(data):
        # Business logic here
        pass
```

#### 2. Create API Views
```python
# api_views.py
class NewFeatureAPIView(BaseAPIView):
    def post(self, request):
        # API logic here
        pass
```

#### 3. Add URL Patterns
```python
# api_urls.py
path('new-feature/', views.NewFeatureAPIView.as_view(), name='new_feature'),
```

#### 4. Write Tests
```python
# tests/test_new_feature.py
class NewFeatureTestCase(BaseAPITestCase):
    def test_new_feature_success(self):
        # Test implementation
        pass
```

### Database Migrations
```bash
# Create migrations
python manage.py makemigrations leave

# Apply migrations
python manage.py migrate

# Check migration status
python manage.py showmigrations leave
```

### Performance Optimization

#### Database Queries
- Use `select_related()` for foreign keys
- Use `prefetch_related()` for many-to-many
- Add database indexes for frequent queries
- Use `only()` and `defer()` to limit fields

#### Caching
```python
from django.core.cache import cache

# Cache expensive operations
def get_dashboard_data(user):
    cache_key = f'dashboard_data_{user.id}'
    data = cache.get(cache_key)
    if not data:
        data = expensive_calculation(user)
        cache.set(cache_key, data, timeout=300)
    return data
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors
**Problem**: Users getting 403 errors
**Solution**: 
- Check user group assignments
- Verify permission decorators
- Review URL access patterns

#### 2. Balance Calculation Issues
**Problem**: Incorrect leave balances
**Solution**:
- Run balance recalculation script
- Check carry-forward settings
- Verify allocation configurations

#### 3. Performance Issues
**Problem**: Slow dashboard loading
**Solution**:
- Enable database query logging
- Add database indexes
- Implement caching
- Optimize service methods

#### 4. HTMX Not Working
**Problem**: Dynamic updates not working
**Solution**:
- Check HTMX library inclusion
- Verify API endpoints
- Check JavaScript console for errors

### Debug Mode
```python
# settings.py
DEBUG = True
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
        },
    },
    'loggers': {
        'trueAlign.leave': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
```

### Monitoring
- Use Django Debug Toolbar for development
- Monitor database query performance
- Track API response times
- Set up error logging for production

## Contributing

### Getting Started
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Review Process
1. Automated tests must pass
2. Code review by team member
3. Security review for sensitive changes
4. Performance impact assessment
5. Documentation updates

### Reporting Issues
Please include:
- Django version
- Python version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages/logs

## License
This project is licensed under the MIT License. See LICENSE file for details.

## Support
For support and questions:
- Email: support@company.com
- Documentation: [Internal Wiki]
- Issues: GitHub Issues
- Chat: Company Slack #leave-management

---
*Last updated: January 2024*
*Version: 2.0.0*