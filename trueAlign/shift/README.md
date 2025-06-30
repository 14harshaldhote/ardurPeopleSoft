# Shift Management App

A comprehensive Django application for managing work shifts, shift assignments, and holidays in an employee management system.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Models](#models)
- [Services](#services)
- [Views and URLs](#views-and-urls)
- [Forms](#forms)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Usage Examples](#usage-examples)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Overview

The Shift Management App is a Django application designed to handle all aspects of employee shift management including:

- Creating and managing shift patterns
- Assigning shifts to employees
- Tracking shift assignments and history
- Managing holidays and time off
- Bulk operations via CSV import
- Statistical reporting and analytics

## Features

### Core Features

- **Shift Management**: Create, update, and delete shift patterns with customizable work days
- **Shift Assignment**: Assign shifts to users with effective date ranges
- **Holiday Management**: Define holidays with yearly recurrence options
- **Bulk Operations**: CSV import for bulk shift assignments
- **Statistics & Reporting**: Comprehensive analytics and reporting
- **API Support**: RESTful API endpoints for integration
- **Permission System**: Role-based access control with decorators
- **Audit Trail**: Complete history tracking of all changes

### Advanced Features

- **Midnight Crossing Shifts**: Support for shifts that span across midnight
- **Flexible Work Days**: Support for weekdays, all days, or custom day patterns
- **Conflict Resolution**: Automatic handling of overlapping shift assignments
- **Grace Periods**: Configurable grace periods for late clock-ins
- **Break Management**: Configurable break durations
- **Validation**: Comprehensive form and data validation
- **Error Handling**: Robust error handling with detailed logging

## Installation

### Prerequisites

- Python 3.8+
- Django 3.2+
- PostgreSQL/MySQL (recommended for production)

### Setup

1. **Install the app** (assuming it's part of a larger Django project):
   ```python
   INSTALLED_APPS = [
       # ... other apps
       'trueAlign.shift',
   ]
   ```

2. **Add URL patterns** to your main `urls.py`:
   ```python
   from django.urls import path, include
   
   urlpatterns = [
       # ... other patterns
       path('shift/', include('trueAlign.shift.urls')),
   ]
   ```

3. **Run migrations**:
   ```bash
   python manage.py makemigrations shift
   python manage.py migrate
   ```

4. **Create required groups**:
   ```python
   from django.contrib.auth.models import Group
   
   # Create required groups
   Group.objects.get_or_create(name='Manager')
   Group.objects.get_or_create(name='Employee')
   ```

## Configuration

### Settings

Add these settings to your Django settings file:

```python
# Logging configuration for shift app
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'shift_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/shift.log',
        },
    },
    'loggers': {
        'trueAlign.shift': {
            'handlers': ['shift_file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Timezone settings
USE_TZ = True
TIME_ZONE = 'Asia/Kolkata'  # Adjust as needed
```

### Permissions

The app uses Django's group-based permissions:

- **Manager**: Can create, update, delete shifts and assignments
- **Employee**: Can view shifts and their own assignments
- **Superuser**: Has access to all functionality

## Models

### ShiftMaster

Defines shift patterns with the following key fields:

```python
class ShiftMaster(models.Model):
    name = CharField(max_length=50)
    start_time = TimeField()
    end_time = TimeField()
    shift_duration = DecimalField(max_digits=5, decimal_places=2)
    break_duration = DurationField(default=timedelta(minutes=30))
    grace_period = DurationField(default=timedelta(minutes=15))
    work_days = CharField(max_length=20, choices=WORK_DAYS_CHOICES)
    custom_work_days = CharField(max_length=255, null=True, blank=True)
    is_active = BooleanField(default=True)
```

**Key Properties:**
- `crosses_midnight`: Boolean indicating if shift spans midnight
- `working_days_list`: List of working day numbers (0=Monday)
- `expected_hours()`: Calculated working hours excluding breaks

### ShiftAssignment

Links users to shifts with date ranges:

```python
class ShiftAssignment(models.Model):
    user = ForeignKey(User, on_delete=CASCADE)
    shift = ForeignKey(ShiftMaster, on_delete=CASCADE)
    effective_from = DateField()
    effective_to = DateField(null=True, blank=True)
    is_current = BooleanField(default=True)
```

**Key Methods:**
- `is_active_on(date)`: Check if assignment is active on given date
- `days_remaining()`: Days left in assignment
- `has_ended()`: Whether assignment has ended

### Holiday

Manages holidays and time off:

```python
class Holiday(models.Model):
    name = CharField(max_length=100)
    date = DateField()
    recurring_yearly = BooleanField(default=True)
```

**Key Methods:**
- `is_holiday(date)`: Class method to check if date is a holiday

## Services

### ShiftService

The main service class providing business logic:

```python
from trueAlign.shift.services import ShiftService

service = ShiftService()
```

#### Key Methods

**Shift Management:**
```python
# Create a shift
shift = service.create_shift(shift_data)

# Get shift by ID or name
shift = service.get_shift_by_id(shift_id)
shift = service.get_shift_by_name('Morning Shift')

# Update shift
updated_shift = service.update_shift(shift_id, updated_data)
```

**Assignment Management:**
```python
# Assign shift to user
assignment = service.assign_shift_to_user(
    user_id=user_id,
    shift_id=shift_id,
    effective_from=date.today()
)

# Bulk assignment
success_count, error_count, errors = service.assign_shifts_to_users(
    user_ids=[1, 2, 3],
    shift_id=shift_id,
    effective_from=date.today()
)

# CSV import
results = service.assign_shifts_from_csv(csv_file)
```

**Statistics and Reporting:**
```python
# Get comprehensive statistics
stats = service.get_shift_statistics()

# Get upcoming changes
changes = service.get_upcoming_shift_changes(days=7)

# Get user shift history
history = service.get_shift_history(user_id)
```

## Views and URLs

### URL Patterns

```python
# Dashboard and overview
shift/                          # Dashboard
shift/statistics/               # Statistics page

# Shift management
shift/list/                     # List all shifts
shift/create/                   # Create new shift
shift/update/<int:shift_id>/    # Update shift
shift/delete/<int:shift_id>/    # Delete shift
shift/detail/<int:shift_id>/    # Shift details

# Assignments
shift/assignments/              # List assignments
shift/assign/                   # Assign shifts
shift/end-assignment/<int:id>/  # End assignment

# Holidays
shift/holidays/                 # List holidays
shift/holidays/create/          # Create holiday

# API endpoints
shift/api/shift-details/<int:id>/       # Shift details API
shift/api/user-assignments/<int:id>/    # User assignments API
```

### View Decorators

The app uses custom decorators for access control:

```python
from trueAlign.shift.decorators import group_required

@group_required(group_names=['Manager'])
def create_shift(request):
    # Only managers can access
    pass

@group_required(group_names=['Manager', 'Employee'])
def view_shifts(request):
    # Managers and employees can access
    pass
```

## Forms

### ShiftForm

For creating and updating shifts:

```python
from trueAlign.shift.forms import ShiftForm

form = ShiftForm(data=request.POST)
if form.is_valid():
    shift = form.save()
```

**Key Validations:**
- Shift duration > 0 and <= 24 hours
- Break duration <= 8 hours
- Grace period <= 2 hours
- Custom work days format validation
- Unique shift names

### ShiftAssignmentForm

For individual shift assignments:

```python
from trueAlign.shift.forms import ShiftAssignmentForm

form = ShiftAssignmentForm(data=request.POST)
if form.is_valid():
    # Process assignment
    pass
```

### CSVUploadForm

For bulk CSV imports:

```python
from trueAlign.shift.forms import CSVUploadForm

form = CSVUploadForm(files=request.FILES)
if form.is_valid():
    csv_file = form.cleaned_data['csv_file']
    # Process CSV
```

**CSV Format:**
```csv
username,shift_name,effective_from,effective_to
john.doe,Morning Shift,2024-01-01,2024-12-31
jane.smith,Night Shift,2024-01-01,
```

## API Endpoints

### Shift Details API

```http
GET /shift/api/shift-details/<shift_id>/
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "id": 1,
        "name": "Morning Shift",
        "start_time": "09:00",
        "end_time": "17:00",
        "is_active": true,
        "users": [...]
    }
}
```

### User Assignments API

```http
GET /shift/api/user-assignments/<user_id>/
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "user": {
            "id": 1,
            "name": "John Doe",
            "username": "john.doe"
        },
        "assignments": [...]
    }
}
```

### Upcoming Changes API

```http
GET /shift/api/upcoming-changes/?days=7
```

**Response:**
```json
{
    "status": "success",
    "data": [
        {
            "id": 1,
            "user_name": "John Doe",
            "shift_name": "Morning Shift",
            "effective_to": "2024-12-31"
        }
    ]
}
```

## Testing

### Running Tests

```bash
# Run all shift app tests
python manage.py test trueAlign.shift

# Run specific test class
python manage.py test trueAlign.shift.tests.ShiftServiceTest

# Run with coverage
coverage run --source='.' manage.py test trueAlign.shift
coverage report
```

### Test Structure

- **Model Tests**: Test model functionality and properties
- **Service Tests**: Test business logic and data operations
- **Form Tests**: Test form validation and processing
- **View Tests**: Test HTTP endpoints and access control
- **Integration Tests**: Test complete workflows
- **Edge Case Tests**: Test error conditions and boundaries
- **Performance Tests**: Test with larger datasets
- **Security Tests**: Test permission and access control

### Test Data

Tests use factories and fixtures for consistent test data:

```python
# Example test setup
def setUp(self):
    self.user = User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )
    self.shift = ShiftMaster.objects.create(
        name='Test Shift',
        start_time=time(9, 0),
        end_time=time(17, 0),
        shift_duration=Decimal('8.0')
    )
```

## Usage Examples

### Creating a Basic Shift

```python
from trueAlign.shift.services import ShiftService

service = ShiftService()
shift_data = {
    'name': 'Morning Shift',
    'start_time': time(9, 0),
    'end_time': time(17, 30),
    'shift_duration': Decimal('8.5'),
    'break_duration': timedelta(minutes=30),
    'grace_period': timedelta(minutes=15),
    'work_days': 'Weekdays',
    'is_active': True
}

shift = service.create_shift(shift_data)
```

### Assigning Shifts

```python
# Single assignment
assignment = service.assign_shift_to_user(
    user_id=user.id,
    shift_id=shift.id,
    effective_from=date.today(),
    effective_to=date(2024, 12, 31)
)

# Bulk assignment
success_count, error_count, errors = service.assign_shifts_to_users(
    user_ids=[1, 2, 3, 4, 5],
    shift_id=shift.id,
    effective_from=date.today()
)
```

### CSV Import

```python
# Prepare CSV content
csv_content = """username,shift_name,effective_from,effective_to
john.doe,Morning Shift,2024-01-01,2024-12-31
jane.smith,Night Shift,2024-01-01,"""

# Process import
results = service.assign_shifts_from_csv(csv_file)
print(f"Assigned {results['success_count']} shifts")
```

### Working with Holidays

```python
# Create holiday
holiday_data = {
    'name': 'Christmas',
    'date': date(2024, 12, 25),
    'recurring_yearly': True
}
holiday = service.create_holiday(holiday_data)

# Check if date is holiday
is_holiday = service.is_holiday(date(2024, 12, 25))
```

## Security

### Access Control

The app implements role-based access control:

- **Authentication Required**: All views require login
- **Group-Based Permissions**: Uses Django groups for authorization
- **Decorator Protection**: Views protected with `@group_required` decorator
- **API Security**: API endpoints require authentication

### Input Validation

- **Form Validation**: Comprehensive form validation for all inputs
- **Data Sanitization**: All user inputs are sanitized
- **File Upload Security**: CSV uploads are validated for content and size
- **SQL Injection Protection**: Uses Django ORM for database operations

### Logging and Auditing

- **Action Logging**: All significant actions are logged
- **Error Tracking**: Errors are logged with full context
- **Audit Trail**: Database changes are tracked with timestamps
- **Security Events**: Failed access attempts are logged

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors

**Problem**: Users can't access certain views
**Solution**: 
- Ensure user is in the correct group (Manager/Employee)
- Check decorator configuration on views
- Verify group names match exactly

#### 2. CSV Import Failures

**Problem**: CSV imports fail with validation errors
**Solution**:
- Check CSV format matches required headers
- Ensure usernames exist in the system
- Verify shift names exist and are active
- Check date formats (YYYY-MM-DD)

#### 3. Shift Assignment Conflicts

**Problem**: Assignment creation fails due to conflicts
**Solution**:
- Check for overlapping assignments
- Verify date ranges are valid
- Ensure user and shift exist and are active

#### 4. Midnight Crossing Shifts

**Problem**: Issues with shifts that cross midnight
**Solution**:
- Ensure end_time < start_time for midnight shifts
- Verify shift duration calculation
- Check working day logic for overnight shifts

### Debug Mode

Enable debug logging for troubleshooting:

```python
LOGGING = {
    'loggers': {
        'trueAlign.shift': {
            'level': 'DEBUG',
            'handlers': ['console'],
        },
    },
}
```

### Common Error Messages

- **"Shift not found"**: Check shift ID and active status
- **"User not found"**: Verify user ID and active status
- **"Permission denied"**: Check user groups and authentication
- **"Invalid date format"**: Use YYYY-MM-DD format
- **"Overlapping assignment"**: End existing assignment first

## Contributing

### Development Setup

1. **Clone the repository**
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Set up database**: `python manage.py migrate`
4. **Create test data**: `python manage.py loaddata fixtures/test_data.json`
5. **Run tests**: `python manage.py test trueAlign.shift`

### Code Standards

- **PEP 8**: Follow Python style guidelines
- **Type Hints**: Use type hints for better code documentation
- **Docstrings**: Document all classes and methods
- **Testing**: Write tests for all new functionality
- **Logging**: Add appropriate logging for debugging

### Submitting Changes

1. **Create feature branch**: `git checkout -b feature/your-feature`
2. **Write tests**: Ensure good test coverage
3. **Update documentation**: Update this README if needed
4. **Submit pull request**: Include description of changes

### Code Review Checklist

- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Performance implications considered
- [ ] Backward compatibility maintained

---

## License

This project is part of the TrueAlign system and follows the same licensing terms.

## Support

For support and questions:
- Create an issue in the project repository
- Contact the development team
- Check the troubleshooting section above

---

**Last Updated**: January 2024
**Version**: 1.0.0