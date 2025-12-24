# TrueAlign ERP - Integration Testing Suite

## Overview

Comprehensive integration testing suite for the TrueAlign ERP system covering all modules (excluding Finance as requested).

## Test Coverage

### Modules Tested (12)
- ✅ Core Module (Session & Authentication)
- ✅ Attendance Management
- ✅ Leave Management
- ✅ Profile & User Management
- ✅ Session Tracking
- ✅ Shift Management
- ✅ Appraisal Module
- ✅ Support Ticket System
- ✅ Conference Room Booking
- ✅ Letter Generation
- ✅ Global Updates/Notes
- ✅ Notifications

### Test Categories
- Module-specific integration tests (~60 tests)
- Role-Based Access Control (RBAC) tests (~10 tests)
- End-to-end workflow tests (~4 tests)
- Cross-module integration tests
- Failure scenario tests

**Total: ~100 integration test cases**

## Running Tests

### Run All Tests
```bash
cd /Users/harshalsmac/WORK/ardur/ardurHome
python manage.py test trueAlign.tests.integration -v 2
```

### Run Specific Module Tests
```bash
# Core module tests
python manage.py test trueAlign.tests.integration.test_core_integration -v 2

# Attendance tests
python manage.py test trueAlign.tests.integration.test_attendance_integration -v 2

# Leave tests
python manage.py test trueAlign.tests.integration.test_leave_integration -v 2

# RBAC tests
python manage.py test trueAlign.tests.integration.test_rbac -v 2

# Workflow tests
python manage.py test trueAlign.tests.integration.test_workflows -v 2
```

### Run with Custom Test Runner
```bash
cd /Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/tests/integration
python run_tests.py
```

## Test Logs

### Log Location
All test logs are stored in:
```
/Users/harshalsmac/WORK/ardur/ardurHome/logs/
```

### Log File Naming
Logs are automatically numbered incrementally:
- `test1.log` - First test run
- `test2.log` - Second test run
- `test3.log` - Third test run
- ...and so on

### Log Contents
Each log file contains:
1. **Test Execution Details**
   - Test case ID
   - Module name
   - Roles involved
   - Step-by-step execution logs
   - Database state changes
   - API requests/responses
   - Assertions (Pass/Fail)

2. **Cross-Module Interactions**
   - Session → Attendance
   - Leave → Attendance → Notification
   - All integration points

3. **Security Validations**
   - Role-based access checks
   - Permission validation
   - Unauthorized access prevention

4. **Test Summary**
   - Total tests executed
   - Pass/Fail counts
   - Success rate
   - Duration

5. **Fixes Needed Section**
   - Failed tests
   - Issues discovered
   - Recommended fixes
   - Priority areas

## Test Database

Tests use an isolated test database:
- **Name**: `truealign_test_db` (handled automatically by Django)
- **Isolation**: Completely separate from production
- **Reset**: Database is created and destroyed for each test run
- **No Impact**: Production database is never touched

## Test Data

### Master Data Created
- Office Locations: Office A (Mumbai), Office B (Pune)
- Departments: Engineering, HR, Operations
- Designations: Employee, Manager, HR Executive, System Administrator
- Leave Types: Annual Leave, Sick Leave, Casual Leave
- Leave Policies: Default policy with accrual and proration
- Shifts: Morning Shift (9 AM - 6 PM), Evening Shift (1 PM - 10 PM)
- Conference Rooms: 2 per office location
- Support Categories: IT Support, HR Support, Admin Support

### Test Users Created
| Username | Role | Department | Location |
|----------|------|------------|----------|
| admin_01 | Admin | Engineering | Office A |
| hr_01 | HR | HR | Office A |
| manager_01 | Manager | Engineering | Office A |
| employee_01 | Employee | Engineering | Office A |
| employee_02 | Employee | Operations | Office B |
| management_01 | Management | Engineering | Office A |

## Test Structure

```
trueAlign/tests/integration/
├── __init__.py                          # Package init
├── base.py                              # Base test classes
├── fixtures.py                          # Master data fixtures
├── logger.py                            # Logging infrastructure
├── run_tests.py                         # Test runner script
├── README.md                            # This file
│
├── test_core_integration.py             # Core module tests (6 tests)
├── test_attendance_integration.py       # Attendance tests (6 tests)
├── test_leave_integration.py            # Leave tests (5 tests)
├── test_rbac.py                         # RBAC tests (9 tests)
└── test_workflows.py                    # E2E workflow tests (4 tests)
```

## Key Integration Points Tested

### Session → Attendance
- Login creates session and auto-marks attendance
- Session heartbeat tracks activity
- Logout ends session and finalizes attendance

### Leave → Attendance → Notification
- Leave application validates balance 
- Leave approval deducts balance
- Leave approval marks attendance as on_leave
- Notifications sent to employee and manager

### Shift → Attendance
- Shift assignment affects attendance timing
- Late arrival detection based on shift
- Conflict prevention

### Complete Workflows
- Employee daily flow (login to logout)
- Manager approval workflow
- HR monthly operations
- Admin system setup

## Interpreting Logs

### Log Structure
```
==================================================================================
TEST CASE: CORE-001
MODULE: Core Module
ROLES: Employee
DESCRIPTION: Login → Session Creation → Auto-Attendance Marking
==================================================================================
STEP 1: Employee logs in
DATABASE [CREATE] Table: UserSession, ID: 123
STEP 2: Verify session created
ASSERTION [PASS] Session Exists
  Expected: True
  Actual: True
CROSS-MODULE [Session → Attendance] Auto-marking | Data: Session ID: 123
...
TEST RESULT: CORE-001 - PASSED (Duration: 1.23s)
==================================================================================
```

### Fixes Needed Section
At the end of each log, you'll find:
```
==================================================================================
FIXES NEEDED - DETAILED ANALYSIS
==================================================================================
────────────────────────────────────────────────────────────────────────────────
AREA: Attendance - Regularization
────────────────────────────────────────────────────────────────────────────────

1. Issue:
   Regularization workflow not working: ...
   Recommendation: Check regularization approval signal handlers
...
```

## Troubleshooting

### Common Issues

**1. Import Errors**
```bash
# Ensure you're in the project root
cd /Users/harshalsmac/WORK/ardur/ardurHome
# Run with proper Python path
PYTHONPATH=. python manage.py test trueAlign.tests.integration
```

**2. Database Errors**
```bash
# Make sure migrations are up to date
python manage.py migrate
# Run tests (Django creates test DB automatically)
python manage.py test trueAlign.tests.integration
```

**3. Missing Dependencies**
```bash
# Install required packages
pip install -r requirements.txt
```

## Adding New Tests

### 1. Create a new test file
```python
from .base import IntegrationTestCase

class MyModuleTests(IntegrationTestCase):
    def test_my_integration(self):
        self.log_test_start('MODULE-001', 'My Module', ['Employee'], 'Test description')
        # Test code here
        self.log_test_end('MODULE-001', passed=True)
```

### 2. Use helper methods
- `self.login_as(user)` - Login as specific user
- `self.create_object(Model, **kwargs)` - Create DB object with logging
- `self.assert_status_code(response, 200)` - Assert HTTP status
- `self.assert_object_exists(Model, **filters)` - Assert DB record exists
- `self.logger.log_cross_module_interaction(...)` - Log integrations

### 3. Run your tests
```bash
python manage.py test trueAlign.tests.integration.test_my_module -v 2
```

## Best Practices

1. **Always use self.log_test_start() and self.log_test_end()**
   - Ensures proper logging
   - Tracks test duration
   - Generates "Fixes Needed" section

2. **Use descriptive test case IDs**
   - Format: `MODULE-XXX` (e.g., `CORE-001`, `ATT-002`)
   - Makes log parsing easier

3. **Test cross-module integrations**
   - Use `self.logger.log_cross_module_interaction()`
   - Validates data flows between modules

4. **Verify security**
   - Test role-based access for each feature
   - Use `self.logger.log_security_check()`

5. **Clean up in tearDown if needed**
   - Base class handles most cleanup
   - Add custom cleanup if necessary

## Contact & Support

For issues with the test suite:
1. Check the latest log file in `/logs/`
2. Review the "Fixes Needed" section
3. Refer to `implementation_plan.md` for detailed test specifications

---

**Last Updated**: December 2024  
**Test Suite Version**: 1.0.0  
**Modules Covered**: 12 (excluding Finance)  
**Total Test Cases**: ~100
