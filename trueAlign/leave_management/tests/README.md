# 🧪 Leave Management System Test Suite

## Overview
This test suite provides comprehensive testing for the Leave Management System, covering policy management, leave allocation, workflow processes, permissions, edge cases, and more. The test suite is designed to ensure the system functions correctly and handles edge cases properly.

This document contains everything you need to run the tests and maintain the test suite.

## Test Categories

| Category | Description | Key Test Areas |
|----------|-------------|----------------|
| **Policy Management** | Tests for leave policy creation, update, and management | Policy CRUD, validation rules, permissions |
| **Leave Allocation** | Tests for allocating leave to users and groups | Allocation calculation, bulk allocation, carry-forward |
| **Workflow** | Tests for leave application, approval, rejection, and cancellation | Full leave lifecycle, notifications, balance updates |
| **Permissions** | Tests for role-based access control | Dashboard access, approval hierarchy, view/edit permissions |
| **Edge Cases** | Tests for boundary conditions and unusual scenarios | Zero balance, date conflicts, overlapping leaves |
| **Services** | Tests for the service layer | Service method validation, error handling |
| **API** | Tests for API endpoints | Response format, error handling, authorization |

## Quick Start

### Running All Tests
```bash
# From project root
python manage.py test trueAlign.leave_management.tests

# Using the test runner (recommended)
python trueAlign/leave_management/tests/test_runner.py --suite=all
```

### Running Specific Test Categories
```bash
# Run policy management tests only
python trueAlign/leave_management/tests/test_runner.py --suite=policy

# Run workflow tests only
python trueAlign/leave_management/tests/test_runner.py --suite=workflow

# Run edge case tests only
python trueAlign/leave_management/tests/test_runner.py --suite=edge_cases
```

### Generating Test Reports
```bash
# Generate HTML report
python trueAlign/leave_management/tests/test_runner.py --report=html

# Generate JSON report
python trueAlign/leave_management/tests/test_runner.py --report=json

# Include coverage information
python trueAlign/leave_management/tests/test_runner.py --coverage
```

### Generating System Health Report
```bash
python trueAlign/leave_management/tests/test_runner.py --health
```

## Test Files

| File | Purpose |
|------|---------|
| `test_policy_management.py` | Tests for policy creation, update, and permissions |
| `test_allocation.py` | Tests for leave allocation and balance management |
| `test_workflow.py` | Tests for leave application workflow and approval process |
| `test_permissions.py` | Tests for role-based permissions and access control |
| `test_edge_cases.py` | Tests for boundary conditions and unusual scenarios |
| `test_final.py` | Simplified tests that work with current implementation |
| `test_runner.py` | Custom test runner with reporting capabilities |
| `generate_health_report.py` | System health report generator |

## Writing New Tests

### Test Case Structure
```python
def test_something_specific(self):
    """Clear description of what this test verifies"""
    # 1. Setup test data
    
    # 2. Execute the operation being tested
    
    # 3. Assert expected outcomes
    
    # 4. Clean up (if needed)
```

### Best Practices
1. **Test Isolation**: Each test should be independent and not rely on the state from other tests
2. **Clear Names**: Use descriptive test method names that explain what's being tested
3. **Docstrings**: Include clear docstrings explaining the test's purpose
4. **Coverage**: Aim to test both happy paths and error conditions
5. **Assertions**: Use specific assertions (assertEqual, assertTrue, etc.) with helpful messages

## Common Test Patterns

### Testing Leave Application
```python
# Apply for leave
leave_request = self.leave_service.apply_leave(
    user=self.employee_user,
    leave_type=self.annual_leave,
    start_date=start_date,
    end_date=end_date,
    reason="Test reason"
)

# Verify request was created with proper status
self.assertEqual(leave_request.status, 'Pending')
self.assertEqual(leave_request.leave_type, self.annual_leave)
```

### Testing Leave Approval
```python
# Approve the leave
self.leave_service.approve_leave(
    leave_request=leave_request,
    approver=self.manager_user,
    comments="Approved"
)

# Verify approval
leave_request.refresh_from_db()
self.assertEqual(leave_request.status, 'Approved')
self.assertEqual(leave_request.approver, self.manager_user)

# Verify balance update
balance = UserLeaveBalance.objects.get(
    user=self.employee_user,
    leave_type=self.annual_leave,
    year=timezone.now().year
)
self.assertEqual(balance.used_days, expected_days)
```

### Testing Permissions
```python
# Test permission utility functions
self.assertTrue(can_approve_leave(self.manager_user, self.employee_user))
self.assertFalse(can_approve_leave(self.employee_user, self.manager_user))

# Test URL access permissions
self.client.login(username="employee", password="password")
response = self.client.get(reverse('leave_management:manager_dashboard'))
self.assertEqual(response.status_code, 403)  # Forbidden
```

## Troubleshooting

### Test Database Issues
If you encounter database-related issues, try:
```bash
# Reset the test database
python manage.py flush --noinput

# Run migrations on test database
python manage.py migrate --settings=test_settings
```

### Common Test Failures

| Error | Possible Cause | Solution |
|-------|----------------|----------|
| `PermissionDenied` | Role-based access control enforced | Verify user has correct group/role |
| `ObjectDoesNotExist` | Missing test data | Check setUp method creates all required data |
| `ValidationError` | Test data doesn't meet validation rules | Adjust test data to match validation rules |
| `AttributeError` | Method or property doesn't exist | Check for typos or verify method exists |

## Health Report

The health report provides a comprehensive overview of the system's current state, including:

- Database health and statistics
- Data integrity checks
- Performance metrics
- URL configuration verification
- Process flow analysis

This is particularly useful for:
- Pre-deployment verification
- Troubleshooting system issues
- Regular maintenance checks
- Performance monitoring

### Generating Health Reports

You can generate a health report in two ways:

```bash
# Using the shell script
./run_leave_tests.sh --health

# Or directly using the Python script
python trueAlign/leave_management/tests/generate_health_report.py
```

This will generate both JSON and text format reports with timestamps in the filename.

## Contributing

When adding new tests:

1. Determine the appropriate test file based on the feature being tested
2. Follow the existing patterns and naming conventions
3. Ensure tests are isolated and don't depend on other tests
4. Run the full test suite to verify no regressions were introduced
5. Update documentation if needed

---

## Test Health Metrics

The following metrics are monitored to ensure system health:

| Metric | Target | Warning Threshold | Critical Threshold |
|--------|--------|-------------------|-------------------|
| Data Integrity | 100% | <90% | <80% |
| User Setup | 100% | <90% | <80% |
| Performance Score | >90 | <70 | <50 |
| Test Coverage | >90% | <80% | <70% |
| Leave Request Workflow | 100% pass | Any failure | Multiple failures |
| Policy Management | 100% pass | Any failure | Multiple failures |
| Balance Calculation | 100% accurate | <99% | <95% |

The health report will automatically calculate these metrics and provide recommendations.

*Last updated: 2024*