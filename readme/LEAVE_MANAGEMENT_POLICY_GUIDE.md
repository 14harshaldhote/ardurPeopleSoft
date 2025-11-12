# Leave Management Policy & Allocation Guide

## Overview
This guide explains how to use the leave management system's policy and allocation features effectively.

## Table of Contents
1. [Understanding the System](#understanding-the-system)
2. [Setting Up Leave Policies](#setting-up-leave-policies)
3. [Managing Leave Types](#managing-leave-types)
4. [Allocating Leaves to Users](#allocating-leaves-to-users)
5. [Monitoring and Tracking](#monitoring-and-tracking)
6. [API Endpoints](#api-endpoints)
7. [Troubleshooting](#troubleshooting)

## Understanding the System

### Key Components

#### 1. Leave Types
- **Purpose**: Define different categories of leave (Annual, Sick, Maternity, etc.)
- **Properties**:
  - `is_paid`: Whether the leave is paid or unpaid
  - `requires_approval`: Whether approval is needed
  - `requires_documentation`: Whether supporting documents are required
  - `count_weekends`: Whether weekends are counted in leave days
  - `can_be_half_day`: Whether half-day leaves are allowed

#### 2. Leave Policies
- **Purpose**: Define rules and allocations for different user groups
- **Properties**:
  - Associated with user groups (Employee, Manager, HR, etc.)
  - Contains multiple leave allocations
  - Can be activated/deactivated

#### 3. Leave Allocations
- **Purpose**: Specify how many days of each leave type users get
- **Properties**:
  - `annual_days`: Number of days allocated per year
  - `max_consecutive_days`: Maximum consecutive days allowed
  - `advance_notice_days`: Required advance notice period
  - `carry_forward_limit`: Maximum days that can be carried forward

#### 4. User Leave Balances
- **Purpose**: Track individual user's leave usage and availability
- **Properties**:
  - `allocated`: Days allocated for the year
  - `used`: Days already used
  - `available`: Days available (calculated)
  - `carried_forward`: Days carried from previous year
  - `additional`: Additional days granted

## Setting Up Leave Policies

### Step 1: Create Leave Types
```python
# Example: Creating leave types via Django admin or shell
from trueAlign.models import LeaveType

# Annual Leave
annual_leave = LeaveType.objects.create(
    name="Annual Leave",
    is_paid=True,
    requires_approval=True,
    requires_documentation=False,
    count_weekends=False,
    can_be_half_day=True,
    is_active=True
)

# Sick Leave
sick_leave = LeaveType.objects.create(
    name="Sick Leave",
    is_paid=True,
    requires_approval=True,
    requires_documentation=True,  # For leaves > 3 days
    count_weekends=False,
    can_be_half_day=True,
    is_active=True
)
```

### Step 2: Create User Groups
```python
from django.contrib.auth.models import Group

# Create groups if they don't exist
employee_group, created = Group.objects.get_or_create(name='Employee')
manager_group, created = Group.objects.get_or_create(name='Manager')
hr_group, created = Group.objects.get_or_create(name='HR')
```

### Step 3: Create Leave Policies
```python
from trueAlign.models import LeavePolicy

# Employee Policy
employee_policy = LeavePolicy.objects.create(
    name="Standard Employee Policy",
    description="Standard leave policy for all employees",
    group=employee_group,
    is_active=True
)
```

### Step 4: Create Leave Allocations
```python
from trueAlign.models import LeaveAllocation

# Annual leave allocation for employees
LeaveAllocation.objects.create(
    policy=employee_policy,
    leave_type=annual_leave,
    annual_days=21,  # 21 days per year
    max_consecutive_days=10,  # Max 10 consecutive days
    advance_notice_days=7,  # 7 days advance notice
    carry_forward_limit=5  # Max 5 days carry forward
)

# Sick leave allocation for employees
LeaveAllocation.objects.create(
    policy=employee_policy,
    leave_type=sick_leave,
    annual_days=12,  # 12 days per year
    max_consecutive_days=0,  # No limit
    advance_notice_days=0,  # No advance notice required
    carry_forward_limit=0  # No carry forward
)
```

## Managing Leave Types

### Best Practices

1. **Naming Convention**: Use clear, descriptive names
   - ✅ "Annual Leave", "Sick Leave", "Maternity Leave"
   - ❌ "Type1", "Leave A", "Special"

2. **Documentation Requirements**: Set appropriately
   - Sick leave > 3 days: Require medical certificate
   - Maternity leave: Require medical documentation
   - Annual leave: Usually no documentation needed

3. **Weekend Counting**: Consider your organization's policy
   - Most organizations don't count weekends in leave days
   - Some may count them for certain leave types

## Allocating Leaves to Users

### Automatic Allocation
The system can automatically allocate leaves when users apply:

```python
# This happens automatically in LeaveService.get_user_leave_balance()
# If no balance exists, it tries to create one based on user's group policy
```

### Manual Allocation via API
```bash
# Bulk allocate leaves to a group
curl -X POST /api/leave_management/bulk_allocate_leaves/ \
  -H "Content-Type: application/json" \
  -d '{
    "group_name": "Employee",
    "year": 2025
  }'
```

### Individual Allocation
```python
from trueAlign.leave_management.services.leave_service import LeaveService

# Allocate leaves to a specific user
result = LeaveService.allocate_leaves_to_user(user, {}, 2025)
```

## Monitoring and Tracking

### Policy Allocation Status
Monitor which users have been allocated leaves:

```bash
# Get policy allocation status
curl /api/leave_management/policy_allocation_status/
```

Response includes:
- Users in each group
- Users with allocated balances
- Allocation percentage
- Policy details

### Policy Expiration Alerts
Track policies that are expiring soon:

```bash
# Get expiration alerts
curl /api/leave_management/policy_expiration_alerts/
```

### Leave Usage Analytics
Get comprehensive usage statistics:

```bash
# Get usage analytics for current year
curl /api/leave_management/leave_usage_analytics/

# Get usage analytics for specific year
curl /api/leave_management/leave_usage_analytics/?year=2024
```

## API Endpoints

### Policy Management APIs

| Endpoint | Method | Description | Access |
|----------|--------|-------------|---------|
| `/api/leave_management/policy_allocation_status/` | GET | Get policy allocation status | HR, Admin |
| `/api/leave_management/policy_expiration_alerts/` | GET | Get expiring policies | HR, Admin |
| `/api/leave_management/bulk_allocate_leaves/` | POST | Bulk allocate leaves | HR, Admin |
| `/api/leave_management/leave_usage_analytics/` | GET | Get usage analytics | HR, Admin |

### Leave Balance APIs

| Endpoint | Method | Description | Access |
|----------|--------|-------------|---------|
| `/api/leave_management/leave_balance/` | GET | Get own leave balance | All users |
| `/api/leave_management/leave_balance/<user_id>/` | GET | Get specific user balance | HR, Admin |
| `/api/leave_management/leave_types/` | GET | Get available leave types | All users |

## Workflow Examples

### 1. Setting Up a New Organization

```python
# 1. Create leave types
annual = LeaveType.objects.create(name="Annual Leave", is_paid=True, ...)
sick = LeaveType.objects.create(name="Sick Leave", is_paid=True, ...)

# 2. Create groups
emp_group = Group.objects.create(name="Employee")

# 3. Create policy
policy = LeavePolicy.objects.create(
    name="Employee Policy", 
    group=emp_group, 
    is_active=True
)

# 4. Create allocations
LeaveAllocation.objects.create(policy=policy, leave_type=annual, annual_days=21)
LeaveAllocation.objects.create(policy=policy, leave_type=sick, annual_days=12)

# 5. Assign users to groups
user.groups.add(emp_group)

# 6. Allocate leaves (happens automatically when user applies)
```

### 2. Annual Leave Allocation Process

```python
# At the beginning of each year, bulk allocate leaves
from django.contrib.auth.models import User
from trueAlign.leave_management.services.leave_service import LeaveService

# Get all active users
users = User.objects.filter(is_active=True)

# Bulk allocate for current year
result = LeaveService.bulk_allocate_leaves(list(users), 2025)
```

### 3. Mid-Year Policy Changes

```python
# If you need to update allocations mid-year
# 1. Update the policy allocation
allocation = LeaveAllocation.objects.get(policy=policy, leave_type=annual)
allocation.annual_days = 25  # Increase from 21 to 25
allocation.save()

# 2. Update existing user balances
balances = UserLeaveBalance.objects.filter(
    leave_type=annual, 
    year=2025
)
for balance in balances:
    balance.allocated = 25
    balance.save()
```

## Troubleshooting

### Common Issues

#### 1. "No leave balance information available"
**Cause**: User doesn't have UserLeaveBalance records
**Solution**: 
- Check if user is assigned to a group
- Check if group has an active policy
- Try manual allocation: `LeaveService.allocate_leaves_to_user(user, {}, year)`

#### 2. "RelatedObjectDoesNotExist: LeaveRequest has no user"
**Cause**: User field not properly set in leave request
**Solution**: 
- Ensure user is authenticated
- Check if user has proper permissions
- Verify the apply_leave view is correctly setting the user

#### 3. Permission Denied Errors
**Cause**: User doesn't have required role/group membership
**Solution**:
- Check user's group membership: `user.groups.all()`
- For superusers: System now automatically grants Admin privileges
- Assign user to appropriate group: `user.groups.add(group)`

#### 4. Policy Not Found
**Cause**: User's group doesn't have an active policy
**Solution**:
```python
# Check user's groups
user.groups.all()

# Check if groups have policies
from trueAlign.models import LeavePolicy
policies = LeavePolicy.objects.filter(group__in=user.groups.all(), is_active=True)

# Create policy if missing
policy = LeavePolicy.objects.create(
    name=f"{group.name} Policy",
    group=group,
    is_active=True
)
```

### Debugging Commands

```python
# Check user's leave balance
from trueAlign.leave_management.services.leave_service import LeaveService
balance = LeaveService.get_user_leave_balance(user)
print(balance)

# Check user's roles
from trueAlign.leave_management.utils import get_user_roles
roles = get_user_roles(user)
print(f"User roles: {roles}")

# Check if user can apply leave
from trueAlign.models import LeaveType
leave_type = LeaveType.objects.first()
# Try creating a test leave request to see validation errors
```

## Best Practices

1. **Regular Monitoring**: Check policy allocation status monthly
2. **Annual Reviews**: Review and update policies annually
3. **Documentation**: Keep policies well-documented
4. **Testing**: Test policy changes in a staging environment first
5. **Backup**: Always backup before making bulk changes
6. **Gradual Rollout**: Implement changes gradually, not all at once

## Support

For additional support:
1. Check the Django admin interface for policy management
2. Use the API endpoints for programmatic access
3. Review the leave management dashboard for visual insights
4. Contact system administrators for complex policy changes
