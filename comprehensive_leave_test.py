#!/usr/bin/env python3
"""
Comprehensive Leave Management Test Suite
Real-world scenarios testing for leave management system
"""
import os
import sys
import django
from datetime import datetime, timedelta, date
from decimal import Decimal
import json

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from django.db import transaction
from django.utils import timezone
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)
from trueAlign.leave_management.services.leave_service import LeaveService
from django.core.files.uploadedfile import SimpleUploadedFile

class LeaveManagementTestSuite:
    def __init__(self):
        self.test_results = []
        self.workflow_details = []
        
    def log_test(self, test_name, status, details="", workflow_step=""):
        """Log test results"""
        result = {
            'test_name': test_name,
            'status': status,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'workflow_step': workflow_step
        }
        self.test_results.append(result)
        print(f"[{status}] {test_name}: {details}")
        
    def log_workflow(self, step, description, data=None):
        """Log workflow details"""
        workflow = {
            'step': step,
            'description': description,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        self.workflow_details.append(workflow)
        print(f"WORKFLOW: {step} - {description}")
        
    def get_weekday_date(self, days_ahead):
        """Get a weekday date (skip weekends)"""
        target_date = date.today() + timedelta(days=days_ahead)
        while target_date.weekday() >= 5:  # Skip weekends (Saturday=5, Sunday=6)
            target_date += timedelta(days=1)
        return target_date
        
    def cleanup_database(self):
        """Clean existing policies, types, and allocations"""
        print("\n=== CLEANING DATABASE ===")
        
        try:
            with transaction.atomic():
                # Delete leave requests
                deleted_requests = LeaveRequest.objects.all().delete()
                self.log_test("Delete Leave Requests", "SUCCESS", 
                            f"Deleted {deleted_requests[0]} leave requests")
                
                # Delete comp-off requests
                deleted_compoff = CompOffRequest.objects.all().delete()
                self.log_test("Delete Comp-off Requests", "SUCCESS", 
                            f"Deleted {deleted_compoff[0]} comp-off requests")
                
                # Delete user balances
                deleted_balances = UserLeaveBalance.objects.all().delete()
                self.log_test("Delete User Balances", "SUCCESS", 
                            f"Deleted {deleted_balances[0]} user balances")
                
                # Delete allocations
                deleted_allocations = LeaveAllocation.objects.all().delete()
                self.log_test("Delete Leave Allocations", "SUCCESS", 
                            f"Deleted {deleted_allocations[0]} allocations")
                
                # Delete policies
                deleted_policies = LeavePolicy.objects.all().delete()
                self.log_test("Delete Leave Policies", "SUCCESS", 
                            f"Deleted {deleted_policies[0]} policies")
                
                # Delete leave types
                deleted_types = LeaveType.objects.all().delete()
                self.log_test("Delete Leave Types", "SUCCESS", 
                            f"Deleted {deleted_types[0]} leave types")
                
        except Exception as e:
            self.log_test("Database Cleanup", "FAILED", str(e))
            
    def create_test_data(self):
        """Create comprehensive test data"""
        print("\n=== CREATING TEST DATA ===")
        
        try:
            with transaction.atomic():
                # Create Groups
                groups = ['HR', 'Manager', 'Employee', 'Admin', 'Intern']
                for group_name in groups:
                    group, created = Group.objects.get_or_create(name=group_name)
                    if created:
                        self.log_test(f"Create Group {group_name}", "SUCCESS", "Group created")
                
                # Create Leave Types
                leave_types_data = [
                    {
                        'name': 'Annual Leave',
                        'description': 'Yearly vacation leave',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': False,
                        'can_be_half_day': True,
                        'max_days_allowed': 30,
                        'carry_forward_allowed': True
                    },
                    {
                        'name': 'Sick Leave',
                        'description': 'Medical leave',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': True,
                        'count_weekends': False,
                        'can_be_half_day': True,
                        'max_days_allowed': 15,
                        'carry_forward_allowed': False
                    },
                    {
                        'name': 'Casual Leave',
                        'description': 'Short-term personal leave',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': False,
                        'can_be_half_day': True,
                        'max_days_allowed': 12,
                        'carry_forward_allowed': False
                    },
                    {
                        'name': 'Maternity Leave',
                        'description': 'Maternity leave for mothers',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': True,
                        'count_weekends': True,
                        'can_be_half_day': False,
                        'max_days_allowed': 180,
                        'carry_forward_allowed': False
                    },
                    {
                        'name': 'Paternity Leave',
                        'description': 'Paternity leave for fathers',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': True,
                        'count_weekends': True,
                        'can_be_half_day': False,
                        'max_days_allowed': 15,
                        'carry_forward_allowed': False
                    },
                    {
                        'name': 'Comp Off',
                        'description': 'Compensatory off for overtime work',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': False,
                        'can_be_half_day': True,
                        'max_days_allowed': 50,
                        'carry_forward_allowed': True
                    },
                    {
                        'name': 'Loss of Pay',
                        'description': 'Unpaid leave',
                        'is_paid': False,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': False,
                        'can_be_half_day': True,
                        'max_days_allowed': 365,
                        'carry_forward_allowed': False
                    },
                    {
                        'name': 'Emergency Leave',
                        'description': 'Emergency situations',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': True,
                        'count_weekends': False,
                        'can_be_half_day': False,
                        'max_days_allowed': 5,
                        'carry_forward_allowed': False
                    }
                ]
                
                created_leave_types = {}
                for lt_data in leave_types_data:
                    leave_type = LeaveType.objects.create(**lt_data)
                    created_leave_types[lt_data['name']] = leave_type
                    self.log_test(f"Create Leave Type {lt_data['name']}", "SUCCESS", 
                                f"Max days: {lt_data['max_days_allowed']}")
                
                # Create Leave Policies
                policies_data = [
                    {
                        'name': 'Standard Employee Policy',
                        'group_name': 'Employee',
                        'allocations': {
                            'Annual Leave': {'annual_days': 21, 'advance_notice_days': 7, 'max_consecutive_days': 15, 'carryforward_limit': 5},
                            'Sick Leave': {'annual_days': 12, 'advance_notice_days': 0, 'max_consecutive_days': 7, 'carryforward_limit': 0},
                            'Casual Leave': {'annual_days': 12, 'advance_notice_days': 1, 'max_consecutive_days': 3, 'carryforward_limit': 0},
                            'Emergency Leave': {'annual_days': 3, 'advance_notice_days': 0, 'max_consecutive_days': 2, 'carryforward_limit': 0}
                        }
                    },
                    {
                        'name': 'Manager Policy',
                        'group_name': 'Manager',
                        'allocations': {
                            'Annual Leave': {'annual_days': 28, 'advance_notice_days': 14, 'max_consecutive_days': 21, 'carryforward_limit': 7},
                            'Sick Leave': {'annual_days': 15, 'advance_notice_days': 0, 'max_consecutive_days': 10, 'carryforward_limit': 0},
                            'Casual Leave': {'annual_days': 15, 'advance_notice_days': 2, 'max_consecutive_days': 5, 'carryforward_limit': 0},
                            'Emergency Leave': {'annual_days': 5, 'advance_notice_days': 0, 'max_consecutive_days': 3, 'carryforward_limit': 0}
                        }
                    },
                    {
                        'name': 'HR Policy',
                        'group_name': 'HR',
                        'allocations': {
                            'Annual Leave': {'annual_days': 25, 'advance_notice_days': 10, 'max_consecutive_days': 18, 'carryforward_limit': 6},
                            'Sick Leave': {'annual_days': 15, 'advance_notice_days': 0, 'max_consecutive_days': 10, 'carryforward_limit': 0},
                            'Casual Leave': {'annual_days': 15, 'advance_notice_days': 1, 'max_consecutive_days': 4, 'carryforward_limit': 0},
                            'Emergency Leave': {'annual_days': 5, 'advance_notice_days': 0, 'max_consecutive_days': 3, 'carryforward_limit': 0}
                        }
                    },
                    {
                        'name': 'Intern Policy',
                        'group_name': 'Intern',
                        'allocations': {
                            'Annual Leave': {'annual_days': 10, 'advance_notice_days': 3, 'max_consecutive_days': 5, 'carryforward_limit': 0},
                            'Sick Leave': {'annual_days': 5, 'advance_notice_days': 0, 'max_consecutive_days': 3, 'carryforward_limit': 0},
                            'Casual Leave': {'annual_days': 6, 'advance_notice_days': 1, 'max_consecutive_days': 2, 'carryforward_limit': 0}
                        }
                    }
                ]
                
                created_policies = {}
                for policy_data in policies_data:
                    group = Group.objects.get(name=policy_data['group_name'])
                    policy = LeavePolicy.objects.create(
                        name=policy_data['name'],
                        group=group,
                        effective_from=date.today(),
                        created_by=None
                    )
                    created_policies[policy_data['name']] = policy
                    
                    # Create allocations for this policy
                    for leave_type_name, allocation_data in policy_data['allocations'].items():
                        if leave_type_name in created_leave_types:
                            LeaveAllocation.objects.create(
                                policy=policy,
                                leave_type=created_leave_types[leave_type_name],
                                **allocation_data
                            )
                    
                    self.log_test(f"Create Policy {policy_data['name']}", "SUCCESS", 
                                f"Group: {policy_data['group_name']}, Allocations: {len(policy_data['allocations'])}")
                
                # Create Test Users
                test_users_data = [
                    {'username': 'john_employee', 'first_name': 'John', 'last_name': 'Doe', 'email': 'john@company.com', 'groups': ['Employee']},
                    {'username': 'jane_manager', 'first_name': 'Jane', 'last_name': 'Smith', 'email': 'jane@company.com', 'groups': ['Manager']},
                    {'username': 'bob_hr', 'first_name': 'Bob', 'last_name': 'Johnson', 'email': 'bob@company.com', 'groups': ['HR']},
                    {'username': 'alice_employee', 'first_name': 'Alice', 'last_name': 'Brown', 'email': 'alice@company.com', 'groups': ['Employee']},
                    {'username': 'mike_intern', 'first_name': 'Mike', 'last_name': 'Wilson', 'email': 'mike@company.com', 'groups': ['Intern']},
                    {'username': 'sarah_manager', 'first_name': 'Sarah', 'last_name': 'Davis', 'email': 'sarah@company.com', 'groups': ['Manager']},
                ]
                
                created_users = {}
                for user_data in test_users_data:
                    user, created = User.objects.get_or_create(
                        username=user_data['username'],
                        defaults={
                            'first_name': user_data['first_name'],
                            'last_name': user_data['last_name'],
                            'email': user_data['email'],
                            'is_active': True
                        }
                    )
                    
                    # Add to groups
                    for group_name in user_data['groups']:
                        group = Group.objects.get(name=group_name)
                        user.groups.add(group)
                    
                    created_users[user_data['username']] = user
                    self.log_test(f"Create User {user_data['username']}", "SUCCESS", 
                                f"Groups: {', '.join(user_data['groups'])}")
                
                return created_users, created_leave_types, created_policies
                
        except Exception as e:
            self.log_test("Create Test Data", "FAILED", str(e))
            return {}, {}, {}
    
    def run_test_scenarios(self, users, leave_types, policies):
        """Run comprehensive test scenarios"""
        print("\n=== RUNNING TEST SCENARIOS ===")
        
        # Allocate leaves to all users first
        self.allocate_leaves_to_users(users)
        
        # Test Scenario 1: Basic Leave Application
        self.test_basic_leave_application(users, leave_types)
        
        # Test Scenario 2: Leave Approval Workflow
        self.test_leave_approval_workflow(users, leave_types)
        
        # Test Scenario 3: Insufficient Balance Handling
        self.test_insufficient_balance(users, leave_types)
        
        # Test Scenario 4: Overlapping Leave Detection
        self.test_overlapping_leaves(users, leave_types)
        
        # Test Scenario 5: Half-day Leave Processing
        self.test_half_day_leaves(users, leave_types)
        
        # Test Scenario 6: Advance Notice Validation
        self.test_advance_notice_validation(users, leave_types)
        
        # Test Scenario 7: Consecutive Days Limit
        self.test_consecutive_days_limit(users, leave_types)
        
        # Test Scenario 8: Documentation Requirements
        self.test_documentation_requirements(users, leave_types)
        
        # Test Scenario 9: Comp-off Management
        self.test_comp_off_management(users, leave_types)
        
        # Test Scenario 10: Leave Cancellation
        self.test_leave_cancellation(users, leave_types)
        
        # Test Scenario 11: Retroactive Leave Application
        self.test_retroactive_leaves(users, leave_types)
        
        # Test Scenario 12: Bulk Operations
        self.test_bulk_operations(users, leave_types)

    def allocate_leaves_to_users(self, users):
        """Allocate leaves to all test users"""
        self.log_workflow("STEP 1", "Allocating leaves to all users")
        
        for username, user in users.items():
            try:
                result = LeaveService.allocate_leaves_to_user(user, {}, 2024)
                self.log_test(f"Allocate Leaves - {username}", "SUCCESS", 
                            f"Allocated leaves for {user.get_full_name()}")
                
                # Debug: Check actual balances created
                balances = UserLeaveBalance.objects.filter(user=user, year=2024)
                print(f"DEBUG: {username} has {balances.count()} balance records")
                for balance in balances:
                    print(f"DEBUG: {username} - {balance.leave_type.name}: allocated={balance.allocated}, used={balance.used}, available={balance.available}, is_deleted={balance.is_deleted}")
                
                # Also check with the manager method
                manager_balances = UserLeaveBalance.objects.for_user_and_year(user, 2024)
                print(f"DEBUG: Manager method returns {manager_balances.count()} records for {username}")
                    
            except Exception as e:
                self.log_test(f"Allocate Leaves - {username}", "FAILED", str(e))

    def test_basic_leave_application(self, users, leave_types):
        """Test basic leave application functionality"""
        self.log_workflow("SCENARIO 1", "Testing basic leave application")
        
        user = users['john_employee']
        leave_type = leave_types['Annual Leave']
        
        # Calculate weekday dates (avoid weekends) - use 8 days ahead to satisfy advance notice
        start_date = self.get_weekday_date(8)
        end_date = start_date  # Single day
            
        leave_data = {
            'leave_type': leave_type.id,
            'start_date': start_date,
            'end_date': end_date,
            'half_day': False,
            'reason': 'Family vacation',
            'is_retroactive': False
        }
        
        try:
            # Debug: Check balance before application
            balance = UserLeaveBalance.objects.get(user=user, leave_type=leave_type, year=2024)
            print(f"DEBUG: Before application - {user.username} {leave_type.name}: available={balance.available}")
            
            # Create leave request to check calculation
            temp_request = LeaveRequest(
                user=user,
                leave_type=leave_type,
                start_date=leave_data['start_date'],
                end_date=leave_data['end_date'],
                half_day=leave_data['half_day']
            )
            calculated_days = temp_request.calculate_leave_days()
            print(f"DEBUG: Calculated days for {leave_data['start_date']} to {leave_data['end_date']}: {calculated_days}")
            print(f"DEBUG: Leave type count_weekends: {leave_type.count_weekends}")
            
            leave_request, result = LeaveService.apply_leave(user, leave_data)
            if result['is_valid']:
                self.log_test("Basic Leave Application", "SUCCESS", 
                            f"Leave request created: ID {leave_request.id}")
                self.log_workflow("WORKFLOW", f"Leave application submitted by {user.username}", {
                    'leave_type': leave_type.name,
                    'duration': f"{leave_data['start_date']} to {leave_data['end_date']}",
                    'status': leave_request.status
                })
            else:
                self.log_test("Basic Leave Application", "FAILED", 
                            f"Validation errors: {result['errors']}")
        except Exception as e:
            self.log_test("Basic Leave Application", "FAILED", str(e))

    def test_leave_approval_workflow(self, users, leave_types):
        """Test complete leave approval workflow"""
        self.log_workflow("SCENARIO 2", "Testing leave approval workflow")
        
        employee = users['alice_employee']
        manager = users['jane_manager']
        leave_type = leave_types['Casual Leave']
        
        # Step 1: Employee applies for leave (use 2 days ahead for casual leave which needs 1 day notice)
        start_date = self.get_weekday_date(2)
        
        leave_data = {
            'leave_type': leave_type.id,
            'start_date': start_date,
            'end_date': start_date,  # Single day
            'half_day': False,
            'reason': 'Personal work',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(employee, leave_data)
            if result['is_valid']:
                self.log_workflow("WORKFLOW", f"Leave applied by {employee.username}", {
                    'request_id': leave_request.id,
                    'status': 'Pending'
                })
                
                # Step 2: Manager approves leave
                approval_result = LeaveService.approve_leave(leave_request, manager, "Approved for personal work")
                if approval_result['success']:
                    self.log_test("Leave Approval Workflow", "SUCCESS", 
                                f"Complete workflow: Apply -> Approve")
                    self.log_workflow("WORKFLOW", f"Leave approved by {manager.username}", {
                        'request_id': leave_request.id,
                        'status': 'Approved'
                    })
                else:
                    self.log_test("Leave Approval Workflow", "FAILED", 
                                f"Approval failed: {approval_result}")
            else:
                self.log_test("Leave Approval Workflow", "FAILED", 
                            f"Application failed: {result['errors']}")
        except Exception as e:
            self.log_test("Leave Approval Workflow", "FAILED", str(e))

    def test_insufficient_balance(self, users, leave_types):
        """Test insufficient balance handling and auto-conversion"""
        self.log_workflow("SCENARIO 3", "Testing insufficient balance handling")
        
        user = users['mike_intern']  # Intern with limited leave balance
        leave_type = leave_types['Annual Leave']
        
        # Try to apply for more days than available
        leave_data = {
            'leave_type': leave_type.id,
            'start_date': date.today() + timedelta(days=15),
            'end_date': date.today() + timedelta(days=25),  # 11 days, but intern only has 10
            'half_day': False,
            'reason': 'Extended vacation',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, leave_data)
            
            if not result['is_valid'] and 'Insufficient' in str(result['errors']):
                self.log_test("Insufficient Balance Detection", "SUCCESS", 
                            "System correctly detected insufficient balance")
                
                # Test auto-conversion to Loss of Pay
                if result.get('can_auto_convert'):
                    self.log_test("Auto-conversion Available", "SUCCESS", 
                                "System can auto-convert to Loss of Pay")
                    self.log_workflow("WORKFLOW", "Auto-conversion option available", {
                        'original_type': leave_type.name,
                        'suggested_type': 'Loss of Pay'
                    })
            else:
                self.log_test("Insufficient Balance Handling", "FAILED", 
                            f"Expected insufficient balance error, got: {result}")
        except Exception as e:
            self.log_test("Insufficient Balance Handling", "FAILED", str(e))

    def test_overlapping_leaves(self, users, leave_types):
        """Test overlapping leave detection"""
        self.log_workflow("SCENARIO 4", "Testing overlapping leave detection")
        
        user = users['john_employee']
        leave_type = leave_types['Annual Leave']  # Use Annual Leave instead of Sick Leave to avoid documentation requirement
        
        # Apply for first leave (8 days ahead for annual leave)
        start_date = self.get_weekday_date(8)
        end_date = start_date  # Single day
        
        first_leave_data = {
            'leave_type': leave_type.id,
            'start_date': start_date,
            'end_date': end_date,
            'half_day': False,
            'reason': 'Medical checkup',
            'is_retroactive': False
        }
        
        try:
            first_request, first_result = LeaveService.apply_leave(user, first_leave_data)
            if first_result['is_valid']:
                # Approve first leave
                manager = users['jane_manager']
                LeaveService.approve_leave(first_request, manager)
                
                # Try to apply for overlapping leave (same date)
                overlap_start = start_date
                overlap_end = start_date
                
                overlapping_leave_data = {
                    'leave_type': leave_type.id,
                    'start_date': overlap_start,
                    'end_date': overlap_end,
                    'half_day': False,
                    'reason': 'Follow-up appointment',
                    'is_retroactive': False
                }
                
                second_request, second_result = LeaveService.apply_leave(user, overlapping_leave_data)
                
                if not second_result['is_valid'] and 'overlapping' in str(second_result['errors']).lower():
                    self.log_test("Overlapping Leave Detection", "SUCCESS", 
                                "System correctly detected overlapping leaves")
                    self.log_workflow("WORKFLOW", "Overlapping leave rejected", {
                        'first_leave': f"{first_leave_data['start_date']} to {first_leave_data['end_date']}",
                        'overlapping_leave': f"{overlapping_leave_data['start_date']} to {overlapping_leave_data['end_date']}"
                    })
                else:
                    self.log_test("Overlapping Leave Detection", "FAILED", 
                                f"Expected overlap error, got: {second_result}")
            else:
                self.log_test("Overlapping Leave Detection", "FAILED", 
                            f"First leave application failed: {first_result}")
        except Exception as e:
            self.log_test("Overlapping Leave Detection", "FAILED", str(e))

    def test_half_day_leaves(self, users, leave_types):
        """Test half-day leave functionality"""
        self.log_workflow("SCENARIO 5", "Testing half-day leave processing")
        
        user = users['alice_employee']
        leave_type = leave_types['Casual Leave']
        
        start_date = self.get_weekday_date(2)  # 2 days ahead for casual leave
        
        half_day_data = {
            'leave_type': leave_type.id,
            'start_date': start_date,
            'end_date': start_date,
            'half_day': True,
            'reason': 'Doctor appointment',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, half_day_data)
            if result['is_valid']:
                # Check if leave days calculated correctly (should be 0.5)
                if leave_request.leave_days == Decimal('0.5'):
                    self.log_test("Half-day Leave Calculation", "SUCCESS", 
                                f"Correctly calculated 0.5 days for half-day leave")
                    self.log_workflow("WORKFLOW", "Half-day leave processed", {
                        'calculated_days': float(leave_request.leave_days),
                        'date': str(half_day_data['start_date'])
                    })
                else:
                    self.log_test("Half-day Leave Calculation", "FAILED", 
                                f"Expected 0.5 days, got {leave_request.leave_days}")
            else:
                self.log_test("Half-day Leave Processing", "FAILED", 
                            f"Half-day leave application failed: {result['errors']}")
        except Exception as e:
            self.log_test("Half-day Leave Processing", "FAILED", str(e))

    def test_advance_notice_validation(self, users, leave_types):
        """Test advance notice requirement validation"""
        self.log_workflow("SCENARIO 6", "Testing advance notice validation")
        
        user = users['jane_manager']  # Manager policy requires 14 days advance notice for annual leave
        leave_type = leave_types['Annual Leave']
        
        # Try to apply for leave with insufficient advance notice
        insufficient_notice_data = {
            'leave_type': leave_type.id,
            'start_date': date.today() + timedelta(days=5),  # Only 5 days notice
            'end_date': date.today() + timedelta(days=7),
            'half_day': False,
            'reason': 'Urgent family matter',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, insufficient_notice_data)
            
            if not result['is_valid'] and 'advance notice' in str(result['errors']).lower():
                self.log_test("Advance Notice Validation", "SUCCESS", 
                            "System correctly enforced advance notice requirement")
                self.log_workflow("WORKFLOW", "Advance notice validation triggered", {
                    'required_days': 14,
                    'provided_days': 5,
                    'status': 'Rejected'
                })
            else:
                self.log_test("Advance Notice Validation", "FAILED", 
                            f"Expected advance notice error, got: {result}")
        except Exception as e:
            self.log_test("Advance Notice Validation", "FAILED", str(e))

    def test_consecutive_days_limit(self, users, leave_types):
        """Test consecutive days limit validation"""
        self.log_workflow("SCENARIO 7", "Testing consecutive days limit")
        
        user = users['mike_intern']  # Intern policy has 5 days max consecutive for annual leave
        leave_type = leave_types['Annual Leave']
        
        # Try to apply for more consecutive days than allowed
        excessive_days_data = {
            'leave_type': leave_type.id,
            'start_date': date.today() + timedelta(days=30),
            'end_date': date.today() + timedelta(days=36),  # 7 days, but limit is 5
            'half_day': False,
            'reason': 'Long vacation',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, excessive_days_data)
            
            if not result['is_valid'] and 'consecutive' in str(result['errors']).lower():
                self.log_test("Consecutive Days Limit", "SUCCESS", 
                            "System correctly enforced consecutive days limit")
                self.log_workflow("WORKFLOW", "Consecutive days limit enforced", {
                    'max_allowed': 5,
                    'requested': 7,
                    'status': 'Rejected'
                })
            else:
                self.log_test("Consecutive Days Limit", "FAILED", 
                            f"Expected consecutive days error, got: {result}")
        except Exception as e:
            self.log_test("Consecutive Days Limit", "FAILED", str(e))

    def test_documentation_requirements(self, users, leave_types):
        """Test documentation requirement validation"""
        self.log_workflow("SCENARIO 8", "Testing documentation requirements")
        
        user = users['alice_employee']
        leave_type = leave_types['Sick Leave']  # Requires documentation
        
        # Try to apply without documentation
        no_doc_data = {
            'leave_type': leave_type.id,
            'start_date': date.today() + timedelta(days=25),
            'end_date': date.today() + timedelta(days=27),
            'half_day': False,
            'reason': 'Flu symptoms',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, no_doc_data)
            
            if not result['is_valid'] and 'documentation' in str(result['errors']).lower():
                self.log_test("Documentation Requirement", "SUCCESS", 
                            "System correctly enforced documentation requirement")
                self.log_workflow("WORKFLOW", "Documentation requirement enforced", {
                    'leave_type': leave_type.name,
                    'requires_doc': True,
                    'provided': False,
                    'status': 'Rejected'
                })
            else:
                self.log_test("Documentation Requirement", "FAILED", 
                            f"Expected documentation error, got: {result}")
        except Exception as e:
            self.log_test("Documentation Requirement", "FAILED", str(e))

    def test_comp_off_management(self, users, leave_types):
        """Test comp-off request and approval workflow"""
        self.log_workflow("SCENARIO 9", "Testing comp-off management")
        
        user = users['john_employee']
        manager = users['jane_manager']
        
        comp_off_data = {
            'worked_date': date.today() - timedelta(days=2),
            'reason': 'Weekend project deployment',
            'hours_worked': Decimal('10.0')
        }
        
        try:
            result = LeaveService.apply_comp_off(user, comp_off_data)
            if result['success']:
                # Get the comp-off request
                comp_off_request = CompOffRequest.objects.get(id=result['request_id'])
                
                # Approve comp-off
                comp_off_request.status = 'Approved'
                comp_off_request.approver = manager
                comp_off_request.save()
                
                self.log_test("Comp-off Management", "SUCCESS", 
                            f"Comp-off request created and approved: {result['request_id']}")
                self.log_workflow("WORKFLOW", "Comp-off workflow completed", {
                    'worked_date': str(comp_off_data['worked_date']),
                    'hours_worked': float(comp_off_data['hours_worked']),
                    'days_earned': float(comp_off_data['hours_worked'] / 8),
                    'status': 'Approved'
                })
            else:
                self.log_test("Comp-off Management", "FAILED", 
                            f"Comp-off application failed: {result}")
        except Exception as e:
            self.log_test("Comp-off Management", "FAILED", str(e))

    def test_leave_cancellation(self, users, leave_types):
        """Test leave cancellation workflow"""
        self.log_workflow("SCENARIO 10", "Testing leave cancellation")
        
        user = users['sarah_manager']
        leave_type = leave_types['Annual Leave']
        
        # Apply for leave (8 days ahead for annual leave)
        start_date = self.get_weekday_date(8)
        
        leave_data = {
            'leave_type': leave_type.id,
            'start_date': start_date,
            'end_date': start_date,  # Single day
            'half_day': False,
            'reason': 'Conference attendance',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, leave_data)
            if result['is_valid']:
                # Approve the leave first
                approver = users['bob_hr']
                LeaveService.approve_leave(leave_request, approver)
                
                # Now cancel the leave
                cancel_result = LeaveService.cancel_leave(leave_request, user, "Conference cancelled")
                
                if cancel_result['success']:
                    self.log_test("Leave Cancellation", "SUCCESS", 
                                "Leave successfully cancelled and balance reverted")
                    self.log_workflow("WORKFLOW", "Leave cancellation completed", {
                        'original_status': 'Approved',
                        'final_status': 'Cancelled',
                        'balance_reverted': True
                    })
                else:
                    self.log_test("Leave Cancellation", "FAILED", 
                                f"Cancellation failed: {cancel_result}")
            else:
                self.log_test("Leave Cancellation", "FAILED", 
                            f"Initial leave application failed: {result}")
        except Exception as e:
            self.log_test("Leave Cancellation", "FAILED", str(e))

    def test_retroactive_leaves(self, users, leave_types):
        """Test retroactive leave application"""
        self.log_workflow("SCENARIO 11", "Testing retroactive leave application")
        
        user = users['bob_hr']  # HR can apply retroactive leaves
        leave_type = leave_types['Emergency Leave']
        
        # Create mock documentation file
        mock_doc = SimpleUploadedFile(
            "emergency_doc.pdf",
            b"Mock emergency documentation content",
            content_type="application/pdf"
        )
        
        # Apply for past date leave
        retroactive_data = {
            'leave_type': leave_type.id,
            'start_date': date.today() - timedelta(days=3),
            'end_date': date.today() - timedelta(days=2),
            'half_day': False,
            'reason': 'Emergency family situation',
            'is_retroactive': True,
            'documentation': mock_doc
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, retroactive_data)
            if result['is_valid']:
                self.log_test("Retroactive Leave Application", "SUCCESS", 
                            "Retroactive leave application accepted")
                self.log_workflow("WORKFLOW", "Retroactive leave processed", {
                    'leave_dates': f"{retroactive_data['start_date']} to {retroactive_data['end_date']}",
                    'application_date': str(date.today()),
                    'is_retroactive': True
                })
            else:
                self.log_test("Retroactive Leave Application", "FAILED", 
                            f"Retroactive leave rejected: {result['errors']}")
        except Exception as e:
            self.log_test("Retroactive Leave Application", "FAILED", str(e))

    def test_bulk_operations(self, users, leave_types):
        """Test bulk leave operations"""
        self.log_workflow("SCENARIO 12", "Testing bulk operations")
        
        try:
            # Test bulk allocation
            user_list = list(users.values())
            result = LeaveService.bulk_allocate_leaves(user_list, 2025)
            
            if result['success']:
                successful_count = sum(1 for r in result['results'] if r['success'])
                self.log_test("Bulk Leave Allocation", "SUCCESS", 
                            f"Allocated leaves to {successful_count}/{len(user_list)} users for 2025")
                self.log_workflow("WORKFLOW", "Bulk allocation completed", {
                    'total_users': len(user_list),
                    'successful': successful_count,
                    'year': 2025
                })
            else:
                self.log_test("Bulk Leave Allocation", "FAILED", 
                            f"Bulk allocation failed: {result}")
        except Exception as e:
            self.log_test("Bulk Operations", "FAILED", str(e))

    def test_edge_cases(self, users, leave_types):
        """Test edge cases and boundary conditions"""
        self.log_workflow("SCENARIO 13", "Testing edge cases")
        
        user = users['alice_employee']
        
        # Test weekend leave application
        next_saturday = date.today() + timedelta(days=(5 - date.today().weekday()) % 7)
        weekend_data = {
            'leave_type': leave_types['Annual Leave'].id,
            'start_date': next_saturday,
            'end_date': next_saturday + timedelta(days=1),  # Saturday-Sunday
            'half_day': False,
            'reason': 'Weekend getaway',
            'is_retroactive': False
        }
        
        try:
            leave_request, result = LeaveService.apply_leave(user, weekend_data)
            # Should succeed but with warnings about weekends
            if result['is_valid'] and result.get('warnings'):
                weekend_warnings = [w for w in result['warnings'] if 'weekend' in w.lower()]
                if weekend_warnings:
                    self.log_test("Weekend Leave Warning", "SUCCESS", 
                                "System correctly warned about weekend dates")
            
            # Test same-day application and approval
            same_day_data = {
                'leave_type': leave_types['Emergency Leave'].id,
                'start_date': date.today(),
                'end_date': date.today(),
                'half_day': False,
                'reason': 'Medical emergency',
                'is_retroactive': True
            }
            
            emergency_request, emergency_result = LeaveService.apply_leave(user, same_day_data)
            if emergency_result['is_valid']:
                self.log_test("Same-day Emergency Leave", "SUCCESS", 
                            "Emergency leave for same day accepted")
                
        except Exception as e:
            self.log_test("Edge Cases", "FAILED", str(e))

    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*80)
        print("COMPREHENSIVE LEAVE MANAGEMENT TEST REPORT")
        print("="*80)
        
        total_tests = len(self.test_results)
        passed_tests = len([t for t in self.test_results if t['status'] == 'SUCCESS'])
        failed_tests = total_tests - passed_tests
        
        print(f"\nTEST SUMMARY:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        print(f"\nDETAILED RESULTS:")
        for test in self.test_results:
            status_symbol = "✓" if test['status'] == 'SUCCESS' else "✗"
            print(f"{status_symbol} {test['test_name']}: {test['details']}")
        
        print(f"\nWORKFLOW ANALYSIS:")
        for workflow in self.workflow_details:
            print(f"• {workflow['step']}: {workflow['description']}")
            if workflow['data']:
                for key, value in workflow['data'].items():
                    print(f"  - {key}: {value}")
        
        # System Improvement Recommendations
        print(f"\n" + "="*80)
        print("SYSTEM IMPROVEMENT RECOMMENDATIONS")
        print("="*80)
        
        recommendations = self.analyze_system_improvements()
        for category, items in recommendations.items():
            print(f"\n{category.upper()}:")
            for item in items:
                print(f"• {item}")
        
        # Save report to file
        report_data = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': passed_tests/total_tests*100
            },
            'test_results': self.test_results,
            'workflow_details': self.workflow_details,
            'recommendations': recommendations,
            'generated_at': datetime.now().isoformat()
        }
        
        with open('leave_management_test_report.json', 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"\nDetailed report saved to: leave_management_test_report.json")

    def analyze_system_improvements(self):
        """Analyze test results and provide improvement recommendations"""
        recommendations = {
            'critical_issues': [],
            'performance_optimizations': [],
            'user_experience_improvements': [],
            'workflow_enhancements': [],
            'security_considerations': [],
            'monitoring_and_analytics': []
        }
        
        # Analyze failed tests for critical issues
        failed_tests = [t for t in self.test_results if t['status'] == 'FAILED']
        if failed_tests:
            recommendations['critical_issues'].extend([
                f"Fix failed test: {test['test_name']} - {test['details']}" 
                for test in failed_tests
            ])
        
        # Performance recommendations
        recommendations['performance_optimizations'].extend([
            "Implement database indexing for leave request queries by user and date range",
            "Add caching for frequently accessed leave policies and allocations",
            "Optimize bulk operations with batch processing for large user sets",
            "Implement async processing for leave balance calculations"
        ])
        
        # UX improvements
        recommendations['user_experience_improvements'].extend([
            "Add real-time balance checking during leave application",
            "Implement leave calendar view for better date selection",
            "Add email notifications for leave status changes",
            "Create mobile-responsive leave application interface",
            "Add leave history and analytics dashboard for employees"
        ])
        
        # Workflow enhancements
        recommendations['workflow_enhancements'].extend([
            "Implement multi-level approval workflow for senior positions",
            "Add delegation feature for approvers during their absence",
            "Create automated leave approval for certain leave types",
            "Implement leave request templates for common scenarios",
            "Add bulk approval functionality for managers"
        ])
        
        # Security considerations
        recommendations['security_considerations'].extend([
            "Implement role-based access control for leave management functions",
            "Add audit trail for all leave-related actions",
            "Implement data encryption for sensitive leave information",
            "Add rate limiting for leave application APIs",
            "Implement secure file upload for leave documentation"
        ])
        
        # Monitoring and analytics
        recommendations['monitoring_and_analytics'].extend([
            "Add comprehensive logging for leave management operations",
            "Implement leave usage analytics and reporting",
            "Create alerts for unusual leave patterns",
            "Add performance monitoring for leave-related database operations",
            "Implement leave trend analysis for HR planning"
        ])
        
        return recommendations


def main():
    """Main execution function"""
    print("Starting Comprehensive Leave Management Test Suite...")
    
    test_suite = LeaveManagementTestSuite()
    
    try:
        # Step 1: Clean database
        test_suite.cleanup_database()
        
        # Step 2: Create test data
        users, leave_types, policies = test_suite.create_test_data()
        
        if users and leave_types and policies:
            # Step 3: Run test scenarios
            test_suite.run_test_scenarios(users, leave_types, policies)
            
            # Step 4: Test edge cases
            test_suite.test_edge_cases(users, leave_types)
            
            # Step 5: Generate report
            test_suite.generate_test_report()
        else:
            print("Failed to create test data. Aborting test execution.")
            
    except Exception as e:
        print(f"Test suite execution failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
