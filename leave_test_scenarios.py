#!/usr/bin/env python3
"""
Leave Management Test Scenarios - Part 2
Real-world test scenarios for comprehensive testing
"""

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
        except Exception as e:
            self.log_test(f"Allocate Leaves - {username}", "FAILED", str(e))

def test_basic_leave_application(self, users, leave_types):
    """Test basic leave application functionality"""
    self.log_workflow("SCENARIO 1", "Testing basic leave application")
    
    user = users['john_employee']
    leave_type = leave_types['Annual Leave']
    
    leave_data = {
        'leave_type': leave_type.id,
        'start_date': date.today() + timedelta(days=10),
        'end_date': date.today() + timedelta(days=12),
        'half_day': False,
        'reason': 'Family vacation',
        'is_retroactive': False
    }
    
    try:
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
    
    # Step 1: Employee applies for leave
    leave_data = {
        'leave_type': leave_type.id,
        'start_date': date.today() + timedelta(days=5),
        'end_date': date.today() + timedelta(days=6),
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
    leave_type = leave_types['Sick Leave']
    
    # Apply for first leave
    first_leave_data = {
        'leave_type': leave_type.id,
        'start_date': date.today() + timedelta(days=20),
        'end_date': date.today() + timedelta(days=22),
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
            
            # Try to apply for overlapping leave
            overlapping_leave_data = {
                'leave_type': leave_type.id,
                'start_date': date.today() + timedelta(days=21),
                'end_date': date.today() + timedelta(days=23),
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
    
    half_day_data = {
        'leave_type': leave_type.id,
        'start_date': date.today() + timedelta(days=8),
        'end_date': date.today() + timedelta(days=8),
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
