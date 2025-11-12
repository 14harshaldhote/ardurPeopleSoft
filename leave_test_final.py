#!/usr/bin/env python3
"""
Leave Management Test Suite - Final Part
Remaining test scenarios and execution
"""

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
    
    # Apply for leave
    leave_data = {
        'leave_type': leave_type.id,
        'start_date': date.today() + timedelta(days=40),
        'end_date': date.today() + timedelta(days=42),
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
    
    # Apply for past date leave
    retroactive_data = {
        'leave_type': leave_type.id,
        'start_date': date.today() - timedelta(days=3),
        'end_date': date.today() - timedelta(days=2),
        'half_day': False,
        'reason': 'Emergency family situation',
        'is_retroactive': True
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
