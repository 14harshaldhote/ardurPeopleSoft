#!/usr/bin/env python3
"""
Simple script to run the comprehensive leave management tests
"""
import subprocess
import sys
import os

def run_tests():
    """Run the comprehensive leave management test suite"""
    
    print("="*60)
    print("COMPREHENSIVE LEAVE MANAGEMENT TEST EXECUTION")
    print("="*60)
    
    # Change to the project directory
    project_dir = "/Users/harshalsmac/WORK/ardur/ardurHome"
    os.chdir(project_dir)
    
    try:
        # Run the comprehensive test
        print("\nExecuting comprehensive leave management tests...")
        result = subprocess.run([
            sys.executable, 
            "comprehensive_leave_test.py"
        ], capture_output=True, text=True, timeout=300)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n✓ Test execution completed successfully!")
        else:
            print(f"\n✗ Test execution failed with return code: {result.returncode}")
            
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("\n✗ Test execution timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"\n✗ Error executing tests: {str(e)}")
        return False

def main():
    """Main function"""
    success = run_tests()
    
    if success:
        print("\n" + "="*60)
        print("TEST EXECUTION SUMMARY")
        print("="*60)
        print("✓ All tests executed successfully")
        print("✓ Check 'leave_management_test_report.json' for detailed results")
        print("✓ Review the console output above for workflow details")
    else:
        print("\n" + "="*60)
        print("TEST EXECUTION FAILED")
        print("="*60)
        print("✗ Some tests may have failed or encountered errors")
        print("✗ Check the error messages above for details")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
