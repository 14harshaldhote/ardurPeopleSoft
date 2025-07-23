#!/bin/bash
# Leave Management System - Test Runner and Health Report Generator
#
# This script runs comprehensive tests on the Leave Management System
# and generates a health report.

set -e

# Configuration
PYTHON=python
MANAGE=manage.py
TEST_MODULE=trueAlign.leave_management.tests
HEALTH_REPORT=trueAlign/leave_management/tests/generate_health_report.py

# Text formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "\n${BOLD}$1${NC}"
    echo "==========================================================="
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

run_tests() {
    local test_module=$1
    local description=$2

    print_header "Running $description"

    $PYTHON $MANAGE test $test_module

    if [ $? -eq 0 ]; then
        print_success "$description tests passed!"
    else
        print_error "$description tests failed!"
        exit 1
    fi
}

generate_health_report() {
    print_header "Generating Health Report"

    $PYTHON $HEALTH_REPORT

    if [ $? -eq 0 ]; then
        print_success "Health report generated successfully!"
    else
        print_error "Failed to generate health report!"
        exit 1
    fi
}

# Main execution
clear
echo "====================================================="
echo "${BOLD}Leave Management System - Test Suite${NC}"
echo "====================================================="
echo "Started at: $(date)"
echo

# Check environment
print_header "Checking Environment"
if ! command -v $PYTHON &> /dev/null; then
    print_error "Python not found!"
    exit 1
fi

print_info "Python: $($PYTHON --version)"
print_info "Django: $($PYTHON -c 'import django; print(django.get_version())')"
print_info "Working directory: $(pwd)"

# Run tests
if [[ $1 == "--all" || $1 == "-a" ]]; then
    run_tests "${TEST_MODULE}" "All Leave Management"
elif [[ $1 == "--core" || $1 == "-c" ]]; then
    run_tests "${TEST_MODULE}.test_final" "Core Leave Management"
elif [[ $1 == "--health" || $1 == "-h" ]]; then
    generate_health_report
    exit 0
else
    # Default test set
    run_tests "${TEST_MODULE}.test_final" "Core Leave Management"
fi

# Generate health report unless skipped
if [[ $2 != "--no-report" && $2 != "-n" ]]; then
    generate_health_report
fi

# Summary
print_header "Test Suite Completed"
echo "Finished at: $(date)"
print_success "All tests passed!"
echo
echo "To view detailed test reports, check the log files in the project directory."
echo "====================================================="
