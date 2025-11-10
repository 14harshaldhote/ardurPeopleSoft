#!/bin/bash
# Appraisal System Test Runner
# Comprehensive test execution script

echo "=================================="
echo "Appraisal System - Test Suite"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if manage.py exists
if [ ! -f "manage.py" ]; then
    echo -e "${RED}Error: manage.py not found. Please run from project root.${NC}"
    exit 1
fi

# Function to run tests
run_tests() {
    local test_path=$1
    local test_name=$2
    
    echo -e "${YELLOW}Running ${test_name}...${NC}"
    python manage.py test $test_path --verbosity=2
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ ${test_name} PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ ${test_name} FAILED${NC}"
        return 1
    fi
}

# Track results
total_tests=0
passed_tests=0
failed_tests=0

echo "Step 1: Model Tests"
echo "-------------------"
run_tests "trueAlign.apprisal.tests.test_models" "Model Tests"
if [ $? -eq 0 ]; then ((passed_tests++)); else ((failed_tests++)); fi
((total_tests++))
echo ""

echo "Step 2: Service Layer Tests"
echo "---------------------------"
run_tests "trueAlign.apprisal.tests.test_service" "Service Tests"
if [ $? -eq 0 ]; then ((passed_tests++)); else ((failed_tests++)); fi
((total_tests++))
echo ""

echo "Step 3: View Tests"
echo "-----------------"
run_tests "trueAlign.apprisal.tests.test_views" "View Tests"
if [ $? -eq 0 ]; then ((passed_tests++)); else ((failed_tests++)); fi
((total_tests++))
echo ""

echo "Step 4: Integration Tests"
echo "------------------------"
run_tests "trueAlign.apprisal.tests.test_integration" "Integration Tests"
if [ $? -eq 0 ]; then ((passed_tests++)); else ((failed_tests++)); fi
((total_tests++))
echo ""

echo "=================================="
echo "Test Summary"
echo "=================================="
echo "Total Test Suites: $total_tests"
echo -e "${GREEN}Passed: $passed_tests${NC}"
if [ $failed_tests -gt 0 ]; then
    echo -e "${RED}Failed: $failed_tests${NC}"
else
    echo "Failed: 0"
fi
echo ""

if [ $failed_tests -eq 0 ]; then
    echo -e "${GREEN}=================================="
    echo "✓ ALL TESTS PASSED!"
    echo -e "==================================${NC}"
    echo ""
    echo "System is ready for deployment!"
    exit 0
else
    echo -e "${RED}=================================="
    echo "✗ SOME TESTS FAILED"
    echo -e "==================================${NC}"
    echo ""
    echo "Please fix failing tests before deployment."
    exit 1
fi
