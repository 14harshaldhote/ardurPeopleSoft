#!/bin/bash

# Comprehensive Scenario Test Runner for Appraisal System
# Tests all possible workflows, rejections, approvals, comments, and notifications

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     APPRAISAL SYSTEM - SCENARIO TEST SUITE              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "${BLUE}Running comprehensive scenario tests...${NC}"
echo ""

# Test 1: Complete Happy Path
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 1: Complete Happy Path${NC}"
echo "Create → Submit → Manager Approve → HR Approve → Finance Approve"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario01_CompleteHappyPath --verbosity=2

# Test 2: Manager Rejection
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 2: Manager Rejection${NC}"
echo "Create → Submit → Manager Rejects with Comments"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario02_ManagerRejection --verbosity=2

# Test 3: HR Rejection
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 3: HR Rejection${NC}"
echo "Create → Submit → Manager Approve → HR Rejects (Policy)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario03_HRRejection --verbosity=2

# Test 4: Finance Rejection
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 4: Finance Rejection${NC}"
echo "Create → Submit → Manager → HR → Finance Rejects (Budget)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario04_FinanceRejection --verbosity=2

# Test 5: Permission Checks
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 5: Permission Violations${NC}"
echo "Test all permission boundary checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario05_PermissionChecks --verbosity=2

# Test 6: Notifications
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 6: Notification Flow${NC}"
echo "Verify notifications sent at each workflow stage"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario06_NotificationFlow --verbosity=2

# Test 7: Edge Cases
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "${YELLOW}SCENARIO 7: Edge Cases${NC}"
echo "Error handling and edge cases"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python manage.py test trueAlign.apprisal.tests.test_scenarios.Scenario07_EdgeCases --verbosity=2

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              SCENARIO TEST SUITE COMPLETE                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "${GREEN}All scenario tests completed!${NC}"
echo ""
echo "To run ALL tests (including unit tests):"
echo "  ${BLUE}python manage.py test trueAlign.apprisal.tests${NC}"
echo ""
