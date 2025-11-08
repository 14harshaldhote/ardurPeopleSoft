# 🧪 ATTENDANCE SYSTEM - COMPREHENSIVE TESTING MASTER PLAN

**Created**: November 8, 2025
**Purpose**: Automated end-to-end testing of attendance, shift, and session tracking
**Status**: Planning Phase

---

## 📋 SYSTEM COMPONENTS TO TEST

### 1. **UserSession Model** (`models.py`)
- Session creation (login_time, logout_time)
- Location tracking (location_type, location_city, etc.)
- Device info (user_agent, browser, os, device_type)
- IP address tracking
- Idle time calculation
- Session activity updates
- Session ending logic

### 2. **ShiftMaster & ShiftAssignment** (`models.py`)
- Shift definitions (start_time, end_time, shift_duration)
- Break duration and grace period
- Day/night shift handling
- Midnight crossing shifts
- Shift assignments to users
- Effective date ranges
- Overlapping shift validation

### 3. **Attendance Model** (`models.py`)
- Auto-creation from sessions
- Status determination (Present, Late, Absent, etc.)
- Clock in/out time tracking
- Total hours calculation
- Overtime calculation
- Late minutes calculation
- Early departure detection
- Location from session
- IP and device info population
- Idle time tracking
- Weekend/holiday detection
- Leave integration
- Regularization workflow

### 4. **AttendanceAutoMarkingService** (`attendance/services.py`)
- Missing record creation
- Session-based updates
- Status recalculation
- Time metric calculations
- Default value assignment

---

## 🎯 TEST SCENARIOS (30+ Cases)

### **Category A: Normal Working Day Scenarios**

#### Test 1: On-Time Arrival & Full Day Work
- User logs in at shift start time (within grace period)
- Works full shift duration
- Logs out at shift end time
- **Expected**:
  - Status: "Present"
  - late_minutes: 0
  - total_hours: = shift.shift_duration
  - overtime_hours: 0
  - early_departure_minutes: 0
  - All session data populated

#### Test 2: Late Arrival
- User logs in 30 minutes after shift start (beyond grace period)
- Works full remaining time
- **Expected**:
  - Status: "Present & Late"
  - late_minutes: 30
  - total_hours calculated
  - overtime_hours: 0

#### Test 3: Early Departure
- User logs in on time
- Logs out 1 hour before shift end
- **Expected**:
  - Status: "Present"
  - early_departure_minutes: 60
  - left_early: True
  - total_hours < expected_hours

#### Test 4: Overtime Work
- User logs in on time
- Works 2 hours beyond shift end
- **Expected**:
  - Status: "Present"
  - overtime_hours: 2.0
  - total_hours > expected_hours

#### Test 5: Late Arrival + Overtime
- User logs in late
- Works overtime to compensate
- **Expected**:
  - Status: "Present & Late"
  - late_minutes: calculated
  - overtime_hours: calculated

---

### **Category B: Session Management Scenarios**

#### Test 6: Multiple Sessions Same Day
- User logs in → logs out → logs in again → logs out
- **Expected**:
  - first_session: earliest session
  - last_session: latest session
  - total_sessions: 2
  - clock_in_time: first login
  - clock_out_time: last logout

#### Test 7: Idle Time Tracking
- User has session with idle periods
- **Expected**:
  - idle_time populated from session
  - total_hours excludes idle time

#### Test 8: Location Tracking
- Session has location_type: "Home"
- **Expected**:
  - attendance.location: "Home"
  - NOT default "Office"

#### Test 9: Device Info Capture
- Session has browser, OS, device info
- **Expected**:
  - device_info JSON populated
  - Contains: user_agent, browser, os, device_type

#### Test 10: IP Address Logging
- Session has IP address
- **Expected**:
  - attendance.ip_address: populated from session

---

### **Category C: Shift Scenarios**

#### Test 11: Day Shift (9 AM - 5 PM)
- Standard 8-hour shift
- **Expected**:
  - expected_hours: 8.0
  - Correct late/overtime calculations

#### Test 12: Night Shift (10 PM - 6 AM)
- Crosses midnight
- **Expected**:
  - shift.crosses_midnight: True
  - Correct time calculations across dates

#### Test 13: Custom Shift (12 PM - 9 PM)
- 9-hour shift with custom times
- **Expected**:
  - expected_hours: 9.0
  - Custom break duration applied

#### Test 14: Shift with Grace Period
- User logs in within 15-minute grace period
- **Expected**:
  - Status: "Present" (not late)
  - late_minutes: 0

#### Test 15: No Shift Assigned
- User has no shift assignment
- **Expected**:
  - Default 8-hour expectation
  - System handles gracefully

---

### **Category D: Special Days**

#### Test 16: Weekend Day
- User tries to work on Saturday/Sunday
- **Expected**:
  - Status: "Weekend"
  - is_weekend: True
  - Normal tracking disabled

#### Test 17: Holiday
- Date is marked as holiday
- **Expected**:
  - Status: "Holiday"
  - is_holiday: True
  - holiday_name: populated

#### Test 18: Approved Leave
- User has approved leave request
- **Expected**:
  - Status: "On Leave"
  - leave_type: populated from request
  - No session tracking required

#### Test 19: Half Day
- User marked for half day
- **Expected**:
  - is_half_day: True
  - expected_hours: shift_duration / 2

---

### **Category E: Absence Scenarios**

#### Test 20: No Clock In
- User never logs in for the day
- End of day reached
- **Expected**:
  - Status: "Absent"
  - clock_in_time: NULL
  - clock_out_time: NULL
  - regularization_reason: auto-generated

#### Test 21: Clock In But No Clock Out
- User logs in but never logs out
- **Expected**:
  - clock_in_time: populated
  - clock_out_time: NULL
  - total_hours: not calculated
  - Status: handles incomplete day

---

### **Category F: Data Population Fixes**

#### Test 22: Verify Location Field Fix
- Session has location_type
- **Expected**:
  - attendance.location = session.location_type
  - NOT always "Office"

#### Test 23: Verify Shift Duration Fix
- Shift has custom duration (e.g., 9 hours)
- User works 10 hours
- **Expected**:
  - overtime_hours: 1.0
  - Uses shift.shift_duration, not hardcoded 8

#### Test 24: Verify IP Population
- **Expected**: attendance.ip_address populated

#### Test 25: Verify Device Info Population
- **Expected**: attendance.device_info has JSON data

#### Test 26: Verify Idle Time Calculation
- Session has idle_time or total_idle_time
- **Expected**: attendance.idle_time = sum of session idle times

#### Test 27: Verify Late Minutes Before Status
- User arrives late
- **Expected**:
  - late_minutes calculated
  - Status = "Present & Late"
  - Values consistent

#### Test 28: Verify Expected Hours Dynamic
- User has 10-hour shift
- **Expected**:
  - expected_hours: 10.0 (not hardcoded 8.0)

---

### **Category G: Regularization Workflow**

#### Test 29: Submit Regularization Request
- User submits request to change status
- **Expected**:
  - regularization_status: "Pending"
  - regularization_requested_by: user
  - regularization_requested_at: timestamp
  - regularization_requested_status: requested value
  - is_hr_notified: True (after email)

#### Test 30: Approve Regularization
- HR approves request
- **Expected**:
  - regularization_status: "Approved"
  - status: changed to requested_status
  - regularization_processed_by: HR user
  - regularization_processed_at: timestamp
  - regularization_remarks: populated
  - is_employee_notified: True

#### Test 31: Reject Regularization
- HR rejects request
- **Expected**:
  - regularization_status: "Rejected"
  - status: unchanged
  - Fields populated with rejection data

---

### **Category H: Edge Cases**

#### Test 32: Session Before Auto-Creation
- User logs in
- Attendance auto-creation runs
- **Expected**:
  - Attendance created with "Present" status
  - NOT "Not Marked"
  - clock_in_time from session

#### Test 33: Weekend/Holiday Flag Preservation
- Record marked as weekend
- Session update occurs
- **Expected**:
  - is_weekend: remains True
  - Flags not overwritten

#### Test 34: Original Timestamp Tracking
- Attendance created with times
- Times modified later
- **Expected**:
  - original_clock_in_time: saved
  - original_clock_out_time: saved
  - Audit trail complete

#### Test 35: Multiple Users Same Shift
- 5 users on same shift
- All work different hours
- **Expected**:
  - Each attendance independent
  - Correct calculations per user

---

## 🏗️ TEST IMPLEMENTATION STRUCTURE

### Test Data Factories

```python
# factories.py
class TestUserFactory:
    - Create test users with profiles
    - Assign to departments
    - Set permissions

class TestShiftFactory:
    - Create day shifts
    - Create night shifts
    - Create custom shifts

class TestShiftAssignmentFactory:
    - Assign shifts to users
    - Set effective dates

class TestSessionFactory:
    - Create sessions with all fields
    - Set location, device, IP
    - Set idle time

class TestAttendanceFactory:
    - Create attendance records
    - Set various statuses
```

---

## 📊 TEST EXECUTION PLAN

### Phase 1: Setup
1. Create test database
2. Run migrations
3. Create test users (10 users)
4. Create test shifts (3 shifts: day, night, custom)
5. Assign shifts to users

### Phase 2: Session Creation
1. Generate sessions for each scenario
2. Set appropriate timestamps
3. Populate location, device, IP data
4. Set idle times

### Phase 3: Attendance Processing
1. Run auto-marking service
2. Process session updates
3. Calculate metrics

### Phase 4: Verification
1. Query attendance records
2. Verify all fields populated
3. Check calculations correct
4. Validate status logic

### Phase 5: Reporting
1. Generate test report
2. Show pass/fail for each test
3. List any failures with details
4. Provide summary statistics

---

## 🎯 SUCCESS CRITERIA

Each test must verify:
- ✅ Correct status assigned
- ✅ Clock times populated
- ✅ Hours calculated accurately
- ✅ Overtime calculated if applicable
- ✅ Late minutes calculated if late
- ✅ Location from session (not default)
- ✅ IP address populated
- ✅ Device info populated
- ✅ Idle time tracked
- ✅ Session references set
- ✅ Flags set appropriately
- ✅ No NULL values where expected

---

## 📁 TEST FILE STRUCTURE

```
trueAlign/tests/
├── __init__.py
├── test_attendance.py        # Main attendance tests
├── test_sessions.py          # Session creation tests
├── test_shifts.py            # Shift logic tests
├── test_integration.py       # End-to-end tests
├── test_fixes.py             # Tests for applied fixes
├── factories.py              # Test data factories
├── utils.py                  # Test utilities
└── fixtures/
    ├── users.json
    ├── shifts.json
    └── sample_data.json
```

---

## 🚀 TEST EXECUTION

### Manual Run
```bash
# Run all tests
python manage.py test trueAlign.tests

# Run specific test file
python manage.py test trueAlign.tests.test_attendance

# Run with verbose output
python manage.py test trueAlign.tests --verbosity=2

# Run specific test case
python manage.py test trueAlign.tests.test_attendance.AttendanceTestCase.test_late_arrival
```

### Automated Script
```bash
# Run comprehensive test suite
python test_attendance_system.py --full

# Run quick smoke tests
python test_attendance_system.py --quick

# Generate HTML report
python test_attendance_system.py --report
```

---

## 📈 EXPECTED OUTCOMES

### All Tests Pass
- ✅ 35+ test scenarios executed
- ✅ All fixes verified working
- ✅ Data population confirmed
- ✅ Calculations accurate
- ✅ Edge cases handled

### Generates Report
- Total tests: 35+
- Passed: X
- Failed: Y
- Execution time
- Detailed logs
- Failed test details

---

## 🎯 NEXT STEPS

1. **Review & Approve Plan** ✓
2. **Create Test Factories** (factories.py)
3. **Implement Test Cases** (test_*.py files)
4. **Create Test Runner** (test_attendance_system.py)
5. **Execute Tests** (run automated)
6. **Generate Report** (HTML/PDF output)
7. **Fix Any Issues** (if tests fail)
8. **Document Results** (final report)

---

**Status**: Plan Complete - Ready for Implementation
**Estimated Implementation Time**: 3-4 hours
**Estimated Test Execution Time**: 5-10 minutes (all scenarios)
