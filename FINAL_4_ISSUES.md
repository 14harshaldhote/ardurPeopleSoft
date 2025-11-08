# 🎯 FINAL 4 ISSUES TO FIX

**Progress**: 14/18 tests passing (77.8% → Target: 100%)

---

## ✅ FIXED (2 tests)
- ✅ test_01 - NOW PASSING (time calculation fixed)
- ✅ test_22 - NOW PASSING (location capitalization fixed)

---

## ❌ REMAINING ISSUES (4)

### **ISSUE #1: test_02 - Late detection**
**Error**: `'Present' != 'Present & Late'`
**Root Cause**: Late session factory not creating actual late time
**Fix Needed**: Check `create_late_session()` logic

---

### **ISSUE #2: test_06 - Timezone still wrong**
**Error**: `clock_in_ist.hour is 8 != 9`
**Root Cause**: Session created at wrong hour or timezone conversion issue
**Fix Needed**: Debug session creation time

---

### **ISSUE #3: test_32 - Session not detected**
**Error**: `'Not Marked' != 'Present'`
**Root Cause**: `_get_attendance_defaults` not finding session
**Fix Needed**: Check session date matching logic

---

### **ISSUE #4: Integration test - Missing method**
**Error**: `AttributeError: 'AttendanceAutoMarkingService' object has no attribute 'mark_attendance_for_date'`
**Root Cause**: Method doesn't exist in service
**Fix Needed**: Use correct method name or create wrapper
