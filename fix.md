Primary Issues:
1. Field Name Mismatch
* Your JavaScript is looking for total_users but your backend is sending total_employees
* This causes the user count to not display properly in the location cards
2. Status Filtering Problems
* "Present & Late" status is not being handled correctly in your backend
* The JavaScript assumes this status exists but your backend might not be filtering for it properly
* Your debug logs show "Present & Late" count of 2, but when clicked, it shows "No records found"
3. Null Value Display Issues
* Many fields are showing as "null" instead of proper names
* This suggests your database joins or field selections are not working correctly
* User names, locations, and shift details are not being populated properly
4. Backend Query Logic
* Your location filtering in the get_status_users view might not be working correctly
* The view might not be properly joining user details with attendance records
* Status detection logic seems inconsistent between the analytics view and the detail view
5. Data Structure Inconsistencies
* The data structure returned by get_status_users doesn't match what the JavaScript expects
* Field names like name, work_location, shift_name might not be the actual field names in your response
Root Causes:
Backend Issues:
* Your get_status_users view is probably not properly joining tables
* Status filtering logic is incomplete or incorrect
* Field selection in queries is missing proper field names or relationships
Frontend Issues:
* JavaScript is hardcoded to expect specific field names that don't match backend response
* Status name parsing logic is too simplistic for compound statuses like "Present & Late"
Data Flow Problems:
* The analytics view calculates stats correctly (you see counts)
* But the detail view (get_status_users) uses different logic and fails to return matching records
* This creates a disconnect where summary shows data but details show empty
What You Need to Fix:
1. Fix the get_status_users view to properly handle all status types, especially "Present & Late"
2. Ensure proper database joins so user names and details are populated
3. Standardize field names between backend response and frontend expectations
4. Add proper null handling for missing data
5. Debug the query logic to ensure location filtering works correctly



---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

[DEBUG] Query Params: time_period=today, view_type=daily, custom_start=None, custom_end=None, location=None, user_id=None, drill_down=None, status_filter=None, global_search=
[DEBUG] Date filters: start_date=2025-05-22, end_date=2025-05-22
[DEBUG] Base attendance query count: 6
[DEBUG] Loaded user_details_dict with 6 users
[DEBUG] Loaded active_shifts: [1]
[DEBUG] Default shift: Day Shift (09:00 - 17:30)
[DEBUG] Using trunc_function for view_type 'daily': <class 'django.db.models.functions.datetime.TruncDay'>
[DEBUG] attendance_stats: [{'period': datetime.date(2025, 5, 22), 'total': 6, 'present_count': 4, 'present_late_count': 2, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'weekend_count': 0, 'holiday_count': 0, 'comp_off_count': 0, 'not_marked_count': 0, 'avg_hours': Decimal('4.171667'), 'avg_late_minutes': 299.3333}]
[DEBUG] status_counts: [{'status': 'Present', 'count': 4}, {'status': 'Present & Late', 'count': 2}]
[DEBUG] working_days_count (excluding weekends/holidays): 6
[DEBUG] present_count: 6
[DEBUG] overall_stats: {'total_records': 6, 'present_percentage': 100.0, 'absent_percentage': 0.0, 'leave_percentage': 0.0, 'avg_working_hours': Decimal('4.171667'), 'total_late_instances': 2, 'avg_late_minutes': 299.3333, 'status_counts': [{'status': 'Present', 'count': 4}, {'status': 'Present & Late', 'count': 2}]}
[DEBUG] active_sessions: []
[DEBUG] top_absent_users: []
[DEBUG] top_late_users: [{'user_id': 3, 'user__username': 'managerSupport', 'user__first_name': '', 'user__last_name': '', 'late_count': 1, 'avg_late_minutes': 64.0}, {'user_id': 6, 'user__username': 'ATS0012', 'user__first_name': 'Wikas', 'user__last_name': 'Raut', 'late_count': 1, 'avg_late_minutes': 90.0}]
[DEBUG] leave_distribution: []
[DEBUG] Processing locations: ['Betul', 'Unspecified']
[DEBUG] Location 'Betul': user_ids=[6]
[DEBUG] Location 'Betul': attendance count=1
[DEBUG] Location 'Betul': present=1, absent=0, leave=0, wfh=0
[DEBUG] Location 'Betul': active_users=1, users_with_attendance=1, yet_to_clock_in=0
[DEBUG] Location 'Betul': working_users=1, present_percentage=100.0
[DEBUG] Location 'Unspecified': user_ids=[1, 2, 3, 4, 5]
[DEBUG] Location 'Unspecified': attendance count=5
[DEBUG] Location 'Unspecified': present=5, absent=0, leave=0, wfh=0
[DEBUG] Location 'Unspecified': active_users=5, users_with_attendance=5, yet_to_clock_in=0
[DEBUG] Location 'Unspecified': working_users=5, present_percentage=100.0
[DEBUG] Final location_stats: [{'location': 'Unspecified', 'total_employees': 5, 'present_count': 5, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}, {'location': 'Betul', 'total_employees': 1, 'present_count': 1, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}]
[DEBUG] location_stats: [{'location': 'Unspecified', 'total_employees': 5, 'present_count': 5, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}, {'location': 'Betul', 'total_employees': 1, 'present_count': 1, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}]
[DEBUG] today: 2025-05-22, week_start: 2025-05-19, prev_week_start: 2025-05-12
[DEBUG] this_week_data: [{'status': 'Present', 'count': 7}, {'status': 'Present & Late', 'count': 5}]
[DEBUG] prev_week_data: []
[DEBUG] Calculating yet to clock in users for end_date=2025-05-22, location=None, global_search=
[DEBUG] Current date: 2025-05-22, Current time: 2025-05-22 17:04:46.651598+05:30
[DEBUG] Initial user_qs count: 6
[DEBUG] Clocked in users for 2025-05-22: [1, 2, 3, 4, 5, 6]
[DEBUG] Excluded users (leave/holiday/weekend/absent) for 2025-05-22: []
[DEBUG] All marked users for 2025-05-22: [1, 2, 3, 4, 5, 6]
[DEBUG] Unmarked users count: 0
[DEBUG] Total yet_to_clock_in_users: 0
[DEBUG] Final context: {'time_period': 'today', 'view_type': 'daily', 'start_date': datetime.date(2025, 5, 22), 'end_date': datetime.date(2025, 5, 22), 'overall_stats': {'total_records': 6, 'present_percentage': 100.0, 'absent_percentage': 0.0, 'leave_percentage': 0.0, 'avg_working_hours': Decimal('4.171667'), 'total_late_instances': 2, 'avg_late_minutes': 299.3333, 'status_counts': [{'status': 'Present', 'count': 4}, {'status': 'Present & Late', 'count': 2}]}, 'attendance_stats': [{'period': datetime.date(2025, 5, 22), 'total': 6, 'present_count': 4, 'present_late_count': 2, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'weekend_count': 0, 'holiday_count': 0, 'comp_off_count': 0, 'not_marked_count': 0, 'avg_hours': Decimal('4.171667'), 'avg_late_minutes': 299.3333}], 'active_sessions': [], 'top_absent_users': [], 'top_late_users': [{'user_id': 3, 'user__username': 'managerSupport', 'user__first_name': '', 'user__last_name': '', 'late_count': 1, 'avg_late_minutes': 64.0}, {'user_id': 6, 'user__username': 'ATS0012', 'user__first_name': 'Wikas', 'user__last_name': 'Raut', 'late_count': 1, 'avg_late_minutes': 90.0}], 'leave_distribution': [], 'location_stats': [{'location': 'Unspecified', 'total_employees': 5, 'present_count': 5, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}, {'location': 'Betul', 'total_employees': 1, 'present_count': 1, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}], 'this_week_data': [{'status': 'Present', 'count': 7}, {'status': 'Present & Late', 'count': 5}], 'prev_week_data': [], 'yet_to_clock_in_users': [], 'global_search': ''}
[DEBUG] Rendering attendance_analytics.html with context
HTTP GET /attendance/analytics/ 200 [0.18, 127.0.0.1:50306]