# attendance/cron/__init__.py
"""
Django Cron Jobs for Attendance System

This package contains all the cron job classes for automated attendance management:
- Daily attendance record creation
- Automatic attendance marking based on sessions
- Attendance notifications and reminders
- Data cleanup and maintenance
"""

from .attendance_cron_jobs import (
    DailyAttendanceCreationCronJob,
    AttendanceAutoMarkingCronJob,
    AttendanceNotificationCronJob,
    AttendanceCleanupCronJob,
)

__all__ = [
    'DailyAttendanceCreationCronJob',
    'AttendanceAutoMarkingCronJob',
    'AttendanceNotificationCronJob',
    'AttendanceCleanupCronJob',
]
