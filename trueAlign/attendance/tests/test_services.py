# attendance/tests/test_services.py
"""
Service Layer Unit Tests

Tests for all attendance service classes.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from datetime import date, timedelta
from decimal import Decimal

from ..services.analytics import AttendanceAnalyticsService
from ..services.reports import AttendanceReportService
from ..services.regularization import AttendanceRegularizationService
from ..utils import get_date_range
from .factories import UserFactory, AttendanceFactory, create_attendance_batch

User = get_user_model()


class AttendanceAnalyticsServiceTest(TestCase):
    """Tests for AttendanceAnalyticsService"""

    def setUp(self):
        self.service = AttendanceAnalyticsService()
        self.user = UserFactory()

        # Create test data: 20 present, 5 absent, 5 late
        for i in range(20):
            AttendanceFactory(user=self.user, status="Present")
        for i in range(5):
            AttendanceFactory(
                user=self.user, status="Absent", clock_in_time=None, clock_out_time=None
            )
        for i in range(5):
            AttendanceFactory(user=self.user, status="Present & Late")

    def test_get_attendance_trends(self):
        """Test attendance trend calculation"""
        start_date, end_date = get_date_range("last_30_days")
        result = self.service.get_attendance_trends(start_date, end_date)

        self.assertTrue(result.success)
        # Service returns list of daily stats or dict with trends
        self.assertTrue(
            isinstance(result.data, list) or "trends" in result.data,
            f"Expected list or dict with 'trends', got: {type(result.data)}",
        )

    def test_get_status_analytics(self):
        """Test status analytics calculation"""
        # Method takes optional target_date, not start/end
        result = self.service.get_status_analytics()

        self.assertTrue(result.success)
        # Verify response contains expected data
        self.assertIsNotNone(result.data)

    def test_get_late_arrival_analysis(self):
        """Test late arrival pattern analysis"""
        start_date, end_date = get_date_range("last_30_days")
        result = self.service.get_late_arrival_analysis(start_date, end_date)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.data)


class AttendanceReportServiceTest(TestCase):
    """Tests for AttendanceReportService"""

    def setUp(self):
        self.service = AttendanceReportService()
        self.user = UserFactory()

        # Create 30 days of attendance
        start_date = date.today() - timedelta(days=30)
        end_date = date.today()
        create_attendance_batch(self.user, start_date, end_date)

    def test_generate_user_summary(self):
        """Test user attendance summary generation"""
        start_date, end_date = get_date_range("last_30_days")
        result = self.service.generate_user_summary(self.user, start_date, end_date)

        self.assertTrue(result.success)
        summary = result.data

        # Check actual fields returned by service
        self.assertIn("total_days", summary)
        self.assertIn("present_days", summary)
        self.assertIn("absent_days", summary)
        self.assertGreater(summary["total_days"], 0)

    def test_generate_monthly_report(self):
        """Test monthly report generation"""
        result = self.service.generate_monthly_report(
            year=date.today().year, month=date.today().month
        )

        self.assertTrue(result.success)
        # Service returns 'daily_stats' not 'records'
        self.assertIn("daily_stats", result.data)
        self.assertIn("summary", result.data)


class AttendanceRegularizationServiceTest(TestCase):
    """Tests for AttendanceRegularizationService"""

    def setUp(self):
        self.service = AttendanceRegularizationService()
        self.user = UserFactory()
        self.hr_user = UserFactory(is_staff=True)
        self.attendance = AttendanceFactory(user=self.user, status="Absent")

    def test_submit_regularization_request(self):
        """Test submitting a regularization request"""
        result = self.service.submit_regularization_request(
            attendance=self.attendance,
            requested_status="Present",
            reason="Forgot to mark attendance",
            requested_by=self.user,
        )

        self.assertTrue(result.success)
        self.attendance.refresh_from_db()
        self.assertEqual(self.attendance.regularization_status, "Pending")
        self.assertEqual(self.attendance.regularization_requested_status, "Present")

    def test_approve_regularization_request(self):
        """Test approving a regularization request"""
        # First submit
        self.service.submit_regularization_request(
            self.attendance, "Present", "Valid reason", self.user
        )

        # Then approve
        result = self.service.process_regularization_request(
            attendance=self.attendance,
            action="approve",
            processed_by=self.hr_user,
            remarks="Approved",
        )

        self.assertTrue(result.success)
        self.attendance.refresh_from_db()
        self.assertEqual(self.attendance.regularization_status, "Approved")
        self.assertEqual(self.attendance.status, "Present")

    def test_reject_regularization_request(self):
        """Test rejecting a regularization request"""
        # Submit
        self.service.submit_regularization_request(
            self.attendance, "Present", "Invalid reason", self.user
        )

        # Reject
        result = self.service.process_regularization_request(
            attendance=self.attendance,
            action="reject",
            processed_by=self.hr_user,
            remarks="Not a valid reason",
        )

        self.assertTrue(result.success)
        self.attendance.refresh_from_db()
        self.assertEqual(self.attendance.regularization_status, "Rejected")
        self.assertEqual(self.attendance.status, "Absent")  # Unchanged
