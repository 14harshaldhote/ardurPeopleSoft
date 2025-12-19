# attendance/tests/factories.py
"""
Test Data Factories

Factory classes for creating test data using factory_boy.
"""

import factory
from factory.django import DjangoModelFactory
from datetime import date, datetime, timedelta
from django.contrib.auth import get_user_model
from decimal import Decimal

from trueAlign.models import Attendance

User = get_user_model()

# Counter for unique dates
_date_counter = 0


def get_unique_date():
    """Generate unique dates to avoid constraint violations"""
    global _date_counter
    _date_counter += 1
    return date.today() - timedelta(days=_date_counter)


class UserFactory(DjangoModelFactory):
    """Factory for creating test users"""

    class Meta:
        model = User
        django_get_or_create = ("username",)

    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@test.com")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    is_active = True
    is_staff = False


class AttendanceFactory(DjangoModelFactory):
    """Factory for creating test attendance records"""

    class Meta:
        model = Attendance
        django_get_or_create = ("user", "date")  # Prevent duplicates

    user = factory.SubFactory(UserFactory)
    date = factory.Sequence(lambda n: date.today() - timedelta(days=n + 1))  # Unique dates
    status = "Present"
    clock_in_time = factory.LazyFunction(lambda: datetime.now().replace(hour=9, minute=0))
    clock_out_time = factory.LazyFunction(lambda: datetime.now().replace(hour=18, minute=0))
    total_hours = Decimal("9.0")
    is_weekend = False
    is_holiday = False


class PresentAttendanceFactory(AttendanceFactory):
    """Factory for Present attendance"""

    status = "Present"


class AbsentAttendanceFactory(AttendanceFactory):
    """Factory for Absent attendance"""

    status = "Absent"
    clock_in_time = None
    clock_out_time = None
    total_hours = Decimal("0.0")


class LateAttendanceFactory(AttendanceFactory):
    """Factory for Late attendance"""

    status = "Present & Late"
    clock_in_time = factory.LazyFunction(lambda: datetime.now().replace(hour=10, minute=30))


class WeekendAttendanceFactory(AttendanceFactory):
    """Factory for Weekend attendance"""

    status = "Weekend"
    is_weekend = True
    clock_in_time = None
    clock_out_time = None
    total_hours = Decimal("0.0")


def create_attendance_batch(user, start_date, end_date, status="Present"):
    """Create attendance records for a date range"""
    attendances = []
    current_date = start_date

    while current_date <= end_date:
        # Use get_or_create pattern to avoid duplicates
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=current_date,
            defaults={
                "status": status,
                "clock_in_time": datetime.now().replace(hour=9, minute=0),
                "clock_out_time": datetime.now().replace(hour=18, minute=0),
                "total_hours": Decimal("9.0"),
            },
        )
        attendances.append(attendance)
        current_date += timedelta(days=1)

    return attendances
