import csv
import json
from datetime import datetime, timedelta, time
from decimal import Decimal
from typing import Dict, List, Optional, Tuple, Any
from django.db.models import Q, Count, Sum, Avg, F, Case, When
from django.utils import timezone
from django.http import HttpResponse
from django.core.mail import send_mail
from django.conf import settings
from pytz import timezone as pytz_timezone
import pytz
import logging

logger = logging.getLogger(__name__)

# Define IST timezone
IST = pytz_timezone('Asia/Kolkata')


class BookingReportGenerator:
    """
    Generate various reports for conference room bookings.
    """

    @staticmethod
    def generate_daily_report(date=None):
        """Generate daily booking report."""
        from trueAlign.models import ConferenceBooking, Room

        if not date:
            date = timezone.now().date()

        # Get all bookings for the day
        daily_bookings = ConferenceBooking.objects.filter(
            start_time__date=date,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        ).select_related('room', 'booked_by').order_by('start_time')

        # Group by room
        room_bookings = {}
        total_hours = 0

        for booking in daily_bookings:
            room_name = booking.room.name
            if room_name not in room_bookings:
                room_bookings[room_name] = []

            room_bookings[room_name].append({
                'time': f"{booking.start_time.astimezone(IST).strftime('%I:%M %p')} - {booking.end_time.astimezone(IST).strftime('%I:%M %p')}",
                'purpose': booking.purpose,
                'booked_by': booking.booked_by.get_full_name(),
                'attendees': booking.attendees_count,
                'duration': booking.duration_hours
            })
            total_hours += booking.duration_hours

        # Calculate utilization
        active_rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        room_utilization = []

        for room in active_rooms:
            room_hours = sum([
                booking.duration_hours for booking in daily_bookings
                if booking.room == room
            ])
            utilization_percent = (room_hours / 9) * 100  # 9 working hours per day

            room_utilization.append({
                'room': room.name,
                'hours_booked': room_hours,
                'utilization_percent': round(utilization_percent, 1),
                'bookings_count': daily_bookings.filter(room=room).count()
            })

        return {
            'date': date,
            'total_bookings': daily_bookings.count(),
            'total_hours': round(total_hours, 2),
            'room_bookings': room_bookings,
            'room_utilization': room_utilization,
            'average_utilization': round(
                sum([r['utilization_percent'] for r in room_utilization]) / len(room_utilization), 1
            ) if room_utilization else 0
        }

    @staticmethod
    def generate_weekly_report(start_date=None):
        """Generate weekly booking report."""
        from trueAlign.models import ConferenceBooking, Room

        if not start_date:
            start_date = timezone.now().date() - timedelta(days=timezone.now().weekday())

        end_date = start_date + timedelta(days=6)

        # Get all bookings for the week
        weekly_bookings = ConferenceBooking.objects.filter(
            start_time__date__range=[start_date, end_date],
            status=ConferenceBooking.BookingStatus.CONFIRMED
        ).select_related('room', 'booked_by')

        # Daily breakdown
        daily_stats = []
        for i in range(7):
            day = start_date + timedelta(days=i)
            day_bookings = weekly_bookings.filter(start_time__date=day)

            daily_stats.append({
                'date': day,
                'day_name': day.strftime('%A'),
                'bookings_count': day_bookings.count(),
                'total_hours': sum([b.duration_hours for b in day_bookings]),
                'unique_users': day_bookings.values('booked_by').distinct().count()
            })

        # Room-wise breakdown
        rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        room_stats = []

        for room in rooms:
            room_bookings = weekly_bookings.filter(room=room)
            total_hours = sum([b.duration_hours for b in room_bookings])

            room_stats.append({
                'room': room.name,
                'bookings_count': room_bookings.count(),
                'total_hours': round(total_hours, 2),
                'average_duration': round(total_hours / room_bookings.count(), 2) if room_bookings.count() > 0 else 0,
                'utilization_percent': round((total_hours / (7 * 9)) * 100, 1)  # 7 days * 9 hours
            })

        # Top users
        top_users = weekly_bookings.values('booked_by__first_name', 'booked_by__last_name')\
            .annotate(
                booking_count=Count('id'),
                total_hours=Sum(F('end_time') - F('start_time'))
            )\
            .order_by('-booking_count')[:5]

        return {
            'start_date': start_date,
            'end_date': end_date,
            'total_bookings': weekly_bookings.count(),
            'total_hours': round(sum([b.duration_hours for b in weekly_bookings]), 2),
            'daily_stats': daily_stats,
            'room_stats': room_stats,
            'top_users': top_users,
            'peak_day': max(daily_stats, key=lambda x: x['bookings_count']) if daily_stats else None
        }

    @staticmethod
    def generate_monthly_report(year=None, month=None):
        """Generate monthly booking report."""
        from trueAlign.models import ConferenceBooking, Room

        if not year:
            year = timezone.now().year
        if not month:
            month = timezone.now().month

        # Get all bookings for the month
        monthly_bookings = ConferenceBooking.objects.filter(
            start_time__year=year,
            start_time__month=month,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        ).select_related('room', 'booked_by')

        # Working days in month (excluding weekends)
        start_date = datetime(year, month, 1).date()
        if month == 12:
            end_date = datetime(year + 1, 1, 1).date() - timedelta(days=1)
        else:
            end_date = datetime(year, month + 1, 1).date() - timedelta(days=1)

        working_days = 0
        current_date = start_date
        while current_date <= end_date:
            if current_date.weekday() < 5:  # Monday = 0, Friday = 4
                working_days += 1
            current_date += timedelta(days=1)

        # Calculate metrics
        total_hours = sum([b.duration_hours for b in monthly_bookings])
        active_rooms_count = Room.objects.filter(status=Room.RoomStatus.ACTIVE).count()
        total_available_hours = working_days * 9 * active_rooms_count  # 9 hours per room per day

        # Meeting types breakdown
        meeting_types = monthly_bookings.values('meeting_type')\
            .annotate(count=Count('id'))\
            .order_by('-count')

        # Cancellation analysis
        cancelled_bookings = ConferenceBooking.objects.filter(
            start_time__year=year,
            start_time__month=month,
            status=ConferenceBooking.BookingStatus.CANCELLED
        )

        return {
            'year': year,
            'month': month,
            'month_name': datetime(year, month, 1).strftime('%B'),
            'working_days': working_days,
            'total_bookings': monthly_bookings.count(),
            'total_hours': round(total_hours, 2),
            'total_available_hours': total_available_hours,
            'overall_utilization': round((total_hours / total_available_hours) * 100, 1) if total_available_hours > 0 else 0,
            'average_booking_duration': round(total_hours / monthly_bookings.count(), 2) if monthly_bookings.count() > 0 else 0,
            'meeting_types': list(meeting_types),
            'cancelled_bookings': cancelled_bookings.count(),
            'cancellation_rate': round((cancelled_bookings.count() / (monthly_bookings.count() + cancelled_bookings.count())) * 100, 1) if (monthly_bookings.count() + cancelled_bookings.count()) > 0 else 0
        }


class BookingExporter:
    """
    Export booking data in various formats.
    """

    @staticmethod
    def export_to_csv(bookings, filename=None):
        """Export bookings to CSV format."""
        if not filename:
            filename = f"bookings_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)

        # Write header
        writer.writerow([
            'ID', 'Room', 'Purpose', 'Booked By', 'Start Time', 'End Time',
            'Duration (hours)', 'Attendees', 'Meeting Type', 'Priority',
            'Status', 'Created At', 'Checked In', 'No Show'
        ])

        # Write data
        for booking in bookings:
            writer.writerow([
                booking.id,
                booking.room.name,
                booking.purpose,
                booking.booked_by.get_full_name(),
                booking.start_time.astimezone(IST).strftime('%Y-%m-%d %H:%M'),
                booking.end_time.astimezone(IST).strftime('%Y-%m-%d %H:%M'),
                booking.duration_hours,
                booking.attendees_count,
                booking.get_meeting_type_display(),
                booking.get_priority_display(),
                booking.get_status_display(),
                booking.created_at.astimezone(IST).strftime('%Y-%m-%d %H:%M'),
                'Yes' if booking.checked_in else 'No',
                'Yes' if booking.no_show else 'No'
            ])

        return response

    @staticmethod
    def export_utilization_report_csv(start_date, end_date):
        """Export room utilization report to CSV."""
        from trueAlign.models import Room, ConferenceBooking

        filename = f"utilization_report_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.csv"
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)

        # Write header
        writer.writerow([
            'Room Name', 'Room Type', 'Capacity', 'Total Bookings',
            'Total Hours Booked', 'Available Hours', 'Utilization %',
            'Average Booking Duration', 'Peak Day'
        ])

        rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        working_days = sum(1 for d in range((end_date - start_date).days + 1)
                          if (start_date + timedelta(days=d)).weekday() < 5)

        for room in rooms:
            bookings = ConferenceBooking.objects.filter(
                room=room,
                start_time__date__range=[start_date, end_date],
                status=ConferenceBooking.BookingStatus.CONFIRMED
            )

            total_hours = sum([b.duration_hours for b in bookings])
            available_hours = working_days * 9  # 9 hours per working day
            utilization = (total_hours / available_hours) * 100 if available_hours > 0 else 0

            # Find peak day
            daily_bookings = bookings.extra(
                select={'day': 'DATE(start_time)'}
            ).values('day').annotate(
                day_hours=Sum(F('end_time') - F('start_time'))
            ).order_by('-day_hours')

            peak_day = daily_bookings.first() if daily_bookings else None
            peak_day = peak_day['day'] if peak_day else 'N/A'

            writer.writerow([
                room.name,
                getattr(room, 'get_room_type_display', lambda: room.room_type)(),
                room.capacity,
                bookings.count(),
                round(total_hours, 2),
                available_hours,
                round(utilization, 1),
                round(total_hours / bookings.count(), 2) if bookings.count() > 0 else 0,
                peak_day
            ])

        return response


class BookingNotificationManager:
    """
    Manage booking notifications and reminders.
    """

    @staticmethod
    def send_booking_confirmation(booking):
        """Send booking confirmation email."""
        subject = f"Booking Confirmed: {booking.room.name}"

        message = f"""
Dear {booking.booked_by.get_full_name()},

Your booking has been confirmed!

Details:
- Room: {booking.room.name}
- Purpose: {booking.purpose}
- Date: {booking.start_time.astimezone(IST).strftime('%B %d, %Y')}
- Time: {booking.start_time.astimezone(IST).strftime('%I:%M %p')} - {booking.end_time.astimezone(IST).strftime('%I:%M %p')}
- Duration: {booking.duration_hours} hours
- Attendees: {booking.attendees_count}

Room Facilities:
{booking.room.facilities}

Please arrive on time and don't forget to check in when you arrive.

Best regards,
Conference Room Management System
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[booking.booked_by.email],
                fail_silently=False
            )
            logger.info(f"Confirmation email sent for booking {booking.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send confirmation email for booking {booking.id}: {e}")
            return False

    @staticmethod
    def send_booking_reminder(booking, minutes_before=15):
        """Send booking reminder email."""
        subject = f"Reminder: {booking.room.name} booking in {minutes_before} minutes"

        message = f"""
Dear {booking.booked_by.get_full_name()},

This is a reminder that your meeting is starting soon!

Details:
- Room: {booking.room.name}
- Purpose: {booking.purpose}
- Start Time: {booking.start_time.astimezone(IST).strftime('%I:%M %p')}
- Location: {booking.room.location}

Please make your way to the room and check in when you arrive.

Best regards,
Conference Room Management System
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[booking.booked_by.email],
                fail_silently=False
            )
            logger.info(f"Reminder email sent for booking {booking.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send reminder email for booking {booking.id}: {e}")
            return False

    @staticmethod
    def send_cancellation_notice(booking):
        """Send cancellation notice email."""
        subject = f"Booking Cancelled: {booking.room.name}"

        message = f"""
Dear {booking.booked_by.get_full_name()},

Your booking has been cancelled.

Original booking details:
- Room: {booking.room.name}
- Purpose: {booking.purpose}
- Date: {booking.start_time.astimezone(IST).strftime('%B %d, %Y')}
- Time: {booking.start_time.astimezone(IST).strftime('%I:%M %p')} - {booking.end_time.astimezone(IST).strftime('%I:%M %p')}

Cancellation details:
- Cancelled at: {booking.cancelled_at.astimezone(IST).strftime('%B %d, %Y at %I:%M %p') if booking.cancelled_at else 'N/A'}
- Cancelled by: {booking.cancelled_by.get_full_name() if booking.cancelled_by else 'System'}
- Reason: {booking.cancellation_reason or 'No reason provided'}

If you need to reschedule, please make a new booking through the system.

Best regards,
Conference Room Management System
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[booking.booked_by.email],
                fail_silently=False
            )
            logger.info(f"Cancellation email sent for booking {booking.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send cancellation email for booking {booking.id}: {e}")
            return False


class BookingAnalytics:
    """
    Advanced analytics for booking patterns and insights.
    """

    @staticmethod
    def get_peak_hours_analysis(days=30):
        """Analyze peak booking hours."""
        from trueAlign.models import ConferenceBooking

        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        bookings = ConferenceBooking.objects.filter(
            start_time__range=[start_date, end_date],
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )

        # Group by hour of day
        hourly_stats = {}
        for hour in range(9, 18):  # 9 AM to 5 PM
            hourly_stats[hour] = {
                'hour': hour,
                'hour_display': f"{hour:02d}:00",
                'booking_count': 0,
                'total_duration': 0,
                'average_duration': 0
            }

        for booking in bookings:
            start_hour = booking.start_time.astimezone(IST).hour
            if 9 <= start_hour < 18:
                hourly_stats[start_hour]['booking_count'] += 1
                hourly_stats[start_hour]['total_duration'] += booking.duration_hours

        # Calculate averages
        for hour_data in hourly_stats.values():
            if hour_data['booking_count'] > 0:
                hour_data['average_duration'] = round(
                    hour_data['total_duration'] / hour_data['booking_count'], 2
                )

        return list(hourly_stats.values())

    @staticmethod
    def get_room_popularity_trends(days=30):
        """Analyze room popularity trends."""
        from trueAlign.models import ConferenceBooking, Room

        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        room_trends = []

        for room in rooms:
            bookings = ConferenceBooking.objects.filter(
                room=room,
                start_time__range=[start_date, end_date],
                status=ConferenceBooking.BookingStatus.CONFIRMED
            )

            total_bookings = bookings.count()
            total_hours = sum([b.duration_hours for b in bookings])

            # Weekly breakdown
            weekly_data = []
            for week in range(4):  # Last 4 weeks
                week_start = end_date - timedelta(days=(week + 1) * 7)
                week_end = end_date - timedelta(days=week * 7)

                week_bookings = bookings.filter(
                    start_time__range=[week_start, week_end]
                ).count()

                weekly_data.append({
                    'week': f"Week {4 - week}",
                    'bookings': week_bookings
                })

            room_trends.append({
                'room': room.name,
                'total_bookings': total_bookings,
                'total_hours': round(total_hours, 2),
                'average_booking_duration': round(total_hours / total_bookings, 2) if total_bookings > 0 else 0,
                'weekly_data': weekly_data,
                'popularity_score': total_bookings + (total_hours * 0.5)  # Weighted score
            })

        # Sort by popularity
        room_trends.sort(key=lambda x: x['popularity_score'], reverse=True)

        return room_trends

    @staticmethod
    def get_user_behavior_analysis(user, days=90):
        """Analyze individual user booking behavior."""
        from trueAlign.models import ConferenceBooking

        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        bookings = ConferenceBooking.objects.filter(
            booked_by=user,
            start_time__range=[start_date, end_date]
        ).select_related('room')

        # Basic stats
        confirmed_bookings = bookings.filter(status=ConferenceBooking.BookingStatus.CONFIRMED)
        cancelled_bookings = bookings.filter(status=ConferenceBooking.BookingStatus.CANCELLED)

        total_hours = sum([b.duration_hours for b in confirmed_bookings])

        # Preferred times
        preferred_hours = {}
        for booking in confirmed_bookings:
            hour = booking.start_time.astimezone(IST).hour
            preferred_hours[hour] = preferred_hours.get(hour, 0) + 1

        # Preferred rooms
        preferred_rooms = {}
        for booking in confirmed_bookings:
            room_name = booking.room.name
            preferred_rooms[room_name] = preferred_rooms.get(room_name, 0) + 1

        # Meeting patterns
        meeting_types = {}
        for booking in confirmed_bookings:
            meeting_type = booking.meeting_type
            meeting_types[meeting_type] = meeting_types.get(meeting_type, 0) + 1

        return {
            'total_bookings': bookings.count(),
            'confirmed_bookings': confirmed_bookings.count(),
            'cancelled_bookings': cancelled_bookings.count(),
            'cancellation_rate': round((cancelled_bookings.count() / bookings.count()) * 100, 1) if bookings.count() > 0 else 0,
            'total_hours': round(total_hours, 2),
            'average_booking_duration': round(total_hours / confirmed_bookings.count(), 2) if confirmed_bookings.count() > 0 else 0,
            'preferred_hours': sorted(preferred_hours.items(), key=lambda x: x[1], reverse=True)[:3],
            'preferred_rooms': sorted(preferred_rooms.items(), key=lambda x: x[1], reverse=True)[:3],
            'meeting_types': sorted(meeting_types.items(), key=lambda x: x[1], reverse=True),
            'bookings_per_week': round(confirmed_bookings.count() / (days / 7), 1),
            'no_shows': confirmed_bookings.filter(no_show=True).count()
        }


class BookingHelper:
    """
    Helper functions for booking operations.
    """

    @staticmethod
    def get_suggested_meeting_duration(meeting_type):
        """Get suggested duration based on meeting type."""
        duration_map = {
            'INTERNAL': 60,  # 1 hour
            'CLIENT': 90,    # 1.5 hours
            'INTERVIEW': 45, # 45 minutes
            'TRAINING': 120, # 2 hours
            'PRESENTATION': 90, # 1.5 hours
            'OTHER': 60      # 1 hour
        }
        return duration_map.get(meeting_type, 60)

    @staticmethod
    def get_recommended_room(attendees_count, meeting_type, preferred_location=None):
        """Recommend best room based on requirements."""
        from trueAlign.models import Room

        # Filter rooms by capacity (with 20% buffer)
        min_capacity = max(1, int(attendees_count * 1.2))

        rooms = Room.objects.filter(
            status=Room.RoomStatus.ACTIVE,
            capacity__gte=min_capacity
        ).order_by('capacity')  # Prefer smaller rooms when possible

        if preferred_location:
            location_rooms = rooms.filter(location__icontains=preferred_location)
            if location_rooms.exists():
                rooms = location_rooms

        # Score rooms based on meeting type
        room_scores = []
        for room in rooms:
            score = 0

            # Capacity scoring (prefer rooms close to required capacity)
            capacity_efficiency = attendees_count / room.capacity
            if 0.5 <= capacity_efficiency <= 0.8:
                score += 10
            elif 0.3 <= capacity_efficiency <= 0.9:
                score += 5

            # Type-based scoring
            if meeting_type == 'CLIENT' and room.room_type == Room.RoomType.CONFERENCE:
                score += 8
            elif meeting_type == 'INTERVIEW' and room.room_type in [Room.RoomType.MEETING, Room.RoomType.HUDDLE]:
                score += 8
            elif meeting_type == 'TRAINING' and room.room_type == Room.RoomType.CONFERENCE:
                score += 6

            # Facility scoring
            if 'video conferencing' in room.facilities.lower():
                if meeting_type in ['CLIENT', 'PRESENTATION']:
                    score += 5

            if 'projector' in room.facilities.lower() or 'tv' in room.facilities.lower():
                if meeting_type in ['PRESENTATION', 'TRAINING']:
                    score += 5

            room_scores.append((room, score))

        # Sort by score and return top recommendations
        room_scores.sort(key=lambda x: x[1], reverse=True)
        return [room for room, score in room_scores[:3]]

    @staticmethod
    def format_duration_human(duration_hours):
        """Format duration in human-readable format."""
        if duration_hours < 1:
            minutes = int(duration_hours * 60)
            return f"{minutes} minutes"
        elif duration_hours == 1:
            return "1 hour"
        elif duration_hours == int(duration_hours):
            return f"{int(duration_hours)} hours"
        else:
            hours = int(duration_hours)
            minutes = int((duration_hours - hours) * 60)
            return f"{hours} hours {minutes} minutes"

    @staticmethod
    def get_booking_conflicts(room, start_time, end_time, exclude_booking_id=None):
        """Get detailed information about booking conflicts."""
        from trueAlign.models import ConferenceBooking

        conflicts = ConferenceBooking.objects.filter(
            room=room,
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lt=end_time,
            end_time__gt=start_time
        )

        if exclude_booking_id:
            conflicts = conflicts.exclude(id=exclude_booking_id)

        conflict_details = []
        for conflict in conflicts:
            conflict_details.append({
                'id': getattr(conflict, 'id', None),
                'purpose': conflict.purpose,
                'booked_by': conflict.booked_by.get_full_name(),
                'start_time': conflict.start_time,
                'end_time': conflict.end_time,
                'duration': conflict.duration_hours,
                'attendees': conflict.attendees_count,
                'overlap_start': max(start_time, conflict.start_time),
                'overlap_end': min(end_time, conflict.end_time)
            })

        return conflict_details

    @staticmethod
    def generate_booking_summary(booking):
        """Generate a comprehensive booking summary."""
        return {
            'basic_info': {
                'id': booking.id,
                'room': booking.room.name,
                'purpose': booking.purpose,
                'description': booking.description
            },
            'schedule': {
                'start_time': booking.start_time.astimezone(IST),
                'end_time': booking.end_time.astimezone(IST),
                'duration': BookingHelper.format_duration_human(booking.duration_hours),
                'date': booking.start_time.astimezone(IST).strftime('%B %d, %Y'),
                'time_range': f"{booking.start_time.astimezone(IST).strftime('%I:%M %p')} - {booking.end_time.astimezone(IST).strftime('%I:%M %p')}"
            },
            'meeting_details': {
                'type': booking.get_meeting_type_display(),
                'priority': booking.get_priority_display(),
                'attendees_count': booking.attendees_count,
                'external_attendees': booking.external_attendees,
                'total_attendees': booking.attendees_count + booking.external_attendees
            },
            'room_info': {
                'name': booking.room.name,
                'type': booking.room.get_room_type_display(),
                'capacity': booking.room.capacity,
                'location': booking.room.location,
                'facilities': booking.room.facilities.split('\n') if booking.room.facilities else []
            },
            'status': {
                'current_status': booking.get_status_display(),
                'is_current': booking.is_current,
                'is_past': booking.is_past,
                'can_be_cancelled': booking.can_be_cancelled,
                'can_check_in': booking.can_check_in,
                'checked_in': booking.checked_in,
                'no_show': booking.no_show
            },
            'booking_info': {
                'booked_by': booking.booked_by.get_full_name(),
                'created_at': booking.created_at.astimezone(IST),
                'updated_at': booking.updated_at.astimezone(IST),
                'cost': {
                    'hourly_rate': float(booking.hourly_rate),
                    'total_cost': float(booking.total_cost)
                }
            },
            'cancellation_info': {
                'cancelled_at': booking.cancelled_at.astimezone(IST) if booking.cancelled_at else None,
                'cancelled_by': booking.cancelled_by.get_full_name() if booking.cancelled_by else None,
                'cancellation_reason': booking.cancellation_reason
            } if booking.status == booking.BookingStatus.CANCELLED else None
        }


class RoomAvailabilityChecker:
    """
    Check room availability and suggest alternatives.
    """

    @staticmethod
    def check_availability(room, start_time, end_time):
        """Check if a room is available for the given time slot."""
        from trueAlign.models import ConferenceBooking

        conflicts = ConferenceBooking.objects.filter(
            room=room,
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lt=end_time,
            end_time__gt=start_time
        )

        return {
            'available': not conflicts.exists(),
            'conflicts': conflicts,
            'conflict_count': conflicts.count()
        }

    @staticmethod
    def get_next_available_time(room, preferred_start_time, duration_minutes=60):
        """Find the next available time slot for a room."""
        from trueAlign.models import ConferenceBooking
        from datetime import timedelta

        duration = timedelta(minutes=duration_minutes)
        search_start = preferred_start_time

        # Look for next 7 days
        for day_offset in range(7):
            current_date = (preferred_start_time + timedelta(days=day_offset)).date()

            # Skip weekends
            if current_date.weekday() >= 5:
                continue

            # Working hours: 9 AM to 6 PM
            day_start = IST.localize(datetime.combine(current_date, time(9, 0)))
            day_end = IST.localize(datetime.combine(current_date, time(18, 0)))

            if day_offset == 0:
                # For today, start from preferred time or current time
                current_time = max(timezone.now(), preferred_start_time)
                search_from = max(current_time, day_start.astimezone(pytz.UTC))
            else:
                search_from = day_start.astimezone(pytz.UTC)

            # Get bookings for this day
            day_bookings = ConferenceBooking.objects.filter(
                room=room,
                start_time__date=current_date,
                status=ConferenceBooking.BookingStatus.CONFIRMED
            ).order_by('start_time')

            # Find gaps
            for booking in day_bookings:
                if booking.start_time > search_from:
                    # Check if there's enough time before this booking
                    if booking.start_time - search_from >= duration:
                        return {
                            'available_time': search_from,
                            'end_time': search_from + duration,
                            'date': current_date
                        }
                # Move search point to after this booking
                search_from = max(search_from, booking.end_time)

            # Check if there's time after the last booking
            day_end_utc = day_end.astimezone(pytz.UTC)
            if search_from + duration <= day_end_utc:
                return {
                    'available_time': search_from,
                    'end_time': search_from + duration,
                    'date': current_date
                }

        return None

    @staticmethod
    def get_alternative_rooms(preferred_room, start_time, end_time, min_capacity=1):
        """Get alternative rooms that are available for the given time slot."""
        from trueAlign.models import Room

        alternatives = []

        # Get all active rooms except the preferred one
        available_rooms = Room.objects.filter(
            status=Room.RoomStatus.ACTIVE,
            capacity__gte=min_capacity
        ).exclude(id=preferred_room.id)

        for room in available_rooms:
            availability = RoomAvailabilityChecker.check_availability(
                room, start_time, end_time
            )

            if availability['available']:
                alternatives.append({
                    'room': room,
                    'capacity_match': room.capacity >= min_capacity,
                    'facilities': room.facilities,
                    'location': room.location,
                    'recommendation_score': RoomAvailabilityChecker._calculate_room_score(
                        room, preferred_room, min_capacity
                    )
                })

        # Sort by recommendation score
        alternatives.sort(key=lambda x: x['recommendation_score'], reverse=True)
        return alternatives

    @staticmethod
    def _calculate_room_score(room, preferred_room, required_capacity):
        """Calculate a recommendation score for a room."""
        score = 0

        # Capacity scoring
        if room.capacity >= required_capacity:
            # Prefer rooms with capacity close to requirements
            efficiency = required_capacity / room.capacity
            if 0.5 <= efficiency <= 0.8:
                score += 10
            elif 0.3 <= efficiency <= 0.9:
                score += 5

        # Type similarity
        if room.room_type == preferred_room.room_type:
            score += 8

        # Location similarity (if same location)
        if room.location == preferred_room.location:
            score += 5

        # Facilities bonus
        if room.facilities:
            score += 3

        return score


class BookingValidator:
    """
    Comprehensive validation for booking operations.
    """

    @staticmethod
    def validate_booking_data(booking_data):
        """Validate all booking data before creation."""
        errors = []

        # Required fields
        required_fields = ['room', 'purpose', 'start_time', 'end_time', 'booked_by']
        for field in required_fields:
            if not booking_data.get(field):
                errors.append(f"{field.replace('_', ' ').title()} is required.")

        # Time validation
        start_time = booking_data.get('start_time')
        end_time = booking_data.get('end_time')

        if start_time and end_time:
            if start_time >= end_time:
                errors.append("End time must be after start time.")

            if start_time < timezone.now():
                errors.append("Booking cannot be in the past.")

            # Duration validation
            duration = end_time - start_time
            if duration < timedelta(minutes=15):
                errors.append("Booking duration must be at least 15 minutes.")

            if duration > timedelta(hours=8):
                errors.append("Booking duration cannot exceed 8 hours.")

        # Capacity validation
        room = booking_data.get('room')
        attendees = booking_data.get('attendees_count', 1)

        if room and attendees > room.capacity:
            errors.append(f"Number of attendees ({attendees}) exceeds room capacity ({room.capacity}).")

        return errors

    @staticmethod
    def validate_recurring_booking(booking_data, occurrences):
        """Validate recurring booking parameters."""
        errors = []

        if occurrences > 52:
            errors.append("Recurring bookings cannot exceed 52 occurrences (1 year).")

        pattern = booking_data.get('recurring_pattern', 'NONE')
        if pattern not in ['NONE', 'DAILY', 'WEEKLY', 'MONTHLY']:
            errors.append("Invalid recurring pattern.")

        return errors


class MaintenanceScheduler:
    """
    Manage room maintenance schedules and notifications.
    """

    @staticmethod
    def schedule_maintenance(room, start_time, end_time, description):
        """Schedule maintenance for a room."""
        from trueAlign.models import ConferenceBooking

        # Check for conflicting bookings
        conflicts = ConferenceBooking.objects.filter(
            room=room,
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lt=end_time,
            end_time__gt=start_time
        )

        if conflicts.exists():
            return {
                'success': False,
                'message': f"Cannot schedule maintenance. {conflicts.count()} conflicting bookings found.",
                'conflicts': conflicts
            }

        # Set room status to maintenance
        room.status = room.RoomStatus.MAINTENANCE
        room.save()

        return {
            'success': True,
            'message': f"Maintenance scheduled for {room.name}",
            'affected_bookings': conflicts.count()
        }

    @staticmethod
    def end_maintenance(room):
        """End maintenance and reactivate room."""
        room.status = room.RoomStatus.ACTIVE
        room.save()

        return {
            'success': True,
            'message': f"{room.name} is now available for booking"
        }


class LocationDetector:
    """
    Utility class for detecting user location and matching with office locations.
    """

    @staticmethod
    def get_city_from_coordinates(latitude, longitude):
        """
        Get city and state from coordinates using Nominatim API.
        Returns None if both city and state are not detected.
        """
        import requests
        import logging

        logger = logging.getLogger(__name__)

        try:
            url = "https://nominatim.openstreetmap.org/reverse"
            params = {
                'format': 'json',
                'lat': latitude,
                'lon': longitude,
                'zoom': 10,
                'addressdetails': 1
            }
            headers = {
                'User-Agent': 'ArdurPeopleSoft-ConferenceBooking/1.0'
            }

            response = requests.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                address = data.get('address', {})

                # Try to get city from different possible fields
                city = (address.get('city') or
                       address.get('town') or
                       address.get('village') or
                       address.get('municipality') or
                       address.get('city_district'))

                # Get state - try different possible fields
                state = (address.get('state') or
                        address.get('state_district') or
                        address.get('province'))

                country = address.get('country')

                # CRITICAL: Return None if both city and state are not present
                if not city or not state:
                    logger.warning(f"Incomplete location data - City: {city}, State: {state}")
                    return None

                return {
                    'city': city,
                    'state': state,
                    'country': country,
                    'display_name': data.get('display_name')
                }
            return None
        except Exception as e:
            logger.error(f"Reverse geocoding error: {e}")
            return None

    @staticmethod
    def find_matching_office_location(city, state=None):
        """
        Find matching office location based on city and state.
        REQUIRES both city and state to be present - no fallback matching.
        """
        from trueAlign.models import OfficeLocation

        # CRITICAL: Both city and state must be present
        if not city or not state:
            return None

        # Try exact match first (case insensitive)
        office_location = OfficeLocation.objects.filter(
            city__iexact=city,
            state__iexact=state,
            is_active=True
        ).first()

        if office_location:
            return office_location

        # Try partial match with icontains for both city and state
        office_location = OfficeLocation.objects.filter(
            city__icontains=city,
            state__icontains=state,
            is_active=True
        ).first()

        return office_location

    @staticmethod
    def get_rooms_for_location(office_location):
        """
        Get available rooms for a given office location
        """
        from trueAlign.models import Room

        rooms = Room.objects.filter(
            office_location=office_location,
            status=Room.RoomStatus.ACTIVE
        ).select_related('office_location')

        rooms_data = []
        for room in rooms:
            rooms_data.append({
                'id': getattr(room, 'id', None),
                'name': room.name,
                'capacity': room.capacity,
                'room_type': room.get_room_type_display() if hasattr(room, 'get_room_type_display') else room.room_type,
                'facilities': room.facilities,
                'location': room.location,
                'hourly_rate': float(room.hourly_rate) if room.hourly_rate else 0,
                'office_location': {
                    'id': getattr(room.office_location, 'id', None) if room.office_location else None,
                    'name': getattr(room.office_location, 'name', None) if room.office_location else None,
                    'city': getattr(room.office_location, 'city', None) if room.office_location else None,
                    'state': getattr(room.office_location, 'state', None) if room.office_location else None,
                } if room.office_location else None
            })

        return rooms_data


class LocationValidator:
    """
    Validates location access and enforces location requirements
    """

    @staticmethod
    def validate_coordinates(latitude, longitude):
        """
        Validate coordinate format and range
        """
        try:
            lat = float(latitude)
            lon = float(longitude)

            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return True, lat, lon
            else:
                return False, None, None
        except (ValueError, TypeError):
            return False, None, None

    @staticmethod
    def is_location_required_for_booking():
        """
        Check if location is required for conference booking
        """
        return True  # Always require location for conference booking

    @staticmethod
    def check_location_access_in_session(request):
        """
        Check if user has already granted location access in current session.
        For initial page loads, allow access but require frontend validation.
        """
        # Allow access for initial page loads - frontend will handle validation
        if request.method == 'GET':
            return True

        # For POST requests (actual bookings), require verified location
        verified_location = request.session.get('location_access_granted', False)
        if not verified_location:
            logger.warning('Location access not verified in session')
        return verified_location

    @staticmethod
    def set_location_access_in_session(request, granted=True):
        """
        Set location access status in session
        """
        request.session['location_access_granted'] = granted
        request.session.modified = True

    @staticmethod
    def is_location_verified_in_session(request):
        """
        Check if location has been verified (for booking operations)
        """
        return request.session.get('location_access_granted', False)
