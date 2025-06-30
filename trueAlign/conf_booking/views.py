from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from trueAlign.models import ConferenceBooking, Room, BookingAnalytics, RoomManager, BookingValidator, BookingNotification
from django.db import IntegrityError
from django.utils import timezone
from datetime import timedelta, datetime, time
from pytz import timezone as pytz_timezone
import pytz
from django import forms
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum, F
from django.views.decorators.http import require_http_methods
import logging
import json

# Set up logger
logger = logging.getLogger(__name__)

# Define timezone
IST = pytz_timezone('Asia/Kolkata')

class ConferenceBookingForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Dynamically populate room choices from active rooms
        active_rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE).order_by('name')
        room_choices = [('', 'Select a room')]
        room_choices.extend([(room.id, f"{room.name} (Capacity: {room.capacity})") for room in active_rooms])

        self.fields['room'].choices = room_choices

        # Make all fields required
        for field_name, field in self.fields.items():
            field.required = True
            logger.debug(f"Setting field {field_name} as required")

    class Meta:
        model = ConferenceBooking
        fields = [
            'room', 'purpose', 'description', 'start_time', 'end_time',
            'attendees_count', 'external_attendees', 'meeting_type', 'priority'
        ]
        widgets = {
            'room': forms.Select(attrs={'class': 'form-control', 'required': True}),
            'purpose': forms.TextInput(attrs={'class': 'form-control', 'required': True, 'maxlength': 255}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'start_time': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control', 'required': True}),
            'end_time': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control', 'required': True}),
            'attendees_count': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 50, 'value': 1}),
            'external_attendees': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'max': 20, 'value': 0}),
            'meeting_type': forms.Select(attrs={'class': 'form-control'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        room = cleaned_data.get('room')
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        attendees_count = cleaned_data.get('attendees_count', 1)

        # Basic validation
        if start_time and end_time:
            if start_time >= end_time:
                raise forms.ValidationError("End time must be after start time.")

            if start_time < timezone.now():
                raise forms.ValidationError("Start time cannot be in the past.")

            # Duration validation (15 minutes to 8 hours)
            duration = end_time - start_time
            if duration < timedelta(minutes=15):
                raise forms.ValidationError("Minimum booking duration is 15 minutes.")

            if duration > timedelta(hours=8):
                raise forms.ValidationError("Maximum booking duration is 8 hours.")

            # Working hours validation
            start_hour = start_time.hour
            end_hour = end_time.hour
            start_day = start_time.weekday()
            end_day = end_time.weekday()

            if start_day >= 5 or end_day >= 5:  # Saturday = 5, Sunday = 6
                raise forms.ValidationError("Bookings are only allowed on weekdays (Monday to Friday).")

            if start_hour < 9 or start_hour >= 18:
                raise forms.ValidationError("Start time must be between 9:00 AM and 6:00 PM.")

            if end_hour < 9 or end_hour > 18:
                raise forms.ValidationError("End time must be between 9:00 AM and 6:00 PM.")

        # Room capacity validation
        if room and attendees_count and attendees_count > room.capacity:
            raise forms.ValidationError(f"Number of attendees ({attendees_count}) exceeds room capacity ({room.capacity}).")

        return cleaned_data


def find_next_available_slot(room, start_time, duration):
    """
    Finds the next available booking slot for a given room.
    """
    # Use RoomManager utility for better slot suggestions
    suggestions = RoomManager.suggest_alternative_slots(
        room, start_time, start_time + duration, duration.total_seconds() / 60
    )

    if suggestions:
        return suggestions[0]['start_time']

    # Fallback logic
    future_bookings = ConferenceBooking.objects.filter(
        room=room,
        status=ConferenceBooking.BookingStatus.CONFIRMED,
        end_time__gt=start_time
    ).order_by('start_time')

    search_from = start_time

    for booking in future_bookings:
        if booking.start_time - search_from >= duration:
            return search_from
        search_from = booking.end_time

    return search_from


@login_required
def booking_room(request):
    """
    Handles both displaying the booking form/dashboard (GET) and
    creating a new booking (POST).
    """
    if request.method == 'POST':
        # Check if form data is present
        form_fields = ['room', 'purpose', 'start_time', 'end_time']
        has_form_data = any(field in request.POST and request.POST[field].strip() for field in form_fields)

        if not has_form_data:
            logger.warning(f"No form data received in booking request from user {request.user}")
            messages.error(request, "No booking data was received. Please ensure all form fields are filled out and try again.", extra_tags='conf_booking')
            return redirect('core:dashboard')

        form = ConferenceBookingForm(request.POST)
        logger.info(f"Processing booking form for user {request.user} with data: {dict(request.POST)}")

        if form.is_valid():
            room = form.cleaned_data['room']
            start_time = form.cleaned_data['start_time']
            end_time = form.cleaned_data['end_time']
            attendees_count = form.cleaned_data['attendees_count']

            logger.info(f"Form valid - attempting to book {room.name} from {start_time} to {end_time} for {attendees_count} attendees")

            # Check for booking conflicts
            conflicting_bookings = ConferenceBooking.get_conflicting_bookings(room, start_time, end_time)

            if conflicting_bookings.exists():
                logger.info(f"Booking conflict detected for {room.name} - {conflicting_bookings.count()} conflicts found")

                try:
                    duration = end_time - start_time
                    next_slot_start = find_next_available_slot(room, start_time, duration)
                    next_slot_end = next_slot_start + duration

                    # Format for display
                    next_slot_start_str = next_slot_start.astimezone(IST).strftime('%b %d, %Y at %I:%M %p')
                    next_slot_end_str = next_slot_end.astimezone(IST).strftime('%I:%M %p')

                    error_msg = (f'"{room.name}" is already booked for the selected time. '
                                 f'The next available slot is on {next_slot_start_str} - {next_slot_end_str}.')
                    messages.error(request, error_msg, extra_tags='conf_booking')
                except Exception as e:
                    logger.error(f"Error finding next available slot: {e}")
                    messages.error(request, f'"{room.name}" is already booked for the selected time. Please choose a different time or room.', extra_tags='conf_booking')
            else:
                try:
                    booking = form.save(commit=False)
                    booking.booked_by = request.user
                    booking.status = ConferenceBooking.BookingStatus.CONFIRMED
                    booking.hourly_rate = room.hourly_rate
                    booking.save()

                    logger.info(f"Booking created successfully: ID {booking.id} for user {request.user}")

                    # Format times for success message
                    start_time_str = start_time.astimezone(IST).strftime('%b %d, %Y at %I:%M %p')
                    end_time_str = end_time.astimezone(IST).strftime('%I:%M %p')

                    success_msg = f'Successfully booked "{room.name}" for {start_time_str} - {end_time_str}!'
                    messages.success(request, success_msg, extra_tags='conf_booking')

                    # Send booking confirmation
                    try:
                        BookingNotification.send_booking_confirmation(booking)
                        logger.info(f"Confirmation email sent for booking {booking.id}")
                    except Exception as e:
                        logger.warning(f"Failed to send confirmation email for booking {booking.id}: {e}")

                    return redirect('core:dashboard')

                except IntegrityError as e:
                    logger.error(f"Database integrity error during booking: {e}")
                    messages.error(request, f'The room "{room.name}" was just booked for the selected time slot by someone else. Please try a different time.', extra_tags='conf_booking')
                except Exception as e:
                    logger.error(f"Unexpected booking error for user {request.user}: {e}")
                    messages.error(request, "An unexpected error occurred while booking the room. Please try again later.", extra_tags='conf_booking')
        else:
            logger.warning(f"Form validation failed for user {request.user}: {form.errors}")

            # Extract and display form errors
            error_messages = []
            for field, errors in form.errors.items():
                if field == '__all__':
                    error_messages.extend(errors)
                else:
                    field_name = field.replace('_', ' ').title()
                    for error in errors:
                        error_messages.append(f"{field_name}: {error}")

            if error_messages:
                messages.error(request, "Please correct the following errors: " + "; ".join(error_messages), extra_tags='conf_booking')
            else:
                messages.error(request, "Please ensure all required fields are filled out correctly.", extra_tags='conf_booking')

    return redirect('core:dashboard')


@login_required
def cancel_booking(request, booking_id):
    """
    Allows a user to cancel their own booking.
    """
    booking = get_object_or_404(ConferenceBooking, id=booking_id)

    # Security check: only the person who booked can cancel
    if booking.booked_by != request.user:
        messages.error(request, "You do not have permission to cancel this booking.")
        return redirect('core:dashboard')

    # Use the model's cancel method for proper validation
    try:
        reason = request.POST.get('cancellation_reason', 'Cancelled by user')
        booking.cancel(cancelled_by=request.user, reason=reason)

        # Send cancellation notice
        try:
            BookingNotification.send_cancellation_notice(booking)
        except Exception as e:
            logger.warning(f"Failed to send cancellation email for booking {booking_id}: {e}")

        messages.success(request, f"Your booking for '{booking.room.name}' has been cancelled.")
    except ValueError as e:
        messages.error(request, str(e))
    except Exception as e:
        logger.error(f"Error cancelling booking {booking_id}: {e}")
        messages.error(request, "An error occurred while cancelling the booking.")

    return redirect('core:dashboard')


@login_required
def get_available_slots(request):
    """
    API endpoint to find and return available slots for a given room and duration.
    """
    logger.info(f"Available slots request from user {request.user} with params: {dict(request.GET)}")

    try:
        # Get query parameters
        room_id = request.GET.get('room_id')
        duration_minutes = int(request.GET.get('duration', 60))
        start_date_str = request.GET.get('start_date')
        min_capacity = int(request.GET.get('min_capacity', 1))
        start_time_str = request.GET.get('start_time')
        end_time_str = request.GET.get('end_time')

        # Handle availability check for specific time slot
        if start_time_str and end_time_str and room_id:
            logger.info(f"Checking specific time slot availability for room {room_id}")
            try:
                room = Room.objects.get(id=room_id, status=Room.RoomStatus.ACTIVE)
                start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))

                # Check if room is available for this specific time
                conflicts = ConferenceBooking.get_conflicting_bookings(room, start_time, end_time)

                if conflicts.exists():
                    logger.info(f"Time slot conflict found for room {room.name}: {conflicts.count()} conflicts")
                    return JsonResponse({'available_slots': []})
                else:
                    logger.info(f"Time slot available for room {room.name}")
                    return JsonResponse({
                        'available_slots': [{
                            'room_id': room.id,
                            'room_name': room.name,
                            'start': start_time.isoformat(),
                            'end': end_time.isoformat(),
                            'capacity': room.capacity
                        }]
                    })
            except Room.DoesNotExist:
                logger.warning(f"Room {room_id} not found or not active")
                return JsonResponse({'error': 'Room not found or not available.'}, status=404)
            except ValueError as e:
                logger.error(f"Invalid time format in availability check: {e}")
                return JsonResponse({'error': 'Invalid room or time format.'}, status=400)

        # Determine search start time
        if not start_date_str:
            start_of_search = timezone.now()
            logger.info("Using current time for slot search")
        else:
            try:
                search_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                day_start_ist = IST.localize(datetime.combine(search_date, time(9, 0)))
                start_of_search = max(timezone.now(), day_start_ist.astimezone(pytz.UTC))
                logger.info(f"Using search date {search_date} for slot search")
            except ValueError:
                logger.error(f"Invalid date format: {start_date_str}")
                return JsonResponse({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)

        end_of_search = start_of_search + timedelta(minutes=duration_minutes)

        if room_id:
            logger.info(f"Finding slots for specific room {room_id}")
            # Get slots for specific room
            try:
                room = Room.objects.get(id=room_id, status=Room.RoomStatus.ACTIVE)
                suggestions = RoomManager.suggest_alternative_slots(
                    room, start_of_search, end_of_search, duration_minutes
                )

                available_slots = []
                for suggestion in suggestions:
                    available_slots.append({
                        'room_id': room.id,
                        'room_name': room.name,
                        'start': suggestion['start_time'].isoformat(),
                        'end': suggestion['end_time'].isoformat(),
                        'capacity': room.capacity,
                        'facilities': room.facilities
                    })

                logger.info(f"Found {len(available_slots)} slots for room {room.name}")

            except Room.DoesNotExist:
                logger.warning(f"Room {room_id} not found for slot search")
                return JsonResponse({'error': 'Room not found or not available.'}, status=404)
        else:
            logger.info(f"Finding available rooms for time slot with min capacity {min_capacity}")
            # Get available rooms for the time slot
            available_rooms = RoomManager.get_available_rooms_for_slot(
                start_of_search, end_of_search, min_capacity
            )

            available_slots = []
            for room_data in available_rooms:
                room = room_data['room']
                available_slots.append({
                    'room_id': room.id,
                    'room_name': room.name,
                    'start': start_of_search.isoformat(),
                    'end': end_of_search.isoformat(),
                    'capacity': room.capacity,
                    'facilities': room.facilities,
                    'current_booking': room_data['current_booking'].purpose if room_data['current_booking'] else None,
                    'next_booking': room_data['next_booking'].start_time.isoformat() if room_data['next_booking'] else None
                })

            logger.info(f"Found {len(available_slots)} available rooms")

        return JsonResponse({'available_slots': available_slots})

    except Exception as e:
        logger.error(f"Error fetching available slots: {e}", exc_info=True)
        return JsonResponse({'error': 'An error occurred while fetching available slots.'}, status=500)


@login_required
def room_dashboard(request):
    """
    Display real-time room status dashboard.
    """
    dashboard_data = RoomManager.get_room_status_dashboard()
    daily_utilization = BookingAnalytics.get_daily_utilization()
    available_rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE).order_by('name')

    context = {
        'room_dashboard': dashboard_data,
        'daily_utilization': daily_utilization,
        'current_time': timezone.now(),
        'available_rooms': available_rooms,
    }

    return render(request, 'conf_booking/room_dashboard.html', context)


@login_required
def booking_analytics(request):
    """
    Display booking analytics and reports.
    """
    # Get date range from request
    start_date_str = request.GET.get('start_date')
    end_date_str = request.GET.get('end_date')

    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    else:
        start_date = timezone.now().date() - timedelta(days=30)

    if end_date_str:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    else:
        end_date = timezone.now().date()

    # Get analytics data
    weekly_report = BookingAnalytics.get_weekly_report(start_date)
    popular_slots = BookingAnalytics.get_popular_time_slots()
    user_analytics = BookingAnalytics.get_user_analytics(request.user)

    # Get room utilization data
    rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
    room_utilization = []
    for room in rooms:
        utilization = ConferenceBooking.get_room_utilization(room, start_date, end_date)
        room_utilization.append({
            'room': room,
            'utilization': utilization,
            'total_bookings': ConferenceBooking.objects.filter(
                room=room,
                start_time__date__range=[start_date, end_date],
                status=ConferenceBooking.BookingStatus.CONFIRMED
            ).count()
        })

    context = {
        'weekly_report': weekly_report,
        'popular_slots': popular_slots,
        'user_analytics': user_analytics,
        'room_utilization': room_utilization,
        'start_date': start_date,
        'end_date': end_date,
    }

    return render(request, 'conf_booking/analytics.html', context)


@login_required
def user_bookings(request):
    """
    Display user's booking history with filtering and pagination.
    """
    # Get filter parameters
    status_filter = request.GET.get('status', 'all')
    start_date_str = request.GET.get('start_date')
    end_date_str = request.GET.get('end_date')

    # Base queryset
    bookings = ConferenceBooking.objects.filter(
        booked_by=request.user
    ).select_related('room').order_by('-created_at')

    # Apply filters
    if status_filter != 'all':
        bookings = bookings.filter(status=status_filter)

    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        bookings = bookings.filter(start_time__date__gte=start_date)

    if end_date_str:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        bookings = bookings.filter(start_time__date__lte=end_date)

    # Pagination
    paginator = Paginator(bookings, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get user statistics
    user_stats = ConferenceBooking.get_user_booking_stats(request.user)

    context = {
        'page_obj': page_obj,
        'user_stats': user_stats,
        'status_filter': status_filter,
        'start_date': start_date_str,
        'end_date': end_date_str,
        'status_choices': ConferenceBooking.BookingStatus.choices,
    }

    return render(request, 'conf_booking/user_bookings.html', context)


@login_required
@require_http_methods(["POST"])
def check_in_booking(request, booking_id):
    """
    Check in to a booking.
    """
    try:
        booking = get_object_or_404(ConferenceBooking, id=booking_id, booked_by=request.user)
        booking.check_in()
        messages.success(request, f"Successfully checked in to {booking.room.name}!")

        return JsonResponse({
            'success': True,
            'message': 'Successfully checked in!',
            'checked_in_at': booking.checked_in_at.isoformat()
        })

    except ValueError as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)
    except Exception as e:
        logger.error(f"Error checking in to booking {booking_id}: {e}")
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while checking in.'
        }, status=500)


@staff_member_required
def admin_booking_management(request):
    """
    Admin view for managing all bookings.
    """
    # Get filter parameters
    room_filter = request.GET.get('room')
    status_filter = request.GET.get('status', 'all')
    date_filter = request.GET.get('date')

    # Base queryset
    bookings = ConferenceBooking.objects.all().select_related('room', 'booked_by').order_by('-created_at')

    # Apply filters
    if room_filter:
        bookings = bookings.filter(room_id=room_filter)

    if status_filter != 'all':
        bookings = bookings.filter(status=status_filter)

    if date_filter:
        filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
        bookings = bookings.filter(start_time__date=filter_date)

    # Pagination
    paginator = Paginator(bookings, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get summary statistics
    total_bookings = ConferenceBooking.objects.count()
    confirmed_today = ConferenceBooking.objects.filter(
        start_time__date=timezone.now().date(),
        status=ConferenceBooking.BookingStatus.CONFIRMED
    ).count()

    # Get reminders and no-shows
    reminder_bookings = BookingNotification.get_reminder_bookings()
    no_show_candidates = BookingNotification.get_no_show_candidates()

    context = {
        'page_obj': page_obj,
        'rooms': Room.objects.filter(status=Room.RoomStatus.ACTIVE),
        'status_choices': ConferenceBooking.BookingStatus.choices,
        'room_filter': room_filter,
        'status_filter': status_filter,
        'date_filter': date_filter,
        'total_bookings': total_bookings,
        'confirmed_today': confirmed_today,
        'reminder_bookings': reminder_bookings,
        'no_show_candidates': no_show_candidates,
    }

    return render(request, 'conf_booking/admin_management.html', context)


@staff_member_required
@require_http_methods(["POST"])
def mark_no_show(request, booking_id):
    """
    Mark a booking as no-show (admin only).
    """
    try:
        booking = get_object_or_404(ConferenceBooking, id=booking_id)
        booking.mark_no_show()

        return JsonResponse({
            'success': True,
            'message': f'Booking for {booking.room.name} marked as no-show.'
        })

    except Exception as e:
        logger.error(f"Error marking booking {booking_id} as no-show: {e}")
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while marking as no-show.'
        }, status=500)


def conference_booking_context(user=None):
    """
    Prepares the context required for the conference booking card.
    This can be called from your main dashboard view.
    """
    form = ConferenceBookingForm()
    now = timezone.now()

    # Get rooms with real-time status
    available_rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE).order_by('name')

    # Prefetch related bookings for efficiency
    available_rooms = available_rooms.prefetch_related(
        'bookings__booked_by'
    )

    # Process each room to ensure properties are accessible in template
    rooms_with_status = []
    for room in available_rooms:
        # Create a room object with additional properties
        room_data = {
            'id': room.id,
            'name': room.name,
            'capacity': room.capacity,
            'location': room.location,
            'room_type': room.room_type,
            'facilities': room.facilities,
            'status': room.status,
            'is_available': room.is_available,
            'is_occupied': room.is_occupied,
            'current_booking': room.current_booking,
            'next_booking': room.next_booking,
        }
        rooms_with_status.append(type('Room', (), room_data)())

    # Fetch user's upcoming bookings if user is provided
    user_bookings = []
    if user and user.is_authenticated:
        user_bookings = ConferenceBooking.objects.filter(
            booked_by=user,
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__gte=now
        ).select_related('room').order_by('start_time')[:5]  # Limit to 5 most recent

    # Get user analytics
    user_analytics = None
    if user and user.is_authenticated:
        try:
            user_analytics = BookingAnalytics.get_user_analytics(user, days=7)
        except Exception as e:
            logger.warning(f"Failed to get user analytics for {user}: {e}")
            user_analytics = None

    context = {
        'conference_form': form,
        'user_bookings': user_bookings,
        'user_analytics': user_analytics,
        'available_rooms': rooms_with_status,
    }
    return context


def get_upcoming_booking_for_room(room_name):
    """
    Fetches the next upcoming booking for a specific room for the rest of today.
    Updated to work with Room model.
    """
    try:
        room = Room.objects.get(name=room_name, status=Room.RoomStatus.ACTIVE)
        return room.next_booking
    except Room.DoesNotExist:
        return None


@login_required
def booking_details(request, booking_id):
    """
    Display detailed view of a specific booking.
    """
    booking = get_object_or_404(ConferenceBooking, id=booking_id, booked_by=request.user)

    # Generate comprehensive booking summary
    from .utils import BookingHelper
    booking_summary = BookingHelper.generate_booking_summary(booking)

    # Calculate utilization percentage based on attendees vs room capacity
    utilization_percentage = 0
    if booking.room.capacity > 0 and booking.attendees_count:
        utilization_percentage = round((booking.attendees_count * 100) / booking.room.capacity)

    context = {
        'booking': booking,
        'booking_summary': booking_summary,
        'utilization_percentage': utilization_percentage, # Pass the calculated value
    }
    return render(request, 'conf_booking/booking_details.html', context)


@login_required
def get_room_details(request, room_id):
    """
    API endpoint to get detailed room information.
    """
    try:
        room = get_object_or_404(Room, id=room_id, status=Room.RoomStatus.ACTIVE)

        # Get today's bookings
        today_bookings = room.get_bookings_today()

        # Get availability slots
        availability_slots = room.get_availability_today()

        room_data = {
            'id': room.id,
            'name': room.name,
            'type': room.get_room_type_display(),
            'capacity': room.capacity,
            'location': room.location,
            'facilities': room.facilities,
            'hourly_rate': float(room.hourly_rate),
            'description': room.description,
            'is_occupied': room.is_occupied,
            'current_booking': {
                'id': room.current_booking.id,
                'purpose': room.current_booking.purpose,
                'booked_by': room.current_booking.booked_by.get_full_name(),
                'end_time': room.current_booking.end_time.isoformat()
            } if room.current_booking else None,
            'next_booking': {
                'id': room.next_booking.id,
                'purpose': room.next_booking.purpose,
                'start_time': room.next_booking.start_time.isoformat(),
                'booked_by': room.next_booking.booked_by.get_full_name()
            } if room.next_booking else None,
            'today_bookings': [{
                'id': booking.id,
                'purpose': booking.purpose,
                'start_time': booking.start_time.isoformat(),
                'end_time': booking.end_time.isoformat(),
                'booked_by': booking.booked_by.get_full_name(),
                'attendees_count': booking.attendees_count
            } for booking in today_bookings],
            'availability_slots': [{
                'start': slot['start'].isoformat(),
                'end': slot['end'].isoformat()
            } for slot in availability_slots],
            'utilization_today': ConferenceBooking.get_room_utilization(
                room, timezone.now().date(), timezone.now().date()
            )
        }

        return JsonResponse(room_data)

    except Exception as e:
        logger.error(f"Error getting room details for room {room_id}: {e}")
        return JsonResponse({'error': 'Room not found'}, status=404)


@login_required
def get_available_rooms(request):
    """
    API endpoint to get all available rooms.
    """
    logger.info(f"Available rooms request from user {request.user}")

    try:
        active_rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE).order_by('name')
        logger.info(f"Found {active_rooms.count()} active rooms")

        rooms_data = []
        for room in active_rooms:
            try:
                room_info = {
                    'id': room.id,
                    'name': room.name,
                    'capacity': room.capacity,
                    'location': room.location,
                    'room_type': room.get_room_type_display(),
                    'facilities': room.facilities,
                    'hourly_rate': float(room.hourly_rate),
                    'is_available': room.is_available,
                    'is_occupied': room.is_occupied,
                    'current_booking': None,
                    'next_booking': None
                }

                # Add current booking info if exists
                current_booking = room.current_booking
                if current_booking:
                    room_info['current_booking'] = {
                        'purpose': current_booking.purpose,
                        'end_time': current_booking.end_time.isoformat(),
                        'booked_by': current_booking.booked_by.get_full_name()
                    }

                # Add next booking info if exists
                next_booking = room.next_booking
                if next_booking:
                    room_info['next_booking'] = {
                        'purpose': next_booking.purpose,
                        'start_time': next_booking.start_time.isoformat(),
                        'booked_by': next_booking.booked_by.get_full_name()
                    }

                rooms_data.append(room_info)

            except Exception as e:
                logger.error(f"Error processing room {room.name}: {e}")
                # Add basic room info even if booking info fails
                rooms_data.append({
                    'id': room.id,
                    'name': room.name,
                    'capacity': room.capacity,
                    'location': room.location,
                    'room_type': room.get_room_type_display(),
                    'facilities': room.facilities,
                    'hourly_rate': float(room.hourly_rate),
                    'is_available': True,
                    'is_occupied': False
                })

        logger.info(f"Returning {len(rooms_data)} rooms data")
        return JsonResponse({'rooms': rooms_data})

    except Exception as e:
        logger.error(f"Error getting available rooms: {e}", exc_info=True)
        return JsonResponse({'error': 'Failed to load rooms'}, status=500)
