"""
Conference Room Management Views
Handles all views for room management and booking functionality.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Count, Prefetch
from django.utils import timezone
from django.http import JsonResponse
from datetime import datetime, timedelta

from trueAlign.models import ConferenceRoom, RoomBooking, OfficeLocation
from .forms import (
    ConferenceRoomForm, 
    RoomBookingForm, 
    BookingCancelForm, 
    RoomFilterForm
)


# ============= Helper Functions =============

def is_admin_or_hr(user):
    """
    Check if user is admin or HR using Django Groups.
    Admin and HR groups have permission to manage conference rooms.
    """
    if not user.is_authenticated:
        return False
    user_groups = user.groups.values_list('name', flat=True)
    return 'Admin' in user_groups or 'HR' in user_groups


def get_dashboard_conference_context(user):
    """
    Get real-time conference booking data for dashboard card.
    Returns context data for displaying current status, next booking, and stats.
    """
    now = timezone.now()
    today = now.date()
    
    # Get user's office location (assuming user has a profile with office_location)
    user_office = None
    if hasattr(user, 'userdetails') and hasattr(user.userdetails, 'office_location'):
        user_office = user.userdetails.office_location
    
    # Get available rooms (prioritize user's office, then all active rooms)
    if user_office:
        featured_room = ConferenceRoom.objects.filter(
            office_location=user_office, 
            is_active=True
        ).first()
    else:
        featured_room = ConferenceRoom.objects.filter(is_active=True).first()
    
    # Get current booking for featured room (if any)
    current_booking = None
    next_booking = None
    is_currently_free = True
    free_until = None
    
    if featured_room:
        # Check if room is currently booked
        current_booking = RoomBooking.objects.filter(
            room=featured_room,
            status__in=[RoomBooking.STATUS_CONFIRMED, RoomBooking.STATUS_PENDING],
            start_time__lte=now,
            end_time__gte=now
        ).first()
        
        is_currently_free = current_booking is None
        
        # Get next booking
        next_booking = RoomBooking.objects.filter(
            room=featured_room,
            status__in=[RoomBooking.STATUS_CONFIRMED, RoomBooking.STATUS_PENDING],
            start_time__gt=now
        ).order_by('start_time').first()
        
        # Calculate free until time
        if is_currently_free and next_booking:
            free_until = next_booking.start_time
        elif current_booking:
            free_until = current_booking.end_time
    
    # Get today's booking stats
    todays_bookings = RoomBooking.objects.filter(
        start_time__date=today,
        status__in=[RoomBooking.STATUS_CONFIRMED, RoomBooking.STATUS_PENDING]
    )
    
    if featured_room:
        todays_room_bookings = todays_bookings.filter(room=featured_room).count()
    else:
        todays_room_bookings = todays_bookings.count()
    
    # Get user's upcoming bookings count
    user_upcoming_bookings = RoomBooking.objects.filter(
        booked_by=user,
        status__in=[RoomBooking.STATUS_CONFIRMED, RoomBooking.STATUS_PENDING],
        start_time__gte=now
    ).count()
    
    return {
        'featured_room': featured_room,
        'current_booking': current_booking,
        'next_booking': next_booking,
        'is_currently_free': is_currently_free,
        'free_until': free_until,
        'todays_bookings_count': todays_room_bookings,
        'user_upcoming_bookings': user_upcoming_bookings,
        'total_active_rooms': ConferenceRoom.objects.filter(is_active=True).count(),
    }


# ============= Room Management Views (Admin Only) =============

@login_required
@user_passes_test(is_admin_or_hr)
def room_list_admin(request):
    """
    Admin view to list all conference rooms with filters.
    Allows Admin to manage (create/edit/delete) rooms.
    """
    # Get filter form
    filter_form = RoomFilterForm(request.GET or None)
    
    # Base queryset
    rooms = ConferenceRoom.objects.select_related('office_location', 'created_by').annotate(
        total_bookings=Count('bookings'),
        upcoming_bookings=Count('bookings', filter=Q(
            bookings__status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
            bookings__start_time__gte=timezone.now()
        ))
    )
    
    # Apply filters
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('office_location'):
            rooms = rooms.filter(office_location=filter_form.cleaned_data['office_location'])
        
        if filter_form.cleaned_data.get('min_capacity'):
            rooms = rooms.filter(capacity__gte=filter_form.cleaned_data['min_capacity'])
        
        if filter_form.cleaned_data.get('floor'):
            rooms = rooms.filter(floor__icontains=filter_form.cleaned_data['floor'])
        
        if filter_form.cleaned_data.get('is_active'):
            rooms = rooms.filter(is_active=True)
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        rooms = rooms.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(office_location__name__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(rooms, 12)  # 12 rooms per page
    page_number = request.GET.get('page')
    rooms_page = paginator.get_page(page_number)
    
    context = {
        'rooms': rooms_page,
        'filter_form': filter_form,
        'search_query': search_query,
        'total_rooms': rooms.count(),
        'active_rooms': rooms.filter(is_active=True).count(),
    }
    
    return render(request, 'conference/admin/room_list.html', context)


@login_required
@user_passes_test(is_admin_or_hr)
def room_create(request):
    """Admin view to create a new conference room."""
    if request.method == 'POST':
        form = ConferenceRoomForm(request.POST, request.FILES)
        if form.is_valid():
            room = form.save(commit=False)
            room.created_by = request.user
            room.save()
            messages.success(request, f'Conference room "{room.name}" created successfully!')
            return redirect('conference:admin_room_list')
    else:
        form = ConferenceRoomForm()
    
    context = {
        'form': form,
        'action': 'Create',
    }
    
    return render(request, 'conference/admin/room_form.html', context)


@login_required
@user_passes_test(is_admin_or_hr)
def room_edit(request, room_id):
    """Admin view to edit an existing conference room."""
    room = get_object_or_404(ConferenceRoom, id=room_id)
    
    if request.method == 'POST':
        form = ConferenceRoomForm(request.POST, request.FILES, instance=room)
        if form.is_valid():
            form.save()
            messages.success(request, f'Conference room "{room.name}" updated successfully!')
            return redirect('conference:admin_room_list')
    else:
        form = ConferenceRoomForm(instance=room)
    
    context = {
        'form': form,
        'room': room,
        'action': 'Edit',
    }
    
    return render(request, 'conference/admin/room_form.html', context)


@login_required
@user_passes_test(is_admin_or_hr)
def room_delete(request, room_id):
    """Admin view to delete a conference room."""
    room = get_object_or_404(ConferenceRoom, id=room_id)
    
    # Check if room has future bookings
    future_bookings = room.bookings.filter(
        status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
        start_time__gte=timezone.now()
    ).count()
    
    if request.method == 'POST':
        room_name = room.name
        room.delete()
        messages.success(request, f'Conference room "{room_name}" deleted successfully!')
        return redirect('conference:admin_room_list')
    
    context = {
        'room': room,
        'future_bookings': future_bookings,
    }
    
    return render(request, 'conference/admin/room_delete_confirm.html', context)


@login_required
@user_passes_test(is_admin_or_hr)
def room_toggle_active(request, room_id):
    """Admin view to toggle room active status."""
    room = get_object_or_404(ConferenceRoom, id=room_id)
    
    room.is_active = not room.is_active
    room.save()
    
    status = "activated" if room.is_active else "deactivated"
    messages.success(request, f'Conference room "{room.name}" {status} successfully!')
    
    return redirect('conference:admin_room_list')


# ============= Room Booking Views (All Users) =============

@login_required
def room_list(request):
    """
    Public view for all employees to browse available conference rooms.
    Shows only active rooms with availability info.
    """
    # Get user's office location (assuming user has office_location field)
    # Adjust this based on your User model structure
    user_office = None
    if hasattr(request.user, 'userdetails') and hasattr(request.user.userdetails, 'office_location'):
        user_office = request.user.userdetails.office_location
    
    # Base queryset - only active rooms
    rooms = ConferenceRoom.objects.filter(is_active=True).select_related('office_location')
    
    # Filter by user's office by default
    if user_office:
        rooms = rooms.filter(office_location=user_office)
    
    # Apply filters
    filter_form = RoomFilterForm(request.GET or None)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('office_location'):
            rooms = rooms.filter(office_location=filter_form.cleaned_data['office_location'])
        
        if filter_form.cleaned_data.get('min_capacity'):
            rooms = rooms.filter(capacity__gte=filter_form.cleaned_data['min_capacity'])
        
        if filter_form.cleaned_data.get('floor'):
            rooms = rooms.filter(floor__icontains=filter_form.cleaned_data['floor'])
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        rooms = rooms.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Annotate with upcoming bookings count
    rooms = rooms.annotate(
        upcoming_bookings=Count('bookings', filter=Q(
            bookings__status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
            bookings__start_time__gte=timezone.now()
        ))
    )
    
    # Pagination
    paginator = Paginator(rooms, 9)  # 9 rooms per page
    page_number = request.GET.get('page')
    rooms_page = paginator.get_page(page_number)
    
    context = {
        'rooms': rooms_page,
        'filter_form': filter_form,
        'search_query': search_query,
        'user_office': user_office,
        'total_rooms': rooms.count(),
    }
    
    return render(request, 'conference/room_list.html', context)


@login_required
def room_detail(request, room_id):
    """
    Detailed view of a conference room showing amenities and upcoming bookings.
    """
    room = get_object_or_404(
        ConferenceRoom.objects.select_related('office_location'),
        id=room_id,
        is_active=True
    )
    
    # Get upcoming bookings for this room
    upcoming_bookings = room.bookings.filter(
        status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
        start_time__gte=timezone.now()
    ).select_related('booked_by').order_by('start_time')[:10]
    
    # Get today's bookings
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    today_bookings = room.bookings.filter(
        status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
        start_time__gte=today_start,
        start_time__lt=today_end
    ).select_related('booked_by').order_by('start_time')
    
    context = {
        'room': room,
        'upcoming_bookings': upcoming_bookings,
        'today_bookings': today_bookings,
        'amenities': room.amenities if isinstance(room.amenities, list) else [],
    }
    
    return render(request, 'conference/room_detail.html', context)


@login_required
def booking_create(request, room_id=None):
    """
    Create a new room booking.
    Can be accessed directly or from a specific room.
    """
    selected_room = None
    if room_id:
        selected_room = get_object_or_404(ConferenceRoom, id=room_id, is_active=True)
    
    # Get user's office location
    user_office = None
    if hasattr(request.user, 'userdetails') and hasattr(request.user.userdetails, 'office_location'):
        user_office = request.user.userdetails.office_location
    
    if request.method == 'POST':
        form = RoomBookingForm(
            request.POST, 
            user=request.user,
            office_location=user_office
        )
        if form.is_valid():
            booking = form.save()
            messages.success(
                request, 
                f'Your booking for "{booking.room.name}" on {booking.start_time.strftime("%B %d, %Y at %I:%M %p")} '  # type: ignore
                f'has been confirmed!'
            )
            return redirect('conference:my_bookings')
    else:
        initial = {}
        if selected_room:
            initial['room'] = selected_room
        
        form = RoomBookingForm(
            initial=initial,
            user=request.user,
            office_location=user_office
        )
    
    context = {
        'form': form,
        'selected_room': selected_room,
    }
    
    return render(request, 'conference/booking_form.html', context)


@login_required
def my_bookings(request):
    """
    View all bookings made by the current user.
    Shows upcoming, active, and past bookings.
    """
    # Get all user bookings
    all_bookings = RoomBooking.objects.filter(
        booked_by=request.user
    ).select_related('room', 'room__office_location').order_by('-start_time')
    
    # Categorize bookings
    upcoming = all_bookings.filter(
        status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
        start_time__gt=timezone.now()
    ).order_by('start_time')
    
    active = all_bookings.filter(
        status=RoomBooking.STATUS_CONFIRMED,
        start_time__lte=timezone.now(),
        end_time__gte=timezone.now()
    )
    
    past = all_bookings.filter(
        Q(end_time__lt=timezone.now()) | Q(status=RoomBooking.STATUS_CANCELLED)
    ).order_by('-start_time')
    
    # Pagination for past bookings
    paginator = Paginator(past, 10)
    page_number = request.GET.get('page')
    past_page = paginator.get_page(page_number)
    
    context = {
        'upcoming_bookings': upcoming,
        'active_bookings': active,
        'past_bookings': past_page,
        'total_bookings': all_bookings.count(),
        'upcoming_count': upcoming.count(),
        'active_count': active.count(),
    }
    
    return render(request, 'conference/my_bookings.html', context)


@login_required
def booking_detail(request, booking_id):
    """
    View details of a specific booking.
    Users can only view their own bookings (unless admin).
    """
    booking = get_object_or_404(
        RoomBooking.objects.select_related('room', 'room__office_location', 'booked_by'),
        id=booking_id
    )
    
    # Check permission
    if booking.booked_by != request.user and not is_admin_or_hr(request.user):
        messages.error(request, "You don't have permission to view this booking.")
        return redirect('conference:my_bookings')
    
    context = {
        'booking': booking,
    }
    
    return render(request, 'conference/booking_detail.html', context)


@login_required
def booking_cancel(request, booking_id):
    """
    Cancel a booking.
    Users can only cancel their own bookings.
    """
    booking = get_object_or_404(
        RoomBooking.objects.select_related('room'),
        id=booking_id
    )
    
    # Check permission
    if booking.booked_by != request.user and not is_admin_or_hr(request.user):
        messages.error(request, "You don't have permission to cancel this booking.")
        return redirect('conference:my_bookings')
    
    # Check if booking can be cancelled
    if booking.status == RoomBooking.STATUS_CANCELLED:
        messages.warning(request, "This booking is already cancelled.")
        return redirect('conference:booking_detail', booking_id=booking.id)
    
    if booking.is_past:
        messages.error(request, "Cannot cancel a past booking.")
        return redirect('conference:booking_detail', booking_id=booking.id)
    
    if request.method == 'POST':
        form = BookingCancelForm(request.POST)
        if form.is_valid():
            reason = form.cleaned_data.get('cancellation_reason', '')
            booking.cancel(reason=reason)
            messages.success(
                request, 
                f'Your booking for "{booking.room.name}" on {booking.start_time.strftime("%B %d, %Y")} '  # type: ignore
                f'has been cancelled successfully.'
            )
            return redirect('conference:my_bookings')
    else:
        form = BookingCancelForm()
    
    context = {
        'booking': booking,
        'form': form,
    }
    
    return render(request, 'conference/booking_cancel.html', context)


# ============= Calendar & Schedule Views =============

@login_required
def booking_calendar(request):
    """
    Calendar view showing all bookings.
    Allows users to see availability across rooms.
    """
    # Get date range (default to current month)
    today = timezone.now().date()
    year = int(request.GET.get('year', today.year))
    month = int(request.GET.get('month', today.month))
    
    # Calculate month boundaries
    from calendar import monthrange
    _, days_in_month = monthrange(year, month)
    
    month_start = timezone.make_aware(datetime(year, month, 1, 0, 0, 0))
    month_end = timezone.make_aware(datetime(year, month, days_in_month, 23, 59, 59))
    
    # Get all bookings in this month
    bookings = RoomBooking.objects.filter(
        status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
        start_time__gte=month_start,
        start_time__lte=month_end
    ).select_related('room', 'booked_by').order_by('start_time')
    
    # Get all active rooms
    rooms = ConferenceRoom.objects.filter(is_active=True).select_related('office_location')
    
    # Filter by room if specified
    room_filter = request.GET.get('room')
    if room_filter:
        bookings = bookings.filter(room_id=room_filter)
    
    context = {
        'bookings': bookings,
        'rooms': rooms,
        'selected_room': room_filter,
        'current_year': year,
        'current_month': month,
        'today': today,
    }
    
    return render(request, 'conference/calendar.html', context)


# ============= API/AJAX Views =============

@login_required
def check_availability(request):
    """
    AJAX endpoint to check room availability for a given time slot.
    Returns JSON response.
    """
    if request.method == 'GET':
        room_id = request.GET.get('room_id')
        date_str = request.GET.get('date')
        start_time_str = request.GET.get('start_time')
        end_time_str = request.GET.get('end_time')
        
        if not all([room_id, date_str, start_time_str, end_time_str]):
            return JsonResponse({'error': 'Missing required parameters'}, status=400)
        
        try:
            room = ConferenceRoom.objects.get(id=room_id, is_active=True)
            
            # Parse datetime
            booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            start_time = datetime.strptime(start_time_str, '%H:%M').time()
            end_time = datetime.strptime(end_time_str, '%H:%M').time()
            
            start_datetime = timezone.make_aware(datetime.combine(booking_date, start_time))
            end_datetime = timezone.make_aware(datetime.combine(booking_date, end_time))
            
            # Check for conflicts
            buffer = timedelta(minutes=room.buffer_time_minutes)
            check_start = start_datetime - buffer
            check_end = end_datetime + buffer
            
            conflicts = RoomBooking.objects.filter(
                room=room,
                status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED],
                start_time__lt=check_end,
                end_time__gt=check_start
            )
            
            if conflicts.exists():
                conflicting = conflicts.first()
                return JsonResponse({
                    'available': False,
                    'message': f'Time slot conflicts with: {conflicting.title}',
                    'conflict': {
                        'title': conflicting.title,
                        'start': conflicting.start_time.strftime('%H:%M'),  # type: ignore
                        'end': conflicting.end_time.strftime('%H:%M'),  # type: ignore
                    }
                })
            else:
                return JsonResponse({
                    'available': True,
                    'message': 'Room is available for this time slot'
                })
        
        except ConferenceRoom.DoesNotExist:
            return JsonResponse({'error': 'Room not found'}, status=404)
        except ValueError as e:
            return JsonResponse({'error': f'Invalid date/time format: {str(e)}'}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)
