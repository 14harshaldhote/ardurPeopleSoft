"""
Conference Room Management Forms
Handles room creation, editing, and booking forms with validation.
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from trueAlign.models import ConferenceRoom, RoomBooking, OfficeLocation
from datetime import timedelta


class ConferenceRoomForm(forms.ModelForm):
    """
    Form for Admin to create and edit conference rooms.
    Includes validation for room details and booking rules.
    """
    
    # Custom field for amenities with helpful widget
    amenities_input = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'rows': 3,
            'placeholder': 'Enter amenities separated by commas (e.g., Projector, Whiteboard, Video Conference, AC)',
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
        }),
        help_text="List amenities separated by commas"
    )
    
    class Meta:
        model = ConferenceRoom
        fields = [
            'name', 'office_location', 'floor', 'capacity',
            'buffer_time_minutes', 'min_lead_time_minutes', 
            'max_booking_duration_hours', 'is_active', 
            'description', 'image'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'e.g., Board Room, Meeting Room A'
            }),
            'office_location': forms.Select(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
            }),
            'floor': forms.TextInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'e.g., 2nd Floor, Ground'
            }),
            'capacity': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'min': '1',
                'placeholder': 'Maximum number of people'
            }),
            'buffer_time_minutes': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'min': '0',
                'placeholder': '15'
            }),
            'min_lead_time_minutes': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'min': '0',
                'placeholder': '15'
            }),
            'max_booking_duration_hours': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'min': '1',
                'placeholder': '3'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded'
            }),
            'description': forms.Textarea(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'rows': 4,
                'placeholder': 'Additional information about the room...'
            }),
            'image': forms.FileInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'accept': 'image/*'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # If editing existing room, populate amenities_input
        if self.instance and self.instance.pk:
            if self.instance.amenities and isinstance(self.instance.amenities, list):
                self.initial['amenities_input'] = ', '.join(self.instance.amenities)
        
        # Only show active office locations
        self.fields['office_location'].queryset = OfficeLocation.objects.filter(is_active=True)
    
    def clean_amenities_input(self):
        """Convert comma-separated string to list."""
        amenities_str = self.cleaned_data.get('amenities_input', '')
        if amenities_str:
            # Split by comma, strip whitespace, and filter empty strings
            amenities_list = [a.strip() for a in amenities_str.split(',') if a.strip()]
            return amenities_list
        return []
    
    def save(self, commit=True):
        """Save room with amenities from custom field."""
        room = super().save(commit=False)
        room.amenities = self.cleaned_data.get('amenities_input', [])
        
        if commit:
            room.save()
        return room


class RoomBookingForm(forms.ModelForm):
    """
    Form for employees to book conference rooms.
    Includes comprehensive validation for booking constraints.
    """
    
    # Custom date and time fields for better UX
    booking_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
        }),
        help_text="Select the date for your meeting"
    )
    
    start_time_field = forms.TimeField(
        widget=forms.TimeInput(attrs={
            'type': 'time',
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
        }),
        help_text="Meeting start time"
    )
    
    end_time_field = forms.TimeField(
        widget=forms.TimeInput(attrs={
            'type': 'time',
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
        }),
        help_text="Meeting end time"
    )
    
    class Meta:
        model = RoomBooking
        fields = [
            'room', 'title', 'purpose', 'attendees', 
            'attendee_count', 'special_requirements'
        ]
        widgets = {
            'room': forms.Select(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
            }),
            'title': forms.TextInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'e.g., Team Standup Meeting'
            }),
            'purpose': forms.Textarea(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'rows': 3,
                'placeholder': 'Describe the purpose of this meeting...'
            }),
            'attendees': forms.Textarea(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'rows': 3,
                'placeholder': 'Enter attendee names or emails (one per line or comma-separated)'
            }),
            'attendee_count': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'min': '1',
                'placeholder': 'Number of attendees'
            }),
            'special_requirements': forms.Textarea(attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'rows': 2,
                'placeholder': 'Any special setup or equipment needed (optional)'
            }),
        }
    
    def __init__(self, *args, user=None, office_location=None, **kwargs):
        """
        Initialize form with user context.
        
        Args:
            user: The user making the booking
            office_location: Filter rooms by office location
        """
        super().__init__(*args, **kwargs)
        self.user = user
        
        # Filter rooms: only active rooms
        rooms_queryset = ConferenceRoom.objects.filter(is_active=True).select_related('office_location')
        
        # If office_location provided, filter by it
        if office_location:
            rooms_queryset = rooms_queryset.filter(office_location=office_location)
        
        self.fields['room'].queryset = rooms_queryset
        
        # Make special_requirements optional
        self.fields['special_requirements'].required = False
        
        # Set initial date to tomorrow (to avoid issues with lead time)
        if not self.instance.pk:
            tomorrow = timezone.now().date() + timedelta(days=1)
            self.initial['booking_date'] = tomorrow
    
    def clean_booking_date(self):
        """Validate booking date is not in the past."""
        booking_date = self.cleaned_data.get('booking_date')
        
        if booking_date < timezone.now().date():
            raise ValidationError("Cannot book a room for a past date.")
        
        return booking_date
    
    def clean(self):
        """Comprehensive validation for booking constraints."""
        cleaned_data = super().clean()
        
        # Get fields
        booking_date = cleaned_data.get('booking_date')
        start_time = cleaned_data.get('start_time_field')
        end_time = cleaned_data.get('end_time_field')
        room = cleaned_data.get('room')
        attendee_count = cleaned_data.get('attendee_count')
        
        # Skip validation if essential fields are missing
        if not all([booking_date, start_time, end_time, room]):
            return cleaned_data
        
        # Combine date and time into datetime objects
        from datetime import datetime
        
        start_datetime = timezone.make_aware(
            datetime.combine(booking_date, start_time)
        )
        end_datetime = timezone.make_aware(
            datetime.combine(booking_date, end_time)
        )
        
        # Store in cleaned_data for saving
        cleaned_data['start_time'] = start_datetime
        cleaned_data['end_time'] = end_datetime
        
        # Validate end time is after start time
        if end_datetime <= start_datetime:
            raise ValidationError("End time must be after start time.")
        
        # Validate booking is not in the past
        if start_datetime < timezone.now():
            raise ValidationError("Cannot book a room in the past.")
        
        # Validate lead time
        time_until_start = (start_datetime - timezone.now()).total_seconds() / 60
        if time_until_start < room.min_lead_time_minutes:
            raise ValidationError(
                f"Booking must be made at least {room.min_lead_time_minutes} minutes in advance. "
                f"Please select a later time."
            )
        
        # Validate max duration
        duration_hours = (end_datetime - start_datetime).total_seconds() / 3600
        if duration_hours > room.max_booking_duration_hours:
            raise ValidationError(
                f"Booking duration ({duration_hours:.1f} hours) exceeds the maximum allowed "
                f"duration of {room.max_booking_duration_hours} hours for this room."
            )
        
        # Validate attendee count vs room capacity
        if attendee_count and attendee_count > room.capacity:
            raise ValidationError(
                f"Number of attendees ({attendee_count}) exceeds room capacity ({room.capacity}). "
                f"Please choose a larger room or reduce attendees."
            )
        
        # Check for overlapping bookings (including buffer)
        buffer = timedelta(minutes=room.buffer_time_minutes)
        check_start = start_datetime - buffer
        check_end = end_datetime + buffer
        
        overlapping_bookings = RoomBooking.objects.filter(
            room=room,
            status__in=[RoomBooking.STATUS_PENDING, RoomBooking.STATUS_CONFIRMED]
        ).exclude(
            pk=self.instance.pk if self.instance else None
        ).filter(
            start_time__lt=check_end,
            end_time__gt=check_start
        )
        
        if overlapping_bookings.exists():
            conflicting = overlapping_bookings.first()
            raise ValidationError(
                f"This time slot conflicts with another booking: '{conflicting.title}' "
                f"({conflicting.start_time.strftime('%I:%M %p')} - {conflicting.end_time.strftime('%I:%M %p')}). "  # type: ignore
                f"Please note there is a {room.buffer_time_minutes}-minute buffer between bookings."
            )
        
        return cleaned_data
    
    def save(self, commit=True):
        """Save booking with user and datetime info."""
        booking = super().save(commit=False)
        
        # Set the user
        if self.user:
            booking.booked_by = self.user
        
        # Set start and end times from cleaned data
        booking.start_time = self.cleaned_data['start_time']
        booking.end_time = self.cleaned_data['end_time']
        
        if commit:
            booking.save()
        
        return booking


class BookingCancelForm(forms.Form):
    """
    Simple form for cancelling a booking with reason.
    """
    cancellation_reason = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent',
            'rows': 3,
            'placeholder': 'Please provide a reason for cancellation (optional)...'
        }),
        help_text="Optional: Provide a reason for cancelling this booking"
    )


class RoomFilterForm(forms.Form):
    """
    Form for filtering conference rooms by various criteria.
    """
    office_location = forms.ModelChoiceField(
        queryset=OfficeLocation.objects.filter(is_active=True),
        required=False,
        empty_label="All Locations",
        widget=forms.Select(attrs={
            'class': 'px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent'
        })
    )
    
    min_capacity = forms.IntegerField(
        required=False,
        min_value=1,
        widget=forms.NumberInput(attrs={
            'class': 'px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
            'placeholder': 'Min capacity'
        })
    )
    
    floor = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
            'placeholder': 'Floor'
        })
    )
    
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded'
        })
    )
