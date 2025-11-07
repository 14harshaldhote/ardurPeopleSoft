"""
Conference Room Booking Signals
Handles email notifications for booking events.
"""

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from trueAlign.models import RoomBooking


def send_booking_email(booking, email_type):
    """
    Helper function to send booking-related emails.
    
    Args:
        booking: RoomBooking instance
        email_type: 'created', 'updated', 'cancelled'
    """
    # Email subject based on type
    subjects = {
        'created': f'Conference Room Booking Confirmed - {booking.room.name}',
        'updated': f'Conference Room Booking Updated - {booking.room.name}',
        'cancelled': f'Conference Room Booking Cancelled - {booking.room.name}',
    }
    
    subject = subjects.get(email_type, 'Conference Room Booking Notification')
    
    # Get user email
    user_email = booking.booked_by.email
    if not user_email:
        return  # Skip if user has no email
    
    # Prepare email context
    context = {
        'booking': booking,
        'user': booking.booked_by,
        'room': booking.room,
        'email_type': email_type,
    }
    
    # Create HTML message (you can create a proper template later)
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <h2 style="color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 10px;">
                Conference Room Booking {email_type.title()}
            </h2>
            
            <div style="margin: 20px 0;">
                <p><strong>Dear {booking.booked_by.get_full_name() or booking.booked_by.username},</strong></p>
                
                {'<p style="color: #059669;">Your conference room booking has been confirmed!</p>' if email_type == 'created' else ''}
                {'<p style="color: #d97706;">Your conference room booking has been updated.</p>' if email_type == 'updated' else ''}
                {'<p style="color: #dc2626;">Your conference room booking has been cancelled.</p>' if email_type == 'cancelled' else ''}
            </div>
            
            <div style="background-color: #f9fafb; padding: 20px; border-radius: 6px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #1f2937;">Booking Details:</h3>
                
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold; width: 40%;">Meeting Title:</td>
                        <td style="padding: 8px 0;">{booking.title}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Room:</td>
                        <td style="padding: 8px 0;">{booking.room.name}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Location:</td>
                        <td style="padding: 8px 0;">{booking.room.office_location.name}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Floor:</td>
                        <td style="padding: 8px 0;">{booking.room.floor}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Date:</td>
                        <td style="padding: 8px 0;">{booking.start_time.strftime('%A, %B %d, %Y')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Time:</td>
                        <td style="padding: 8px 0;">{booking.start_time.strftime('%I:%M %p')} - {booking.end_time.strftime('%I:%M %p')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Duration:</td>
                        <td style="padding: 8px 0;">{booking.duration_hours:.1f} hours</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Attendees:</td>
                        <td style="padding: 8px 0;">{booking.attendee_count} people</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Status:</td>
                        <td style="padding: 8px 0;">
                            <span style="padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold;
                                {'background-color: #d1fae5; color: #065f46;' if booking.status == 'CONFIRMED' else ''}
                                {'background-color: #fee2e2; color: #991b1b;' if booking.status == 'CANCELLED' else ''}
                                {'background-color: #fef3c7; color: #92400e;' if booking.status == 'PENDING' else ''}
                            ">
                                {booking.get_status_display()}
                            </span>
                        </td>
                    </tr>
                </table>
                
                {'<div style="margin-top: 15px; padding: 12px; background-color: #fee2e2; border-left: 4px solid #dc2626; border-radius: 4px;"><strong>Cancellation Reason:</strong><br/>' + booking.cancellation_reason + '</div>' if email_type == 'cancelled' and booking.cancellation_reason else ''}
            </div>
            
            <div style="margin: 20px 0;">
                <h4 style="color: #1f2937;">Purpose:</h4>
                <p style="background-color: #f9fafb; padding: 12px; border-radius: 4px;">{booking.purpose}</p>
            </div>
            
            {f'<div style="margin: 20px 0;"><h4 style="color: #1f2937;">Special Requirements:</h4><p style="background-color: #f9fafb; padding: 12px; border-radius: 4px;">{booking.special_requirements}</p></div>' if booking.special_requirements else ''}
            
            <div style="margin: 30px 0; padding: 15px; background-color: #eff6ff; border-radius: 6px;">
                <h4 style="margin-top: 0; color: #1e40af;">Room Amenities:</h4>
                <p>{booking.room.amenities_display}</p>
            </div>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #6b7280; font-size: 12px;">
                <p>This is an automated notification from the Conference Room Booking System.</p>
                <p>For any queries, please contact your HR department.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version
    plain_message = strip_tags(html_message)
    
    # Send email
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            html_message=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'noreply@company.com',
            recipient_list=[user_email],
            fail_silently=True,  # Don't raise exception if email fails
        )
    except Exception as e:
        # Log the error (you can use Django logging here)
        print(f"Failed to send email: {str(e)}")


@receiver(post_save, sender=RoomBooking)
def booking_created_or_updated(sender, instance, created, **kwargs):
    """
    Signal triggered when a booking is created or updated.
    Sends email notification to the user.
    """
    # Only send email for confirmed or cancelled bookings
    if instance.status in [RoomBooking.STATUS_CONFIRMED, RoomBooking.STATUS_CANCELLED]:
        if created:
            # New booking created
            send_booking_email(instance, 'created')
        else:
            # Existing booking updated
            if instance.status == RoomBooking.STATUS_CANCELLED:
                send_booking_email(instance, 'cancelled')
            else:
                # Check if start_time or end_time changed (booking rescheduled)
                # Note: For this to work properly, you'd need to track old values
                # For now, we'll send update email for any non-cancelled update
                pass  # You can enable this if needed: send_booking_email(instance, 'updated')


# Optional: Add Slack webhook notification
def send_slack_notification(booking, event_type):
    """
    Send notification to Slack webhook (optional feature).
    
    Args:
        booking: RoomBooking instance
        event_type: 'created', 'cancelled', 'updated'
    """
    import requests
    import json
    
    # Get Slack webhook URL from settings (you need to add this to settings.py)
    slack_webhook_url = getattr(settings, 'SLACK_WEBHOOK_URL', None)
    
    if not slack_webhook_url:
        return  # Skip if webhook not configured
    
    # Prepare Slack message
    color_map = {
        'created': '#10b981',  # green
        'cancelled': '#ef4444',  # red
        'updated': '#f59e0b',  # yellow
    }
    
    emoji_map = {
        'created': ':calendar:',
        'cancelled': ':x:',
        'updated': ':repeat:',
    }
    
    message = {
        "attachments": [
            {
                "color": color_map.get(event_type, '#3b82f6'),
                "title": f"{emoji_map.get(event_type, ':bell:')} Conference Room Booking {event_type.title()}",
                "fields": [
                    {
                        "title": "Meeting Title",
                        "value": booking.title,
                        "short": False
                    },
                    {
                        "title": "Room",
                        "value": f"{booking.room.name} ({booking.room.office_location.name})",
                        "short": True
                    },
                    {
                        "title": "Booked By",
                        "value": booking.booked_by.get_full_name() or booking.booked_by.username,
                        "short": True
                    },
                    {
                        "title": "Date & Time",
                        "value": f"{booking.start_time.strftime('%B %d, %Y at %I:%M %p')} - {booking.end_time.strftime('%I:%M %p')}",  # type: ignore
                        "short": False
                    },
                    {
                        "title": "Attendees",
                        "value": f"{booking.attendee_count} people",
                        "short": True
                    },
                    {
                        "title": "Status",
                        "value": booking.get_status_display(),
                        "short": True
                    }
                ],
                "footer": "Conference Room Booking System",
                "ts": int(booking.created_at.timestamp())  # type: ignore
            }
        ]
    }
    
    try:
        response = requests.post(
            slack_webhook_url,
            data=json.dumps(message),
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
    except Exception as e:
        print(f"Failed to send Slack notification: {str(e)}")


# Uncomment below if you want Slack notifications
# @receiver(post_save, sender=RoomBooking)
# def send_slack_on_booking(sender, instance, created, **kwargs):
#     """Send Slack notification on booking events."""
#     if created:
#         send_slack_notification(instance, 'created')
#     elif instance.status == RoomBooking.STATUS_CANCELLED:
#         send_slack_notification(instance, 'cancelled')
