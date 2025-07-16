"""
Comprehensive Views Module for Smart Ticketing System
Provides role-based access control and intelligent ticket management views
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import csv
import io
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, Http404, FileResponse
from django.db.models import Q, Count, Avg, F, Sum, Max, Min
from django.utils import timezone
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib.auth.decorators import user_passes_test
from django.core.cache import cache
from django.template.loader import render_to_string
from django.urls import reverse

from trueAlign.models import Support, TicketComment, TicketAttachment, TicketActivity, UserDetails
from .forms import (
    TicketCreationForm, TicketUpdateForm, CommentForm, BulkActionForm,
    TicketSearchForm, TicketAssignmentForm, TicketEscalationForm,
    TicketFeedbackForm, TicketReopenForm
)
from .utils import PermissionManager, TicketHelper, CacheManager, ReportGenerator, TicketValidator
from .logging_system import ticket_logger

logger = logging.getLogger(__name__)


def get_services():
    """
    Lazy import of services to avoid Django app loading issues
    """
    try:
        from .services import TicketService, NotificationService
        from .assignment_engine import AssignmentEngine
        from .prioritization_engine import PrioritizationEngine
        from .sla_engine import SLAEngine

        return {
            'ticket_service': TicketService(),
            'notification_service': NotificationService(),
            'assignment_engine': AssignmentEngine(),
            'prioritization_engine': PrioritizationEngine(),
            'sla_engine': SLAEngine()
        }
    except ImportError as e:
        logger.error(f"Service import error: {e}")
        return {
            'ticket_service': None,
            'notification_service': None,
            'assignment_engine': None,
            'prioritization_engine': None,
            'sla_engine': None
        }


@login_required
def dashboard(request):
    """
    Main dashboard with role-based ticket overview and analytics
    """
    try:
        services = get_services()
        user_roles = PermissionManager.get_user_roles(request.user)

        # Get filtered tickets based on user permissions
        all_tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        # Calculate statistics
        today = timezone.now().date()

        stats = {
            'total_tickets': all_tickets.count(),
            'open_tickets': all_tickets.filter(status__in=['New', 'Open', 'In Progress']).count(),
            'overdue_tickets': all_tickets.filter(
                sla_target_date__lt=timezone.now(),
                status__in=['New', 'Open', 'In Progress', 'Pending User Response']
            ).count(),
            'resolved_today': all_tickets.filter(
                status__in=['Resolved', 'Closed'],
                resolved_at__date=today
            ).count(),
            'pending_tickets': all_tickets.filter(status='Pending User Response').count(),
            'high_priority': all_tickets.filter(priority__in=['High', 'Critical']).count(),
        }

        # Priority breakdown
        priority_breakdown = {}
        for priority in Support.Priority.choices:
            priority_breakdown[priority[0]] = all_tickets.filter(priority=priority[0]).count()

        # Calculate average resolution time
        resolved_tickets = all_tickets.filter(
            status__in=['Resolved', 'Closed'],
            resolved_at__isnull=False,
            created_at__isnull=False
        )

        if resolved_tickets.exists():
            avg_resolution_time = resolved_tickets.aggregate(
                avg_time=Avg(F('resolved_at') - F('created_at'))
            )['avg_time']
            if avg_resolution_time:
                hours = avg_resolution_time.total_seconds() / 3600
                stats['avg_resolution_time'] = f"{hours:.1f}h"
            else:
                stats['avg_resolution_time'] = "N/A"
        else:
            stats['avg_resolution_time'] = "N/A"

        # Satisfaction rating
        satisfaction_avg = all_tickets.filter(
            satisfaction_rating__isnull=False
        ).aggregate(avg_rating=Avg('satisfaction_rating'))['avg_rating']
        stats['satisfaction_rating'] = f"{satisfaction_avg:.1f}/5" if satisfaction_avg else "N/A"

        # SLA compliance
        total_resolved = resolved_tickets.count()
        sla_compliant = resolved_tickets.filter(
            resolved_at__lte=F('sla_target_date')
        ).count()
        stats['sla_compliance'] = f"{(sla_compliant/total_resolved*100):.1f}%" if total_resolved > 0 else "N/A"

        # Recent tickets
        recent_tickets = all_tickets.select_related('user', 'assigned_to_user').order_by('-created_at')[:10]

        # Overdue tickets
        overdue_tickets = all_tickets.filter(
            sla_target_date__lt=timezone.now(),
            status__in=['New', 'Open', 'In Progress', 'Pending User Response']
        ).select_related('user', 'assigned_to_user')[:5]

        # SLA warnings (tickets approaching SLA breach)
        sla_warnings = []
        if user_roles.get('is_admin') or user_roles.get('is_manager'):
            approaching_sla = all_tickets.filter(
                sla_target_date__lte=timezone.now() + timedelta(hours=4),
                sla_target_date__gt=timezone.now(),
                status__in=['New', 'Open', 'In Progress']
            ).select_related('user', 'assigned_to_user')[:5]
            sla_warnings = approaching_sla

        # Agent performance (for managers and admins)
        agent_performance = []
        if user_roles.get('is_admin') or user_roles.get('is_manager'):
            agent_performance = ReportGenerator().generate_agent_performance_report(
                date_from=today - timedelta(days=30),
                date_to=today
            )

        context = {
            'stats': stats,
            'priority_breakdown': priority_breakdown,
            'recent_tickets': recent_tickets,
            'overdue_tickets': overdue_tickets,
            'sla_warnings': sla_warnings,
            'agent_performance': agent_performance,
            'user_roles': user_roles,
            'page_title': 'Support Dashboard',
            'now': timezone.now()
        }

        return render(request, 'support/dashboard.html', context)

    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.id}: {str(e)}")
        messages.error(request, "Error loading dashboard. Please try again.")
        return render(request, 'support/dashboard.html', {'error': True})


@login_required
def ticket_list(request):
    """
    Display paginated list of tickets with advanced filtering
    """
    try:
        services = get_services()
        search_form = TicketSearchForm(request.GET or None)

        # Get base queryset filtered by user permissions
        tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        # Apply search filters
        if search_form.is_valid():
            filters = search_form.cleaned_data

            # Text search
            if filters.get('search_query'):
                query = filters['search_query']
                tickets = tickets.filter(
                    Q(ticket_id__icontains=query) |
                    Q(subject__icontains=query) |
                    Q(description__icontains=query)
                )

            # Status filter
            if filters.get('status'):
                tickets = tickets.filter(status__in=filters['status'])

            # Priority filter
            if filters.get('priority'):
                tickets = tickets.filter(priority__in=filters['priority'])

            # Issue type filter
            if filters.get('issue_type'):
                tickets = tickets.filter(issue_type__in=filters['issue_type'])

            # Assignee filter
            if filters.get('assigned_to'):
                tickets = tickets.filter(assigned_to_user=filters['assigned_to'])

            # Group filter
            if filters.get('assigned_group'):
                tickets = tickets.filter(assigned_group=filters['assigned_group'])

            # Date range filter
            if filters.get('date_from'):
                tickets = tickets.filter(created_at__gte=filters['date_from'])
            if filters.get('date_to'):
                tickets = tickets.filter(created_at__lte=filters['date_to'])

            # Overdue filter
            if filters.get('overdue_only'):
                tickets = tickets.filter(
                    sla_target_date__lt=timezone.now(),
                    status__in=['New', 'Open', 'In Progress', 'Pending User Response']
                )

        # Sorting
        sort_by = request.GET.get('sort', '-created_at')
        valid_sort_fields = ['created_at', '-created_at', 'priority', '-priority', 'status', '-status', 'sla_target_date', '-sla_target_date']
        if sort_by in valid_sort_fields:
            tickets = tickets.order_by(sort_by)

        # Pagination
        paginator = Paginator(tickets.select_related('user', 'assigned_to_user'), 25)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        # Get user roles for UI customization
        user_roles = PermissionManager.get_user_roles(request.user)

        # Bulk action form
        bulk_form = BulkActionForm(user=request.user) if user_roles['is_admin'] or user_roles['is_manager'] else None

        context = {
            'tickets': page_obj,
            'search_form': search_form,
            'bulk_form': bulk_form,
            'user_roles': user_roles,
            'page_title': 'Tickets',
            'total_tickets': paginator.count
        }

        return render(request, 'support/ticket_list.html', context)

    except Exception as e:
        logger.error(f"Ticket list error for user {request.user.id}: {str(e)}")
        messages.error(request, "Error loading tickets. Please try again.")
        return render(request, 'support/ticket_list.html', {'error': True})


@login_required
def create_ticket(request):
    """
    Create new support ticket with intelligent assignment and prioritization
    """
    services = get_services()

    if request.method == 'POST':
        form = TicketCreationForm(request.POST, request.FILES, user=request.user)

        if form.is_valid():
            try:
                with transaction.atomic():
                    # Prepare ticket data
                    ticket_data = {
                        'subject': form.cleaned_data['subject'],
                        'description': form.cleaned_data['description'],
                        'issue_type': form.cleaned_data['issue_type'],
                        'priority': form.cleaned_data['priority'],
                        'department': form.cleaned_data['department'],
                        'location': form.cleaned_data['location'],
                        'asset_id': form.cleaned_data['asset_id']
                    }

                    # Handle attachments
                    attachments = request.FILES.getlist('attachments')

                    # Create ticket using service
                    if services['ticket_service']:
                        ticket = services['ticket_service'].create_ticket(
                            user=request.user,
                            ticket_data=ticket_data,
                            attachments=attachments
                        )
                    else:
                        # Fallback ticket creation
                        ticket = Support.objects.create(
                            user=request.user,
                            **ticket_data
                        )

                        # Generate ticket ID
                        ticket.ticket_id = TicketHelper.generate_ticket_id()
                        ticket.save()

                        # Handle attachments
                        for attachment in attachments:
                            TicketAttachment.objects.create(
                                ticket=ticket,
                                file=attachment,
                                uploaded_by=request.user
                            )

                    # Add CC users
                    cc_users = form.cleaned_data.get('cc_users', [])
                    if cc_users:
                        ticket.cc_users.set(cc_users)

                    # Auto-assign using assignment engine
                    if services['assignment_engine'] and not ticket.assigned_to_user:
                        try:
                            assigned_agent, reason = services['assignment_engine'].assign_ticket(ticket)
                            if assigned_agent:
                                ticket.assigned_to_user = assigned_agent
                                ticket.save()

                                # Log assignment
                                TicketActivity.objects.create(
                                    ticket=ticket,
                                    action=TicketActivity.Action.ASSIGNED,
                                    user=request.user,
                                    details=f"Auto-assigned to {assigned_agent.get_full_name()}: {reason}"
                                )
                        except Exception as e:
                            logger.warning(f"Auto-assignment failed: {str(e)}")

                    # Recalculate priority using prioritization engine
                    if services['prioritization_engine']:
                        try:
                            new_priority, factors = services['prioritization_engine'].calculate_priority(ticket)
                            if new_priority != ticket.priority:
                                old_priority = ticket.priority
                                ticket.priority = new_priority
                                ticket.save()

                                # Log priority change
                                TicketActivity.objects.create(
                                    ticket=ticket,
                                    action=TicketActivity.Action.PRIORITY_CHANGED,
                                    user=request.user,
                                    details=f"Priority changed from {old_priority} to {new_priority} (Smart prioritization)"
                                )
                        except Exception as e:
                            logger.warning(f"Smart prioritization failed: {str(e)}")

                    # Set SLA target
                    if services['sla_engine']:
                        try:
                            sla_target = services['sla_engine'].calculate_sla_target(ticket)
                            ticket.sla_target_date = sla_target
                            ticket.save()
                        except Exception as e:
                            logger.warning(f"SLA calculation failed: {str(e)}")

                    # Send notifications
                    if services['notification_service']:
                        try:
                            # Notify assigned agent
                            if ticket.assigned_to_user:
                                services['notification_service'].send_ticket_notification(
                                    ticket, 'assigned', [ticket.assigned_to_user]
                                )

                            # Notify CC users
                            if cc_users:
                                services['notification_service'].send_ticket_notification(
                                    ticket, 'cc_added', cc_users
                                )
                        except Exception as e:
                            logger.warning(f"Notification sending failed: {str(e)}")

                    # Log ticket creation
                    ticket_logger.log_ticket_creation(request.user, ticket)

                    messages.success(
                        request,
                        f'Ticket {ticket.ticket_id} created successfully! '
                        f'Priority: {ticket.priority}'
                        f'{", Assigned to: " + ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else ""}'
                    )

                    return redirect('support:ticket_detail', ticket_id=ticket.ticket_id)

            except Exception as e:
                logger.error(f"Ticket creation error: {str(e)}")
                messages.error(request, f"Error creating ticket: {str(e)}")

    else:
        form = TicketCreationForm(user=request.user)

    context = {
        'form': form,
        'page_title': 'Create New Ticket'
    }

    return render(request, 'support/create_ticket.html', context)


@login_required
def ticket_detail(request, ticket_id):
    """
    Display detailed ticket information with comments and activities
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_view_ticket(request.user, ticket):
            raise PermissionDenied("You don't have permission to view this ticket")

        # Get user roles and permissions
        user_roles = PermissionManager.get_user_roles(request.user)
        can_edit = PermissionManager.can_edit_ticket(request.user, ticket)
        can_assign = PermissionManager.can_assign_ticket(request.user, ticket)
        can_escalate = PermissionManager.can_escalate_ticket(request.user, ticket)
        can_delete = PermissionManager.can_delete_ticket(request.user, ticket)
        can_view_internal = PermissionManager.can_view_internal_comments(request.user, ticket)

        # Get ticket comments
        comments = TicketComment.objects.filter(ticket=ticket)
        if not can_view_internal:
            comments = comments.filter(is_internal=False)
        comments = comments.select_related('user').order_by('created_at')

        # Get ticket activities
        activities = TicketActivity.objects.filter(ticket=ticket).select_related('user').order_by('-created_at')

        # Get attachments
        attachments = TicketAttachment.objects.filter(ticket=ticket).select_related('uploaded_by')

        # Get related tickets
        related_tickets = Support.objects.filter(
            Q(user=ticket.user) | Q(subject__icontains=ticket.subject[:20]),
            is_deleted=False
        ).exclude(id=ticket.id)[:5]

        # Get assignable users
        assignable_users = PermissionManager.get_assignable_users(request.user, ticket)

        # Get SLA information
        sla_info = {}
        if services['sla_engine']:
            try:
                sla_info = services['sla_engine'].get_sla_status(ticket)
            except Exception as e:
                logger.warning(f"SLA info retrieval failed: {str(e)}")

        # Prepare forms
        comment_form = CommentForm()
        if can_edit:
            update_form = TicketUpdateForm(instance=ticket, user=request.user)
        else:
            update_form = None

        if can_assign:
            assignment_form = TicketAssignmentForm(ticket=ticket, user=request.user)
        else:
            assignment_form = None

        if can_escalate:
            escalation_form = TicketEscalationForm(ticket=ticket)
        else:
            escalation_form = None

        # Feedback form (for ticket creator when ticket is resolved)
        feedback_form = None
        if ticket.user == request.user and ticket.status in ['Resolved', 'Closed'] and not ticket.feedback_submitted:
            feedback_form = TicketFeedbackForm()

        # Reopen form (for ticket creator when ticket is closed)
        reopen_form = None
        if ticket.user == request.user and ticket.status == 'Closed':
            reopen_form = TicketReopenForm()

        # Calculate time metrics
        time_metrics = {
            'age': TicketHelper.format_duration(timezone.now() - ticket.created_at),
            'age_category': TicketHelper.get_ticket_age_category(ticket),
            'time_to_first_response': None,
            'time_to_resolution': None
        }

        # First response time
        first_response = comments.filter(user__ne=ticket.user).first()
        if first_response:
            time_metrics['time_to_first_response'] = TicketHelper.format_duration(
                first_response.created_at - ticket.created_at
            )

        # Resolution time
        if ticket.resolved_at:
            time_metrics['time_to_resolution'] = TicketHelper.format_duration(
                ticket.resolved_at - ticket.created_at
            )

        context = {
            'ticket': ticket,
            'comments': comments,
            'activities': activities,
            'attachments': attachments,
            'related_tickets': related_tickets,
            'assignable_users': assignable_users,
            'sla_info': sla_info,
            'time_metrics': time_metrics,
            'user_roles': user_roles,
            'can_edit': can_edit,
            'can_assign': can_assign,
            'can_escalate': can_escalate,
            'can_delete': can_delete,
            'can_view_internal': can_view_internal,
            'comment_form': comment_form,
            'update_form': update_form,
            'assignment_form': assignment_form,
            'escalation_form': escalation_form,
            'feedback_form': feedback_form,
            'reopen_form': reopen_form,
            'page_title': f'Ticket {ticket.ticket_id}'
        }

        return render(request, 'support/ticket_detail.html', context)

    except Support.DoesNotExist:
        messages.error(request, "Ticket not found")
        return redirect('support:ticket_list')
    except PermissionDenied as e:
        messages.error(request, str(e))
        return redirect('support:ticket_list')
    except Exception as e:
        logger.error(f"Ticket detail error: {str(e)}")
        messages.error(request, "Error loading ticket details")
        return redirect('support:ticket_list')


@login_required
@require_POST
def add_comment(request, ticket_id):
    """
    Add comment to a ticket
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_view_ticket(request.user, ticket):
            raise PermissionDenied("You don't have permission to comment on this ticket")

        form = CommentForm(request.POST, request.FILES)

        if form.is_valid():
            with transaction.atomic():
                comment = form.save(commit=False)
                comment.ticket = ticket
                comment.user = request.user
                comment.save()

                # Handle attachments
                attachments = request.FILES.getlist('attachments')
                for attachment in attachments:
                    TicketAttachment.objects.create(
                        ticket=ticket,
                        file=attachment,
                        uploaded_by=request.user,
                        description=f"Attachment from comment by {request.user.get_full_name()}"
                    )

                # Update ticket status if needed
                if ticket.status == 'Pending User Response' and ticket.user == request.user:
                    ticket.status = 'Open'
                    ticket.save()

                # Log activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.COMMENT_ADDED,
                    user=request.user,
                    details=f"Comment added{'(Internal)' if comment.is_internal else ''}"
                )

                # Send notifications
                if services['notification_service']:
                    try:
                        recipients = []
                        if ticket.assigned_to_user and ticket.assigned_to_user != request.user:
                            recipients.append(ticket.assigned_to_user)
                        if ticket.user != request.user:
                            recipients.append(ticket.user)

                        # Add CC users
                        cc_users = ticket.cc_users.exclude(id=request.user.id)
                        recipients.extend(cc_users)

                        if recipients:
                            services['notification_service'].send_ticket_notification(
                                ticket, 'comment_added', recipients
                            )
                    except Exception as e:
                        logger.warning(f"Notification sending failed: {str(e)}")

                messages.success(request, "Comment added successfully")

        else:
            messages.error(request, "Error adding comment. Please check your input.")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Add comment error: {str(e)}")
        messages.error(request, "Error adding comment")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def update_ticket(request, ticket_id):
    """
    Update ticket information
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_edit_ticket(request.user, ticket):
            raise PermissionDenied("You don't have permission to edit this ticket")

        form = TicketUpdateForm(request.POST, instance=ticket, user=request.user)

        if form.is_valid():
            with transaction.atomic():
                # Track changes
                changes = []
                old_values = {}

                # Store old values for comparison
                for field in ['subject', 'description', 'status', 'priority', 'assigned_to_user', 'assigned_group']:
                    old_values[field] = getattr(ticket, field)

                # Save the updated ticket
                updated_ticket = form.save()

                # Check what changed and log activities
                for field, old_value in old_values.items():
                    new_value = getattr(updated_ticket, field)
                    if old_value != new_value:
                        changes.append(f"{field}: {old_value} → {new_value}")

                        # Log specific activities
                        if field == 'status':
                            TicketActivity.objects.create(
                                ticket=updated_ticket,
                                action=TicketActivity.Action.STATUS_CHANGED,
                                user=request.user,
                                details=f"Status changed from {old_value} to {new_value}"
                            )
                        elif field == 'priority':
                            TicketActivity.objects.create(
                                ticket=updated_ticket,
                                action=TicketActivity.Action.PRIORITY_CHANGED,
                                user=request.user,
                                details=f"Priority changed from {old_value} to {new_value}"
                            )
                        elif field == 'assigned_to_user':
                            TicketActivity.objects.create(
                                ticket=updated_ticket,
                                action=TicketActivity.Action.ASSIGNED,
                                user=request.user,
                                details=f"Assigned to {new_value.get_full_name() if new_value else 'Unassigned'}"
                            )

                # Update resolved_at timestamp if status changed to resolved/closed
                if updated_ticket.status in ['Resolved', 'Closed'] and old_values['status'] not in ['Resolved', 'Closed']:
                    updated_ticket.resolved_at = timezone.now()
                    updated_ticket.save()

                # Send notifications for important changes
                if services['notification_service'] and changes:
                    try:
                        recipients = []
                        if updated_ticket.assigned_to_user and updated_ticket.assigned_to_user != request.user:
                            recipients.append(updated_ticket.assigned_to_user)
                        if updated_ticket.user != request.user:
                            recipients.append(updated_ticket.user)

                        if recipients:
                            services['notification_service'].send_ticket_notification(
                                updated_ticket, 'updated', recipients
                            )
                    except Exception as e:
                        logger.warning(f"Notification sending failed: {str(e)}")

                if changes:
                    messages.success(request, f"Ticket updated successfully. Changes: {', '.join(changes[:3])}")
                else:
                    messages.info(request, "No changes made to the ticket")

        else:
            messages.error(request, "Error updating ticket. Please check your input.")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Update ticket error: {str(e)}")
        messages.error(request, "Error updating ticket")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def assign_ticket(request, ticket_id):
    """
    Assign ticket to a user
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_assign_ticket(request.user, ticket):
            raise PermissionDenied("You don't have permission to assign this ticket")

        form = TicketAssignmentForm(request.POST, ticket=ticket, user=request.user)

        if form.is_valid():
            with transaction.atomic():
                old_assignee = ticket.assigned_to_user
                new_assignee = form.cleaned_data['assigned_to_user']
                assignment_reason = form.cleaned_data.get('assignment_reason', '')

                ticket.assigned_to_user = new_assignee
                ticket.assigned_group = form.cleaned_data.get('assigned_group', ticket.assigned_group)
                ticket.save()

                # Log activity
                details = f"Assigned to {new_assignee.get_full_name() if new_assignee else 'Unassigned'}"
                if assignment_reason:
                    details += f" - Reason: {assignment_reason}"
                if old_assignee:
                    details += f" (Previously: {old_assignee.get_full_name()})"

                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.ASSIGNED,
                    user=request.user,
                    details=details
                )

                # Send notifications
                if services['notification_service']:
                    try:
                        recipients = []
                        if new_assignee and new_assignee != request.user:
                            recipients.append(new_assignee)
                        if old_assignee and old_assignee != request.user and old_assignee != new_assignee:
                            recipients.append(old_assignee)

                        if recipients:
                            services['notification_service'].send_ticket_notification(
                                ticket, 'assigned', recipients
                            )
                    except Exception as e:
                        logger.warning(f"Notification sending failed: {str(e)}")

                messages.success(
                    request,
                    f"Ticket assigned to {new_assignee.get_full_name() if new_assignee else 'Unassigned'}"
                )

        else:
            messages.error(request, "Error assigning ticket. Please check your input.")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Assign ticket error: {str(e)}")
        messages.error(request, "Error assigning ticket")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def escalate_ticket(request, ticket_id):
    """
    Escalate ticket to higher priority or management
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_escalate_ticket(request.user, ticket):
            raise PermissionDenied("You don't have permission to escalate this ticket")

        form = TicketEscalationForm(request.POST, ticket=ticket)

        if form.is_valid():
            with transaction.atomic():
                escalation_reason = form.cleaned_data['escalation_reason']
                escalation_level = form.cleaned_data.get('escalation_level', 'Management')

                # Update ticket priority if not already at highest level
                if ticket.priority != 'Critical':
                    old_priority = ticket.priority
                    ticket.priority = 'Critical'
                    ticket.save()

                    # Log priority escalation
                    TicketActivity.objects.create(
                        ticket=ticket,
                        action=TicketActivity.Action.PRIORITY_CHANGED,
                        user=request.user,
                        details=f"Priority escalated from {old_priority} to Critical due to escalation"
                    )

                # Log escalation
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.ESCALATED,
                    user=request.user,
                    details=f"Escalated to {escalation_level} - Reason: {escalation_reason}"
                )

                # Reassign if needed using assignment engine
                if services['assignment_engine']:
                    try:
                        new_assignee, reason = services['assignment_engine'].assign_ticket(ticket, escalation_level)
                        if new_assignee and new_assignee != ticket.assigned_to_user:
                            ticket.assigned_to_user = new_assignee
                            ticket.save()

                            TicketActivity.objects.create(
                                ticket=ticket,
                                action=TicketActivity.Action.ASSIGNED,
                                user=request.user,
                                details=f"Reassigned to {new_assignee.get_full_name()} due to escalation"
                            )
                    except Exception as e:
                        logger.warning(f"Auto-reassignment during escalation failed: {str(e)}")

                # Send notifications
                if services['notification_service']:
                    try:
                        # Notify managers and admin
                        managers = User.objects.filter(groups__name='Manager', is_active=True)
                        admins = User.objects.filter(groups__name='Admin', is_active=True)
                        recipients = list(managers) + list(admins)

                        if ticket.assigned_to_user:
                            recipients.append(ticket.assigned_to_user)

                        services['notification_service'].send_ticket_notification(
                            ticket, 'escalated', recipients
                        )
                    except Exception as e:
                        logger.warning(f"Escalation notification failed: {str(e)}")

                messages.success(request, "Ticket escalated successfully!")
        else:
            messages.error(request, "Error escalating ticket. Please check your input.")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Escalate ticket error: {str(e)}")
        messages.error(request, "Error escalating ticket")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def reopen_ticket(request, ticket_id):
    """
    Reopen a resolved/closed ticket
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions (only ticket creator can reopen)
        if ticket.user != request.user:
            raise PermissionDenied("Only the ticket creator can reopen this ticket")

        if ticket.status not in ['Resolved', 'Closed']:
            messages.error(request, "Only resolved or closed tickets can be reopened")
            return redirect('support:ticket_detail', ticket_id=ticket_id)

        form = TicketReopenForm(request.POST)

        if form.is_valid():
            with transaction.atomic():
                reopen_reason = form.cleaned_data['reopen_reason']

                # Update ticket status
                ticket.status = 'Open'
                ticket.resolved_at = None
                ticket.save()

                # Log reopening
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.REOPENED,
                    user=request.user,
                    details=f"Ticket reopened - Reason: {reopen_reason}"
                )

                # Send notifications
                if services['notification_service']:
                    try:
                        recipients = []
                        if ticket.assigned_to_user:
                            recipients.append(ticket.assigned_to_user)

                        # Notify managers
                        managers = User.objects.filter(groups__name='Manager', is_active=True)
                        recipients.extend(managers)

                        services['notification_service'].send_ticket_notification(
                            ticket, 'reopened', recipients
                        )
                    except Exception as e:
                        logger.warning(f"Reopen notification failed: {str(e)}")

                messages.success(request, "Ticket reopened successfully!")
        else:
            messages.error(request, "Error reopening ticket. Please check your input.")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Reopen ticket error: {str(e)}")
        messages.error(request, "Error reopening ticket")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def close_ticket(request, ticket_id):
    """
    Close a ticket
    """
    try:
        services = get_services()
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_change_status(request.user, ticket, 'Closed'):
            raise PermissionDenied("You don't have permission to close this ticket")

        with transaction.atomic():
            old_status = ticket.status
            ticket.status = 'Closed'
            ticket.resolved_at = timezone.now()
            ticket.save()

            # Log closure
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.STATUS_CHANGED,
                user=request.user,
                details=f"Ticket closed (was {old_status})"
            )

            # Send notifications
            if services['notification_service']:
                try:
                    recipients = [ticket.user]
                    if ticket.assigned_to_user and ticket.assigned_to_user != request.user:
                        recipients.append(ticket.assigned_to_user)

                    services['notification_service'].send_ticket_notification(
                        ticket, 'closed', recipients
                    )
                except Exception as e:
                    logger.warning(f"Close notification failed: {str(e)}")

            messages.success(request, "Ticket closed successfully!")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Close ticket error: {str(e)}")
        messages.error(request, "Error closing ticket")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def submit_feedback(request, ticket_id):
    """
    Submit feedback for a resolved ticket
    """
    try:
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions (only ticket creator can submit feedback)
        if ticket.user != request.user:
            raise PermissionDenied("You can only submit feedback for your own tickets")

        if ticket.status not in ['Resolved', 'Closed']:
            messages.error(request, "You can only submit feedback for resolved or closed tickets")
            return redirect('support:ticket_detail', ticket_id=ticket_id)

        form = TicketFeedbackForm(request.POST)

        if form.is_valid():
            with transaction.atomic():
                ticket.satisfaction_rating = form.cleaned_data['satisfaction_rating']
                ticket.feedback = form.cleaned_data['feedback']
                ticket.feedback_submitted = True
                ticket.save()

                # Log feedback submission
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.FEEDBACK_SUBMITTED,
                    user=request.user,
                    details=f"Feedback submitted - Rating: {ticket.satisfaction_rating}/5"
                )

                messages.success(request, "Thank you for your feedback!")
        else:
            messages.error(request, "Error submitting feedback. Please check your input.")

        return redirect('support:ticket_detail', ticket_id=ticket_id)

    except Exception as e:
        logger.error(f"Submit feedback error: {str(e)}")
        messages.error(request, "Error submitting feedback")
        return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_POST
def bulk_actions(request):
    """
    Handle bulk actions on tickets
    """
    try:
        services = get_services()

        # Check permissions
        user_roles = PermissionManager.get_user_roles(request.user)
        if not (user_roles['is_admin'] or user_roles['is_manager']):
            raise PermissionDenied("You don't have permission to perform bulk actions")

        form = BulkActionForm(request.POST, user=request.user)

        if form.is_valid():
            action = form.cleaned_data['action']
            ticket_ids = form.cleaned_data['ticket_ids']

            # Get tickets user can modify
            tickets = PermissionManager.get_filtered_tickets_queryset(request.user).filter(
                ticket_id__in=ticket_ids
            )

            updated_count = 0

            with transaction.atomic():
                for ticket in tickets:
                    try:
                        if action == 'assign':
                            assignee = form.cleaned_data.get('assigned_to')
                            if assignee and PermissionManager.can_assign_ticket(request.user, ticket):
                                ticket.assigned_to_user = assignee
                                ticket.save()
                                updated_count += 1

                                TicketActivity.objects.create(
                                    ticket=ticket,
                                    action=TicketActivity.Action.ASSIGNED,
                                    user=request.user,
                                    details=f"Bulk assigned to {assignee.get_full_name()}"
                                )

                        elif action == 'status_change':
                            new_status = form.cleaned_data.get('status')
                            if new_status and PermissionManager.can_change_status(request.user, ticket, new_status):
                                old_status = ticket.status
                                ticket.status = new_status
                                ticket.save()
                                updated_count += 1

                                TicketActivity.objects.create(
                                    ticket=ticket,
                                    action=TicketActivity.Action.STATUS_CHANGED,
                                    user=request.user,
                                    details=f"Bulk status change from {old_status} to {new_status}"
                                )

                        elif action == 'priority_change':
                            new_priority = form.cleaned_data.get('priority')
                            if new_priority and PermissionManager.can_edit_ticket(request.user, ticket):
                                old_priority = ticket.priority
                                ticket.priority = new_priority
                                ticket.save()
                                updated_count += 1

                                TicketActivity.objects.create(
                                    ticket=ticket,
                                    action=TicketActivity.Action.PRIORITY_CHANGED,
                                    user=request.user,
                                    details=f"Bulk priority change from {old_priority} to {new_priority}"
                                )

                    except Exception as e:
                        logger.warning(f"Bulk action failed for ticket {ticket.ticket_id}: {str(e)}")
                        continue

            messages.success(request, f"Bulk action completed successfully! {updated_count} tickets updated.")
        else:
            messages.error(request, "Error processing bulk action. Please check your input.")

        return redirect('support:ticket_list')

    except Exception as e:
        logger.error(f"Bulk actions error: {str(e)}")
        messages.error(request, "Error performing bulk action")
        return redirect('support:ticket_list')


@login_required
def analytics(request):
    """
    Display analytics and reports
    """
    try:
        # Check permissions
        user_roles = PermissionManager.get_user_roles(request.user)
        if not (user_roles['is_admin'] or user_roles['is_manager']):
            raise PermissionDenied("You don't have permission to view analytics")

        # Get filtered tickets
        tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        # Generate analytics data
        analytics_data = ReportGenerator().generate_ticket_summary(
            tickets=tickets,
            user=request.user
        )

        context = {
            'analytics': analytics_data,
            'user_roles': user_roles,
            'page_title': 'Support Analytics'
        }

        return render(request, 'support/analytics.html', context)

    except PermissionDenied:
        messages.error(request, "You don't have permission to view analytics")
        return redirect('support:dashboard')
    except Exception as e:
        logger.error(f"Analytics error: {str(e)}")
        messages.error(request, "Error loading analytics")
        return redirect('support:dashboard')


@login_required
def api_ticket_stats(request):
    """
    API endpoint for ticket statistics
    """
    try:
        tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        stats = {
            'total': tickets.count(),
            'open': tickets.filter(status__in=['New', 'Open', 'In Progress']).count(),
            'resolved': tickets.filter(status='Resolved').count(),
            'closed': tickets.filter(status='Closed').count(),
            'overdue': tickets.filter(
                sla_target_date__lt=timezone.now(),
                status__in=['New', 'Open', 'In Progress']
            ).count(),
            'high_priority': tickets.filter(priority__in=['High', 'Critical']).count(),
        }

        return JsonResponse(stats)

    except Exception as e:
        logger.error(f"API ticket stats error: {str(e)}")
        return JsonResponse({'error': 'Failed to get ticket statistics'}, status=500)


@login_required
def api_assignable_users(request, ticket_id):
    """
    API endpoint for getting assignable users for a ticket
    """
    try:
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_assign_ticket(request.user, ticket):
            return JsonResponse({'error': 'Permission denied'}, status=403)

        assignable_users = PermissionManager.get_assignable_users(request.user, ticket)

        users_data = []
        for user in assignable_users:
            workload = TicketHelper.get_workload_indicator(user)
            users_data.append({
                'id': user.id,
                'name': user.get_full_name() or user.username,
                'email': user.email,
                'workload': workload
            })

        return JsonResponse({'users': users_data})

    except Exception as e:
        logger.error(f"API assignable users error: {str(e)}")
        return JsonResponse({'error': 'Failed to get assignable users'}, status=500)


@login_required
def api_ticket_activities(request, ticket_id):
    """
    API endpoint for getting ticket activities
    """
    try:
        ticket = get_object_or_404(Support, ticket_id=ticket_id, is_deleted=False)

        # Check permissions
        if not PermissionManager.can_view_ticket(request.user, ticket):
            return JsonResponse({'error': 'Permission denied'}, status=403)

        activities = TicketActivity.objects.filter(ticket=ticket).select_related('user').order_by('-timestamp')[:20]

        activities_data = []
        for activity in activities:
            activities_data.append({
                'id': activity.id,
                'action': activity.action,
                'details': activity.details,
                'timestamp': activity.timestamp.isoformat(),
                'user': activity.user.get_full_name() if activity.user else 'System'
            })

        return JsonResponse({'activities': activities_data})

    except Exception as e:
        logger.error(f"API ticket activities error: {str(e)}")
        return JsonResponse({'error': 'Failed to get ticket activities'}, status=500)


@login_required
def download_attachment(request, attachment_id):
    """
    Download a ticket attachment
    """
    try:
        attachment = get_object_or_404(TicketAttachment, id=attachment_id)

        # Check permissions
        if not PermissionManager.can_view_ticket(request.user, attachment.ticket):
            raise PermissionDenied("You don't have permission to download this attachment")

        # Create response with file content
        response = FileResponse(
            attachment.file.open(),
            content_type=attachment.file_type or 'application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{attachment.original_filename or attachment.file.name}"'

        return response

    except Exception as e:
        logger.error(f"Download attachment error: {str(e)}")
        messages.error(request, "Error downloading attachment")
        return redirect('support:ticket_list')


@login_required
@require_POST
def delete_attachment(request, attachment_id):
    """
    Delete a ticket attachment
    """
    try:
        attachment = get_object_or_404(TicketAttachment, id=attachment_id)

        # Check permissions
        if not PermissionManager.can_edit_ticket(request.user, attachment.ticket):
            raise PermissionDenied("You don't have permission to delete this attachment")

        # Soft delete
        attachment.is_deleted = True
        attachment.save()

        # Log activity
        TicketActivity.objects.create(
            ticket=attachment.ticket,
            action=TicketActivity.Action.ATTACHMENT_DELETED,
            user=request.user,
            details=f"Attachment deleted: {attachment.original_filename or attachment.file.name}"
        )

        messages.success(request, "Attachment deleted successfully")
        return JsonResponse({'success': True})

    except Exception as e:
        logger.error(f"Delete attachment error: {str(e)}")
        return JsonResponse({'error': 'Failed to delete attachment'}, status=500)


@login_required
def search_tickets(request):
    """
    Advanced ticket search
    """
    try:
        form = TicketSearchForm(request.GET or None)
        tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        if form.is_valid():
            search_query = form.cleaned_data.get('search_query')
            if search_query:
                tickets = tickets.filter(
                    Q(ticket_id__icontains=search_query) |
                    Q(subject__icontains=search_query) |
                    Q(description__icontains=search_query)
                )

            # Apply other filters
            if form.cleaned_data.get('status'):
                tickets = tickets.filter(status__in=form.cleaned_data['status'])
            if form.cleaned_data.get('priority'):
                tickets = tickets.filter(priority__in=form.cleaned_data['priority'])
            if form.cleaned_data.get('assigned_to'):
                tickets = tickets.filter(assigned_to_user=form.cleaned_data['assigned_to'])
            if form.cleaned_data.get('date_from'):
                tickets = tickets.filter(created_at__gte=form.cleaned_data['date_from'])
            if form.cleaned_data.get('date_to'):
                tickets = tickets.filter(created_at__lte=form.cleaned_data['date_to'])

        # Pagination
        paginator = Paginator(tickets.select_related('user', 'assigned_to_user'), 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        context = {
            'form': form,
            'tickets': page_obj,
            'page_title': 'Search Tickets'
        }

        return render(request, 'support/search_tickets.html', context)

    except Exception as e:
        logger.error(f"Search tickets error: {str(e)}")
        messages.error(request, "Error searching tickets")
        return render(request, 'support/search_tickets.html', {'form': TicketSearchForm()})


@login_required
def export_tickets(request):
    """
    Export tickets to CSV
    """
    try:
        # Check permissions
        user_roles = PermissionManager.get_user_roles(request.user)
        if not (user_roles['is_admin'] or user_roles['is_manager']):
            raise PermissionDenied("You don't have permission to export tickets")

        # Get tickets to export
        tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        # Apply filters if provided
        if request.GET.get('status'):
            tickets = tickets.filter(status=request.GET.get('status'))
        if request.GET.get('priority'):
            tickets = tickets.filter(priority=request.GET.get('priority'))
        if request.GET.get('date_from'):
            tickets = tickets.filter(created_at__gte=request.GET.get('date_from'))
        if request.GET.get('date_to'):
            tickets = tickets.filter(created_at__lte=request.GET.get('date_to'))

        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="tickets.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Ticket ID', 'Subject', 'Status', 'Priority', 'Created',
            'Assigned To', 'Created By', 'Department', 'Issue Type'
        ])

        for ticket in tickets.select_related('user', 'assigned_to_user'):
            writer.writerow([
                ticket.ticket_id,
                ticket.subject,
                ticket.status,
                ticket.priority,
                ticket.created_at.strftime('%Y-%m-%d %H:%M'),
                ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'Unassigned',
                ticket.user.get_full_name(),
                ticket.department or '',
                ticket.issue_type or ''
            ])

        return response

    except Exception as e:
        logger.error(f"Export tickets error: {str(e)}")
        messages.error(request, "Error exporting tickets")
        return redirect('support:ticket_list')


@login_required
def sla_monitoring(request):
    """
    SLA monitoring dashboard
    """
    try:
        services = get_services()

        # Check permissions
        user_roles = PermissionManager.get_user_roles(request.user)
        if not (user_roles['is_admin'] or user_roles['is_manager']):
            raise PermissionDenied("You don't have permission to view SLA monitoring")

        tickets = PermissionManager.get_filtered_tickets_queryset(request.user)

        # Calculate SLA metrics
        total_tickets = tickets.count()
        overdue_tickets = tickets.filter(
            sla_target_date__lt=timezone.now(),
            status__in=['New', 'Open', 'In Progress']
        )

        approaching_sla = tickets.filter(
            sla_target_date__lte=timezone.now() + timedelta(hours=4),
            sla_target_date__gt=timezone.now(),
            status__in=['New', 'Open', 'In Progress']
        )

        resolved_tickets = tickets.filter(
            status__in=['Resolved', 'Closed'],
            resolved_at__isnull=False
        )

        sla_compliant = resolved_tickets.filter(
            resolved_at__lte=F('sla_target_date')
        ).count()

        sla_compliance_rate = (sla_compliant / resolved_tickets.count() * 100) if resolved_tickets.count() > 0 else 0

        sla_data = {
            'total_tickets': total_tickets,
            'overdue_count': overdue_tickets.count(),
            'approaching_count': approaching_sla.count(),
            'compliance_rate': round(sla_compliance_rate, 2),
            'overdue_tickets': overdue_tickets.select_related('user', 'assigned_to_user')[:10],
            'approaching_tickets': approaching_sla.select_related('user', 'assigned_to_user')[:10],
        }

        context = {
            'sla_data': sla_data,
            'user_roles': user_roles,
            'page_title': 'SLA Monitoring'
        }

        return render(request, 'support/sla_monitoring.html', context)

    except Exception as e:
        logger.error(f"SLA monitoring error: {str(e)}")
        messages.error(request, "Error loading SLA monitoring")
        return redirect('support:dashboard')


@login_required
@require_POST
def run_sla_check(request):
    """
    Manual SLA check trigger
    """
    try:
        services = get_services()

        # Check permissions
        user_roles = PermissionManager.get_user_roles(request.user)
        if not (user_roles['is_admin'] or user_roles['is_manager']):
            raise PermissionDenied("You don't have permission to run SLA checks")

        # Run SLA check
        if services['sla_engine']:
            result = services['sla_engine'].run_sla_monitoring()
            if result.get('success'):
                messages.success(request, f"SLA check completed. {result.get('processed_count', 0)} tickets processed.")
            else:
                messages.error(request, f"Error running SLA check: {result.get('error', 'Unknown error')}")
        else:
            messages.warning(request, "SLA engine not available")

        return redirect('support:sla_monitoring')

    except Exception as e:
        logger.error(f"Run SLA check error: {str(e)}")
        messages.error(request, "Error running SLA check")
        return redirect('support:sla_monitoring')


@login_required
def agent_dashboard(request):
    """
    Agent-specific dashboard
    """
    try:
        # Get agent's assigned tickets
        assigned_tickets = PermissionManager.get_filtered_tickets_queryset(request.user).filter(
            assigned_to_user=request.user
        )

        # Get workload metrics
        workload_stats = {
            'total_assigned': assigned_tickets.count(),
            'open_tickets': assigned_tickets.filter(status__in=['New', 'Open', 'In Progress']).count(),
            'overdue_tickets': assigned_tickets.filter(
                sla_target_date__lt=timezone.now(),
                status__in=['New', 'Open', 'In Progress']
            ).count(),
            'resolved_today': assigned_tickets.filter(
                status__in=['Resolved', 'Closed'],
                resolved_at__date=timezone.now().date()
            ).count(),
        }

        # Get performance metrics
        performance_data = ReportGenerator().generate_agent_performance_report(
            user=request.user,
            date_from=timezone.now().date() - timedelta(days=30),
            date_to=timezone.now().date()
        )

        context = {
            'assigned_tickets': assigned_tickets.select_related('user')[:10],
            'workload_stats': workload_stats,
            'performance_data': performance_data,
            'page_title': 'Agent Dashboard'
        }

        return render(request, 'support/agent_dashboard.html', context)

    except Exception as e:
        logger.error(f"Agent dashboard error: {str(e)}")
        messages.error(request, "Error loading agent dashboard")
        return redirect('support:dashboard')


@login_required
def user_guide(request):
    """
    User guide and help documentation
    """
    try:
        user_roles = PermissionManager.get_user_roles(request.user)

        context = {
            'user_roles': user_roles,
            'page_title': 'User Guide'
        }

        return render(request, 'support/user_guide.html', context)

    except Exception as e:
        logger.error(f"User guide error: {str(e)}")
        messages.error(request, "Error loading user guide")
        return redirect('support:dashboard')


@login_required
def my_tickets(request):
    """
    User's personal tickets view
    """
    try:
        # Get user's own tickets
        user_tickets = PermissionManager.get_filtered_tickets_queryset(request.user).filter(
            user=request.user
        )

        # Get statistics
        stats = {
            'total_tickets': user_tickets.count(),
            'open_tickets': user_tickets.filter(status__in=['New', 'Open', 'In Progress']).count(),
            'resolved_tickets': user_tickets.filter(status='Resolved').count(),
            'closed_tickets': user_tickets.filter(status='Closed').count(),
        }

        # Calculate average response time
        resolved_tickets = user_tickets.filter(
            status__in=['Resolved', 'Closed'],
            resolved_at__isnull=False
        )

        if resolved_tickets.exists():
            avg_resolution_time = resolved_tickets.aggregate(
                avg_time=Avg(F('resolved_at') - F('created_at'))
            )['avg_time']

            if avg_resolution_time:
                hours = avg_resolution_time.total_seconds() / 3600
                stats['avg_response_time'] = f"{hours:.1f}h"
            else:
                stats['avg_response_time'] = "N/A"
        else:
            stats['avg_response_time'] = "N/A"

        # Pagination
        paginator = Paginator(user_tickets.select_related('assigned_to_user'), 20)
        page_number = request.GET.get('page')
        tickets = paginator.get_page(page_number)

        context = {
            'tickets': tickets,
            'stats': stats,
            'page_title': 'My Tickets'
        }

        return render(request, 'support/my_tickets.html', context)

    except Exception as e:
        logger.error(f"My tickets error: {str(e)}")
        messages.error(request, "Error loading your tickets")
        return redirect('support:dashboard')


# Error handlers
def handler404(request, exception):
    """Custom 404 handler"""
    return render(request, 'support/404.html', status=404)


def handler500(request):
    """Custom 500 handler"""
    return render(request, 'support/500.html', status=500)


def handler403(request, exception):
    """Custom 403 handler"""
    return render(request, 'support/403.html', status=403)
