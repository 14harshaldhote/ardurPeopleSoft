"""
Support Views Module - Updated for Multiple File Uploads
Handles all HTTP requests for the support ticket system
"""

import os
import csv
import json
from datetime import datetime
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.db.models import Q, Count, Prefetch
from django.http import JsonResponse, FileResponse, HttpResponse, Http404
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.core.exceptions import ValidationError, PermissionDenied
from django.core.paginator import Paginator
from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_exempt
import mimetypes
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError, PermissionDenied

from trueAlign.models import (
    Support, TicketComment, TicketAttachment,
    TicketActivity, CommentAttachment
)
from .services import (
    SupportTicketService, FileAttachmentService, BulkTicketService
)
from .forms import (
    TicketCreateForm, CommentForm, StatusUpdateForm,
    AssignmentForm, PriorityUpdateForm, TicketFilterForm,
    AttachmentForm, BulkActionForm
)

import logging
logger = logging.getLogger('support')


@login_required
def support_dashboard(request):
    """Support dashboard with statistics and metrics"""
    try:
        user_roles = SupportTicketService.get_user_roles(request.user)

        # Get statistics
        dashboard_data = SupportTicketService.get_ticket_statistics(request.user, user_roles)

        context = {
            'dashboard_data': dashboard_data,
            'user_roles': user_roles,
        }
        return render(request, 'support/dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in support_dashboard: {str(e)}", exc_info=True)
        messages.error(request, 'An error occurred while loading the dashboard.')
        return render(request, 'support/dashboard.html', {})


@login_required
def ticket_list(request):
    """List all tickets with filtering and pagination"""
    try:
        # Get user roles for permission checking
        user_roles = SupportTicketService.get_user_roles(request.user)

        # Get base queryset
        queryset = SupportTicketService.get_tickets_queryset(request.user, user_roles)

        # Apply filters
        filter_form = TicketFilterForm(request.GET or None)
        if filter_form.is_valid():
            cleaned_data = filter_form.cleaned_data

            if cleaned_data.get('status'):
                queryset = queryset.filter(status=cleaned_data['status'])
            if cleaned_data.get('priority'):
                queryset = queryset.filter(priority=cleaned_data['priority'])
            if cleaned_data.get('issue_type'):
                queryset = queryset.filter(issue_type=cleaned_data['issue_type'])
            if cleaned_data.get('assigned_group'):
                queryset = queryset.filter(assigned_group=cleaned_data['assigned_group'])

        # Pagination
        paginator = Paginator(queryset, 25)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        context = {
            'page_obj': page_obj,
            'filter_form': filter_form,
            'user_roles': user_roles,
        }
        return render(request, 'support/ticket_list.html', context)

    except Exception as e:
        logger.error(f"Error in ticket_list: {str(e)}", exc_info=True)
        messages.error(request, 'An error occurred while loading tickets.')
        return render(request, 'support/ticket_list.html', {})


@login_required
def ticket_list_api(request):
    """API endpoint for ticket list with filtering"""
    try:
        user_roles = SupportTicketService.get_user_roles(request.user)
        queryset = SupportTicketService.get_tickets_queryset(request.user, user_roles)

        # Apply filters from GET parameters
        status = request.GET.get('status')
        priority = request.GET.get('priority')
        search = request.GET.get('search')

        if status:
            queryset = queryset.filter(status=status)
        if priority:
            queryset = queryset.filter(priority=priority)
        if search:
            queryset = queryset.filter(
                Q(subject__icontains=search) |
                Q(description__icontains=search) |
                Q(ticket_id__icontains=search)
            )

        # Pagination
        page = int(request.GET.get('page', 1))
        per_page = int(request.GET.get('per_page', 25))

        paginator = Paginator(queryset, per_page)
        page_obj = paginator.get_page(page)

        # Serialize data
        tickets_data = []
        for ticket in page_obj:
            tickets_data.append({
                'id': ticket.id,
                'ticket_id': ticket.ticket_id,
                'subject': ticket.subject,
                'status': ticket.status,
                'priority': ticket.priority,
                'created_at': ticket.created_at.isoformat(),
                'user': ticket.user.get_full_name() or ticket.user.username,
                'assigned_to': ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else None,
            })

        return JsonResponse({
            'tickets': tickets_data,
            'pagination': {
                'page': page_obj.number,
                'pages': paginator.num_pages,
                'per_page': per_page,
                'total': paginator.count,
            }
        })

    except Exception as e:
        logger.error(f"Error in ticket_list_api: {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Failed to load tickets'}, status=500)


@login_required
def handle_ticket_actions(request, ticket):
    """Handle POST actions on ticket detail page"""
    action = _determine_action(request.POST)

    try:
        if action == 'add_comment':
            return handle_add_comment(request, ticket)
        elif action == 'update_status':
            return handle_status_update(request, ticket)
        elif action == 'assign':
            return handle_assignment(request, ticket)
        elif action == 'update_priority':
            return handle_priority_update(request, ticket)
        elif action == 'escalate':
            return handle_escalation(request, ticket)
        else:
            messages.error(request, 'Invalid action.')
            return redirect('support:ticket_detail', pk=ticket.pk)

    except Exception as e:
        logger.error(f"Error handling ticket action {action}: {str(e)}", exc_info=True)
        messages.error(request, f'An error occurred while processing your request: {str(e)}')
        return redirect('support:ticket_detail', pk=ticket.pk)


def handle_add_comment(request, ticket):
    """Handle adding a comment with multiple attachments"""
    form = CommentForm(request.POST, request.FILES, user=request.user)

    if form.is_valid():
        try:
            with transaction.atomic():
                # Create comment
                comment = TicketComment.objects.create(
                    ticket=ticket,
                    user=request.user,
                    content=form.cleaned_data['content'],
                    is_internal=form.cleaned_data.get('is_internal', False)
                )

                # Create ticket activity
                activity = TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.COMMENTED,
                    user=request.user,
                    details=f'Comment added: {form.cleaned_data["content"][:100]}...'
                )

                # Handle multiple comment attachments
                attachments = form.cleaned_data.get('comment_attachments', [])
                attachment_count = 0

                for file_obj in attachments:
                    if file_obj:
                        try:
                            CommentAttachment.objects.create(
                                comment=comment,
                                ticket_activity=activity,
                                file=file_obj,
                                uploaded_by=request.user,
                                description=f'Attachment for comment'
                            )
                            attachment_count += 1
                        except Exception as e:
                            logger.error(f"Error uploading comment attachment: {str(e)}")
                            messages.warning(request, f'Failed to upload file: {file_obj.name}')

                success_msg = 'Comment added successfully!'
                if attachment_count > 0:
                    success_msg += f' ({attachment_count} file(s) attached)'
                messages.success(request, success_msg)

        except Exception as e:
            logger.error(f"Error adding comment: {str(e)}", exc_info=True)
            messages.error(request, f'Failed to add comment: {str(e)}')
    else:
        # Form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')

    return redirect('support:ticket_detail', pk=ticket.pk)


def handle_status_update(request, ticket):
    """Handle status updates"""
    form = StatusUpdateForm(request.POST)

    if form.is_valid():
        try:
            old_status = ticket.status
            new_status = form.cleaned_data['status']

            # Validate status transition
            if not SupportTicketService.is_valid_status_transition(old_status, new_status):
                messages.error(request, f'Invalid status transition from {old_status} to {new_status}.')
                return redirect('support:ticket_detail', pk=ticket.pk)

            # Update ticket status
            SupportTicketService.update_ticket_status(
                ticket=ticket,
                new_status=new_status,
                user=request.user,
                comment=form.cleaned_data.get('comment', '')
            )

            messages.success(request, f'Ticket status updated to {new_status}.')

        except Exception as e:
            logger.error(f"Error updating status: {str(e)}", exc_info=True)
            messages.error(request, f'Failed to update status: {str(e)}')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')

    return redirect('support:ticket_detail', pk=ticket.pk)


def handle_assignment(request, ticket):
    """Handle ticket assignment"""
    form = AssignmentForm(request.POST, user=request.user)

    if form.is_valid():
        try:
            SupportTicketService.assign_ticket(
                ticket=ticket,
                assigned_user=form.cleaned_data.get('assigned_to_user'),
                assigned_group=form.cleaned_data.get('assigned_group'),
                assigner=request.user,
                comment=form.cleaned_data.get('assignment_comment', '')
            )

            messages.success(request, 'Ticket assignment updated successfully.')

        except Exception as e:
            logger.error(f"Error assigning ticket: {str(e)}", exc_info=True)
            messages.error(request, f'Failed to assign ticket: {str(e)}')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')

    return redirect('support:ticket_detail', pk=ticket.pk)


def handle_priority_update(request, ticket):
    """Handle priority updates"""
    form = PriorityUpdateForm(request.POST)

    if form.is_valid():
        try:
            old_priority = ticket.priority
            new_priority = form.cleaned_data['priority']

            ticket.priority = new_priority
            ticket.save(user=request.user)

            # Create activity log
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                user=request.user,
                details=f'Priority changed from {old_priority} to {new_priority}'
            )

            messages.success(request, f'Ticket priority updated to {new_priority}.')

        except Exception as e:
            logger.error(f"Error updating priority: {str(e)}", exc_info=True)
            messages.error(request, f'Failed to update priority: {str(e)}')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')

    return redirect('support:ticket_detail', pk=ticket.pk)


def handle_escalation(request, ticket):
    """Handle ticket escalation"""
    try:
        SupportTicketService.escalate_ticket(ticket, request.user)
        messages.success(request, 'Ticket escalated successfully.')
    except Exception as e:
        logger.error(f"Error escalating ticket: {str(e)}", exc_info=True)
        messages.error(request, f'Failed to escalate ticket: {str(e)}')

    return redirect('support:ticket_detail', pk=ticket.pk)


def _determine_action(post_data):
    """Determine which action to take based on POST data"""
    if 'add_comment' in post_data:
        return 'add_comment'
    elif 'update_status' in post_data:
        return 'update_status'
    elif 'assign' in post_data:
        return 'assign'
    elif 'update_priority' in post_data:
        return 'update_priority'
    elif 'escalate' in post_data:
        return 'escalate'
    else:
        return 'unknown'


def get_ticket_context_data(request, ticket, user_roles):
    """Get context data for ticket detail page"""
    try:
        # Get comments with attachments
        comments = TicketComment.objects.filter(ticket=ticket).select_related('user').prefetch_related(
            'attachments__uploaded_by'
        ).order_by('created_at')

        # Get attachments
        attachments = TicketAttachment.objects.filter(
            ticket=ticket,
            is_deleted=False
        ).select_related('uploaded_by').order_by('-uploaded_at')

        # Get activity log
        activities = TicketActivity.objects.filter(ticket=ticket).select_related('user').order_by('-timestamp')

        # Get assignable users
        assignable_users = _get_assignable_users(request.user, user_roles)

        # Initialize forms
        comment_form = CommentForm(user=request.user)
        status_form = StatusUpdateForm(initial={'status': ticket.status})
        assignment_form = AssignmentForm(user=request.user)
        priority_form = PriorityUpdateForm(initial={'priority': ticket.priority})
        attachment_form = AttachmentForm()

        # Get permissions
        permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

        return {
            'ticket': ticket,
            'comments': comments,
            'attachments': attachments,
            'activities': activities,
            'assignable_users': assignable_users,
            'comment_form': comment_form,
            'status_form': status_form,
            'assignment_form': assignment_form,
            'priority_form': priority_form,
            'attachment_form': attachment_form,
            'permissions': permissions,
            'user_roles': user_roles,
        }
    except Exception as e:
        logger.error(f"Error getting ticket context: {str(e)}", exc_info=True)
        return {
            'ticket': ticket,
            'error': 'Failed to load ticket data'
        }


def _get_assignable_users(user, user_roles):
    """Get list of users that can be assigned tickets"""
    try:
        if 'Admin' in user_roles:
            return User.objects.filter(is_staff=True).order_by('first_name', 'last_name')
        elif 'HR' in user_roles:
            return User.objects.filter(groups__name='HR').order_by('first_name', 'last_name')
        else:
            return User.objects.none()
    except Exception as e:
        logger.error(f"Error getting assignable users: {str(e)}")
        return User.objects.none()


@login_required
def create_ticket(request):
    """Create a new support ticket with multiple file upload support"""
    if request.method == 'POST':
        form = TicketCreateForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Create the ticket
                    ticket = Support.objects.create(
                        user=request.user,
                        subject=form.cleaned_data['subject'],
                        description=form.cleaned_data['description'],
                        priority=form.cleaned_data['priority'],
                        issue_type=form.cleaned_data['issue_type'],
                        assigned_group=form.cleaned_data.get('assigned_group') or None,
                        department=form.cleaned_data.get('department', ''),
                        location=form.cleaned_data.get('location', ''),
                        asset_id=form.cleaned_data.get('asset_id', ''),
                    )

                    # Handle multiple attachments
                    attachments = form.cleaned_data.get('attachments', [])
                    attachment_count = 0

                    for file_obj in attachments:
                        if file_obj:
                            try:
                                TicketAttachment.objects.create(
                                    ticket=ticket,
                                    file=file_obj,
                                    uploaded_by=request.user,
                                    description=f'Attachment uploaded during ticket creation'
                                )
                                attachment_count += 1
                            except Exception as e:
                                logger.error(f"Error uploading attachment: {str(e)}")
                                messages.warning(request, f'Failed to upload file: {file_obj.name}')

                    # Create ticket activity
                    TicketActivity.objects.create(
                        ticket=ticket,
                        action=TicketActivity.Action.CREATED,
                        user=request.user,
                        details=f'Ticket created with {attachment_count} attachment(s)'
                    )

                    success_msg = f'Ticket #{ticket.ticket_id} created successfully!'
                    if attachment_count > 0:
                        success_msg += f' ({attachment_count} file(s) attached)'
                    messages.success(request, success_msg)

                    return redirect('support:ticket_detail', pk=ticket.pk)

            except Exception as e:
                logger.error(f"Error creating ticket: {str(e)}", exc_info=True)
                messages.error(request, f'An error occurred while creating the ticket: {str(e)}')
        else:
            # Form validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = TicketCreateForm()

    context = _get_create_ticket_context()
    context['form'] = form
    return render(request, 'support/create_ticket.html', context)


def _prepare_ticket_data(request):
    """Prepare and validate ticket data from request"""
    return {
        'subject': request.POST.get('subject', '').strip(),
        'description': request.POST.get('description', '').strip(),
        'priority': request.POST.get('priority', Support.Priority.MEDIUM),
        'issue_type': request.POST.get('issue_type'),
        'assigned_group': request.POST.get('assigned_group'),
        'department': request.POST.get('department', '').strip(),
        'location': request.POST.get('location', '').strip(),
        'asset_id': request.POST.get('asset_id', '').strip(),
    }


def _get_create_ticket_context():
    """Get context for create ticket form"""
    try:
        return {
            'priority_choices': Support.Priority.choices,
            'issue_type_choices': Support.IssueType.choices,
            'assigned_group_choices': Support.AssignedGroup.choices,
        }
    except Exception as e:
        logger.error(f"Error getting create ticket context: {str(e)}")
        return {
            'priority_choices': [],
            'issue_type_choices': [],
            'assigned_group_choices': [],
        }


@login_required
def ticket_detail(request, pk):
    """Display ticket details and handle actions"""
    ticket = get_object_or_404(Support, pk=pk)

    # Check permissions
    user_roles = SupportTicketService.get_user_roles(request.user)
    permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

    if not permissions.get('can_view', False):
        messages.error(request, 'You do not have permission to view this ticket.')
        return redirect('support:ticket_list')

    if request.method == 'POST':
        return handle_ticket_actions(request, ticket)

    # GET request - render ticket detail
    try:
        context = get_ticket_context_data(request, ticket, user_roles)
        return render(request, 'support/ticket_detail.html', context)
    except Exception as e:
        logger.error(f"Error rendering ticket detail: {str(e)}", exc_info=True)
        messages.error(request, 'An error occurred while loading the ticket.')
        return redirect('support:ticket_list')


@login_required
def delete_attachment(request, pk, attachment_id):
    """Delete a ticket attachment"""
    ticket = get_object_or_404(Support, pk=pk)
    attachment = get_object_or_404(TicketAttachment, pk=attachment_id, ticket=ticket)

    # Check permissions
    user_roles = SupportTicketService.get_user_roles(request.user)
    permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

    if not permissions.get('can_delete_attachments', False):
        messages.error(request, 'You do not have permission to delete attachments.')
        return redirect('support:ticket_detail', pk=pk)

    try:
        # Use service to delete attachment
        FileAttachmentService.delete_attachment(attachment, request.user)
        messages.success(request, 'Attachment deleted successfully.')

    except Exception as e:
        logger.error(f"Error deleting attachment: {str(e)}", exc_info=True)
        messages.error(request, f'Failed to delete attachment: {str(e)}')

    return redirect('support:ticket_detail', pk=pk)


@login_required
def download_attachment(request, pk, attachment_id):
    """Download a ticket attachment"""
    ticket = get_object_or_404(Support, pk=pk)
    attachment = get_object_or_404(TicketAttachment, pk=attachment_id, ticket=ticket)

    # Check permissions
    user_roles = SupportTicketService.get_user_roles(request.user)
    permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

    if not permissions.get('can_view', False):
        raise PermissionDenied('You do not have permission to view this ticket.')

    try:
        # Check if file exists
        if not attachment.file or not default_storage.exists(attachment.file.name):
            raise Http404('File not found.')

        # Get file content
        file_path = attachment.file.path

        # Determine content type
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = 'application/octet-stream'

        # Create file response
        response = FileResponse(
            open(file_path, 'rb'),
            content_type=content_type,
            as_attachment=True,
            filename=attachment.original_filename or attachment.file.name
        )

        return response

    except Exception as e:
        logger.error(f"Error downloading attachment: {str(e)}", exc_info=True)
        messages.error(request, 'Failed to download attachment.')
        return redirect('support:ticket_detail', pk=pk)


@login_required
def bulk_ticket_actions(request):
    """Handle bulk actions on multiple tickets"""
    if request.method == 'POST':
        form = BulkActionForm(request.POST)
        ticket_ids = request.POST.getlist('ticket_ids')

        if not ticket_ids:
            messages.error(request, 'No tickets selected.')
            return redirect('support:ticket_list')

        if form.is_valid():
            try:
                action = form.cleaned_data['action']

                # Get tickets
                tickets = Support.objects.filter(id__in=ticket_ids)

                if action == 'assign':
                    result = BulkTicketService.bulk_assign(
                        tickets=tickets,
                        assigned_user=form.cleaned_data.get('assigned_to_user'),
                        assigned_group=form.cleaned_data.get('assigned_group'),
                        user=request.user
                    )
                elif action == 'change_status':
                    result = BulkTicketService.bulk_status_change(
                        tickets=tickets,
                        new_status=form.cleaned_data['new_status'],
                        user=request.user
                    )
                elif action == 'change_priority':
                    result = BulkTicketService.bulk_priority_change(
                        tickets=tickets,
                        new_priority=form.cleaned_data['new_priority'],
                        user=request.user
                    )
                elif action == 'delete':
                    result = BulkTicketService.bulk_delete(
                        tickets=tickets,
                        user=request.user
                    )

                messages.success(request, f'Bulk action completed. {result["updated"]} tickets updated.')

            except Exception as e:
                logger.error(f"Error in bulk action: {str(e)}", exc_info=True)
                messages.error(request, f'Bulk action failed: {str(e)}')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')

    return redirect('support:ticket_list')


@login_required
def ticket_export(request):
    """Export tickets to CSV"""
    try:
        user_roles = SupportTicketService.get_user_roles(request.user)
        queryset = SupportTicketService.get_tickets_queryset(request.user, user_roles)

        # Apply filters if provided
        status = request.GET.get('status')
        priority = request.GET.get('priority')

        if status:
            queryset = queryset.filter(status=status)
        if priority:
            queryset = queryset.filter(priority=priority)

        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="tickets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Ticket ID', 'Subject', 'Status', 'Priority', 'Issue Type',
            'Created By', 'Assigned To', 'Created At', 'Updated At',
            'Resolved At', 'Department', 'Location'
        ])

        for ticket in queryset:
            writer.writerow([
                ticket.ticket_id,
                ticket.subject,
                ticket.status,
                ticket.priority,
                ticket.issue_type,
                ticket.user.get_full_name() or ticket.user.username,
                ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'None',
                ticket.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                ticket.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                ticket.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.resolved_at else '',
                ticket.department,
                ticket.location,
            ])

        return response

    except Exception as e:
        logger.error(f"Error exporting tickets: {str(e)}", exc_info=True)
        messages.error(request, 'Failed to export tickets.')
        return redirect('support:ticket_list')


@login_required
def get_ticket_stats(request):
    """Get ticket statistics for dashboard"""
    try:
        user_roles = SupportTicketService.get_user_roles(request.user)
        stats = SupportTicketService.get_ticket_statistics(request.user, user_roles)

        return JsonResponse({
            'success': True,
            'stats': stats
        })

    except Exception as e:
        logger.error(f"Error getting ticket stats: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Failed to get statistics'
        }, status=500)




@login_required
def search_tickets(request):
    """Search tickets API endpoint"""
    try:
        query = request.GET.get('q', '').strip()

        if not query:
            return JsonResponse({'results': []})

        user_roles = SupportTicketService.get_user_roles(request.user)
        queryset = SupportTicketService.get_tickets_queryset(request.user, user_roles)

        # Search in multiple fields
        from django.db.models import Q
        search_results = queryset.filter(
            Q(ticket_id__icontains=query) |
            Q(subject__icontains=query) |
            Q(description__icontains=query) |
            Q(user__first_name__icontains=query) |
            Q(user__last_name__icontains=query) |
            Q(user__username__icontains=query)
        ).select_related('user', 'assigned_to_user')[:20]

        results = []
        for ticket in search_results:
            results.append({
                'id': ticket.id,
                'ticket_id': ticket.ticket_id,
                'subject': ticket.subject,
                'status': ticket.status,
                'priority': ticket.priority,
                'created_at': ticket.created_at.isoformat(),
                'user': ticket.user.get_full_name() or ticket.user.username,
                'assigned_to': ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else None,
                'url': f'/support/tickets/{ticket.id}/'
            })

        return JsonResponse({
            'success': True,
            'results': results,
            'query': query
        })

    except Exception as e:
        logger.error(f"Error searching tickets: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Search failed'
        }, status=500)


@login_required
def reopen_ticket(request, pk):
    """Reopen a closed ticket"""
    ticket = get_object_or_404(Support, pk=pk)

    # Check permissions
    user_roles = SupportTicketService.get_user_roles(request.user)
    permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

    if not permissions.get('can_reopen', False):
        messages.error(request, 'You do not have permission to reopen this ticket.')
        return redirect('support:ticket_detail', pk=pk)

    try:
        # Use service to reopen ticket
        result = SupportTicketService.reopen_ticket(ticket, request.user)

        if result.get('success'):
            messages.success(request, 'Ticket reopened successfully.')

            # Log activity
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.REOPENED,
                user=request.user,
                details=f'Ticket reopened by {request.user.get_full_name() or request.user.username}'
            )
        else:
            messages.error(request, result.get('error', 'Failed to reopen ticket.'))

    except Exception as e:
        logger.error(f"Error reopening ticket: {str(e)}", exc_info=True)
        messages.error(request, f'Failed to reopen ticket: {str(e)}')

    return redirect('support:ticket_detail', pk=pk)


@login_required
def escalate_ticket(request, pk):
    """Escalate a ticket"""
    ticket = get_object_or_404(Support, pk=pk)

    # Check permissions
    user_roles = SupportTicketService.get_user_roles(request.user)
    permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

    if not permissions.get('can_escalate', False):
        messages.error(request, 'You do not have permission to escalate this ticket.')
        return redirect('support:ticket_detail', pk=pk)

    try:
        # Use service to escalate ticket
        result = SupportTicketService.escalate_ticket(ticket, request.user)

        if result.get('success'):
            messages.success(request, 'Ticket escalated successfully.')

            # Log activity
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.ESCALATED,
                user=request.user,
                details=f'Ticket escalated to level {ticket.escalation_level} by {request.user.get_full_name() or request.user.username}'
            )
        else:
            messages.error(request, result.get('error', 'Failed to escalate ticket.'))

    except Exception as e:
        logger.error(f"Error escalating ticket: {str(e)}", exc_info=True)
        messages.error(request, f'Failed to escalate ticket: {str(e)}')

    return redirect('support:ticket_detail', pk=pk)


@login_required
def get_users_by_group(request, group_id):
    """Get users by group ID - API endpoint"""
    try:
        # Check if user has permission to view group members
        user_roles = SupportTicketService.get_user_roles(request.user)

        if not ('Admin' in user_roles or 'HR' in user_roles):
            return JsonResponse({
                'success': False,
                'error': 'Permission denied'
            }, status=403)

        # Get group
        group = get_object_or_404(Group, pk=group_id)

        # Get users in group
        users = User.objects.filter(
            groups=group,
            is_active=True
        ).order_by('first_name', 'last_name', 'username')

        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name() or user.username,
                'email': user.email,
                'is_staff': user.is_staff,
            })

        return JsonResponse({
            'success': True,
            'group': {
                'id': group.id,
                'name': group.name,
            },
            'users': users_data
        })

    except Exception as e:
        logger.error(f"Error getting users by group: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Failed to get users'
        }, status=500)


@login_required
def serve_ticket_attachment(request, file_path):
    """Serve ticket attachment files"""
    try:
        # Security check - ensure file path is within attachment directory
        import os
        from django.conf import settings
        from django.core.files.storage import default_storage

        # Normalize the path
        normalized_path = os.path.normpath(file_path)

        # Check if file exists
        if not default_storage.exists(normalized_path):
            raise Http404('File not found')

        # Get the actual file path
        actual_path = default_storage.path(normalized_path)

        # Security check - ensure file is within media directory
        media_root = os.path.normpath(settings.MEDIA_ROOT)
        if not actual_path.startswith(media_root):
            raise PermissionDenied('Access denied')

        # Find the attachment record to check permissions
        from trueAlign.models import TicketAttachment, CommentAttachment

        attachment = None

        # Try to find ticket attachment
        try:
            attachment = TicketAttachment.objects.get(file=normalized_path)
            ticket = attachment.ticket
        except TicketAttachment.DoesNotExist:
            # Try to find comment attachment
            try:
                comment_attachment = CommentAttachment.objects.get(file=normalized_path)
                ticket = comment_attachment.ticket_activity.ticket
            except CommentAttachment.DoesNotExist:
                raise Http404('Attachment not found')

        # Check permissions
        user_roles = SupportTicketService.get_user_roles(request.user)
        permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

        if not permissions.get('can_view', False):
            raise PermissionDenied('You do not have permission to view this file.')

        # Serve the file
        import mimetypes
        content_type, _ = mimetypes.guess_type(actual_path)
        if not content_type:
            content_type = 'application/octet-stream'

        from django.http import FileResponse

        return FileResponse(
            open(actual_path, 'rb'),
            content_type=content_type,
            as_attachment=True,
            filename=os.path.basename(actual_path)
        )

    except Exception as e:
        logger.error(f"Error serving attachment: {str(e)}", exc_info=True)
        from django.http import Http404
        raise Http404('File not found')


# Additional utility functions for AJAX calls

@login_required
def get_ticket_comments_api(request, pk):
    """Get ticket comments via API"""
    try:
        ticket = get_object_or_404(Support, pk=pk)

        # Check permissions
        user_roles = SupportTicketService.get_user_roles(request.user)
        permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

        if not permissions.get('can_view', False):
            return JsonResponse({
                'success': False,
                'error': 'Permission denied'
            }, status=403)

        # Get comments
        from trueAlign.models import TicketComment
        comments = TicketComment.objects.filter(ticket=ticket).select_related('user').order_by('created_at')

        comments_data = []
        for comment in comments:
            comments_data.append({
                'id': comment.id,
                'content': comment.content,
                'is_internal': comment.is_internal,
                'created_at': comment.created_at.isoformat(),
                'user': {
                    'id': comment.user.id,
                    'username': comment.user.username,
                    'full_name': comment.user.get_full_name() or comment.user.username,
                }
            })

        return JsonResponse({
            'success': True,
            'comments': comments_data
        })

    except Exception as e:
        logger.error(f"Error getting comments: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Failed to get comments'
        }, status=500)


@login_required
def get_ticket_activities_api(request, pk):
    """Get ticket activities via API"""
    try:
        ticket = get_object_or_404(Support, pk=pk)

        # Check permissions
        user_roles = SupportTicketService.get_user_roles(request.user)
        permissions = SupportTicketService.get_ticket_permissions(request.user, ticket, user_roles)

        if not permissions.get('can_view', False):
            return JsonResponse({
                'success': False,
                'error': 'Permission denied'
            }, status=403)

        # Get activities
        activities = TicketActivity.objects.filter(ticket=ticket).select_related('user').order_by('-timestamp')

        activities_data = []
        for activity in activities:
            activities_data.append({
                'id': activity.id,
                'action': activity.action,
                'details': activity.details,
                'timestamp': activity.timestamp.isoformat(),
                'user': {
                    'id': activity.user.id if activity.user else None,
                    'username': activity.user.username if activity.user else 'System',
                    'full_name': activity.user.get_full_name() if activity.user else 'System',
                }
            })

        return JsonResponse({
            'success': True,
            'activities': activities_data
        })

    except Exception as e:
        logger.error(f"Error getting activities: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Failed to get activities'
        }, status=500)
