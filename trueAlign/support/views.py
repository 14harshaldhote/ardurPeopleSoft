from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.views.generic import ListView, DetailView, CreateView
from django.views.decorators.http import require_http_methods
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Q

from trueAlign.models import Support
from .services import SupportTicketService
from .forms import TicketCreateForm, TicketCommentForm, TicketStatusForm, TicketReassignForm
from .events import dispatch_event


class SupportDashboardView(LoginRequiredMixin, ListView):
    """Main dashboard view showing tickets and statistics"""
    template_name = 'support/dashboard.html'
    context_object_name = 'tickets'
    paginate_by = 20

    def get_queryset(self):
        status_filter = self.request.GET.get('status')
        search_query = self.request.GET.get('search')
        priority_filter = self.request.GET.get('priority')

        tickets = SupportTicketService.get_tickets_for_user(
            self.request.user,
            status_filter=status_filter
        )

        # Apply search filter
        if search_query:
            tickets = tickets.filter(
                Q(ticket_id__icontains=search_query) |
                Q(subject__icontains=search_query) |
                Q(description__icontains=search_query)
            )

        # Apply priority filter
        if priority_filter:
            tickets = tickets.filter(priority=priority_filter)

        return tickets

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['stats'] = SupportTicketService.get_dashboard_stats(self.request.user)
        context['status_choices'] = Support.Status.choices
        context['priority_choices'] = Support.Priority.choices
        context['current_filters'] = {
            'status': self.request.GET.get('status', ''),
            'search': self.request.GET.get('search', ''),
            'priority': self.request.GET.get('priority', ''),
        }
        return context


class TicketCreateView(LoginRequiredMixin, CreateView):
    """View for creating new support tickets"""
    model = Support
    form_class = TicketCreateForm
    template_name = 'support/create_ticket.html'
    success_url = '/support/'

    def form_valid(self, form):
        import logging
        logger = logging.getLogger(__name__)

        try:
            # Log form data for debugging
            logger.info(f"Creating ticket for user: {self.request.user.username}")
            logger.info(f"Form data: {form.cleaned_data}")

            ticket_data = {
                'issue_type': form.cleaned_data['issue_type'],
                'subject': form.cleaned_data['subject'],
                'description': form.cleaned_data['description'],
                'priority': form.cleaned_data['priority'],
                'location': form.cleaned_data.get('location', ''),
                'asset_id': form.cleaned_data.get('asset_id', ''),
            }

            ticket = SupportTicketService.create_ticket(
                user=self.request.user,
                ticket_data=ticket_data
            )

            logger.info(f"Ticket created successfully: {ticket.ticket_id}")

            messages.success(
                self.request,
                f'Ticket {ticket.ticket_id} created successfully!'
            )

            # Dispatch event
            dispatch_event('ticket_created', ticket, self.request.user)

            return redirect('support:ticket_detail', ticket_id=ticket.pk)

        except Exception as e:
            logger.error(f'Error creating ticket: {str(e)}', exc_info=True)
            messages.error(self.request, f'Error creating ticket: {str(e)}')
            return self.form_invalid(form)


class TicketDetailView(LoginRequiredMixin, DetailView):
    """View for displaying ticket details"""
    model = Support
    template_name = 'support/ticket_detail.html'
    context_object_name = 'ticket'
    pk_url_kwarg = 'ticket_id'

    def get_object(self, queryset=None):
        try:
            return SupportTicketService.get_ticket_detail(
                ticket_id=self.kwargs['ticket_id'],
                user=self.request.user
            )
        except PermissionDenied:
            raise Http404("Ticket not found or access denied")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ticket = self.get_object()

        # Add forms for actions
        context['comment_form'] = TicketCommentForm()
        context['can_resolve'] = SupportTicketService.can_resolve_tickets(self.request.user)
        context['can_reassign'] = SupportTicketService.can_reassign_tickets(self.request.user)

        if context['can_resolve']:
            context['status_form'] = TicketStatusForm()

        if context['can_reassign']:
            context['reassign_form'] = TicketReassignForm()
            context['available_assignees'] = SupportTicketService.get_available_assignees(
                self.request.user
            )

        # Get ticket activities and comments
        context['comments'] = ticket.comments.select_related('user').order_by('created_at')
        context['activities'] = ticket.ticket_activity.select_related('user').order_by('-timestamp')[:10]
        context['attachments'] = ticket.attachments.filter(is_deleted=False).order_by('-uploaded_at')

        return context


@login_required
@require_http_methods(["POST"])
def update_ticket_status(request, ticket_id):
    """Update ticket status"""
    try:
        new_status = request.POST.get('status')
        comment = request.POST.get('comment', '')

        if not new_status:
            messages.error(request, 'Status is required')
            return redirect('support:ticket_detail', ticket_id=ticket_id)

        ticket = SupportTicketService.update_ticket_status(
            ticket_id=ticket_id,
            new_status=new_status,
            user=request.user,
            comment=comment if comment else None
        )

        messages.success(request, f'Ticket status updated to {dict(Support.Status.choices)[ticket.status]}')

        # Dispatch event
        dispatch_event(
            'ticket_status_changed', 
            ticket, 
            request.user, 
            old_status=request.POST.get('old_status') # Note: We might need to fetch old status before update if not passed, but service handles update. 
            # Actually, the service returns the updated ticket. We don't easily have the old status here unless we fetch it before.
            # Let's assume the rule handler handles "current status is X" logic. 
            # But wait, the rule says "Notify ticket owner: Your ticket is now X". That works with new status.
            # The rule also says "Notify assignee: Ticket status changed to X". That also works.
            # So we don't strictly need old_status for the notification message itself, but maybe for logic?
            # The rule implementation I wrote uses `kwargs.get('old_status')` but doesn't strictly depend on it for the message content except maybe for diffing?
            # Actually, let's just pass it if we can. But here we don't have it easily without an extra DB call.
            # Let's check if we can get it from the form or just skip it for now as the messages I defined don't use it.
            # Re-reading my rule implementation: `old_status = kwargs.get('old_status')` is used.
            # But the message is: `Your ticket '{ticket.subject}' is now {new_status}.`
            # So it's fine.
        )

    except PermissionDenied as e:
        messages.error(request, str(e))
    except Exception as e:
        messages.error(request, f'Error updating status: {str(e)}')

    return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_http_methods(["POST"])
def reassign_ticket(request, ticket_id):
    """Reassign ticket to different user or group"""
    try:
        assigned_to_user_id = request.POST.get('assigned_to_user')
        assigned_group = request.POST.get('assigned_group')

        # Convert empty string to None for user assignment
        if assigned_to_user_id == '':
            assigned_to_user_id = None
        elif assigned_to_user_id:
            assigned_to_user_id = int(assigned_to_user_id)

        ticket = SupportTicketService.reassign_ticket(
            ticket_id=ticket_id,
            assigned_to_user_id=assigned_to_user_id,
            assigned_group=assigned_group,
            reassigning_user=request.user
        )

        messages.success(request, 'Ticket reassigned successfully')

        # Dispatch event
        # We need to know if it was a reassign or initial assign (though initial usually happens at create).
        # This view is `reassign_ticket`, so it's likely a reassign.
        # We might want the old assignee. Again, service handles it.
        # Let's just dispatch 'ticket_reassigned' and let the handler figure it out or just notify new assignee.
        dispatch_event('ticket_reassigned', ticket, request.user)

    except PermissionDenied as e:
        messages.error(request, str(e))
    except ValueError:
        messages.error(request, 'Invalid user selection')
    except Exception as e:
        messages.error(request, f'Error reassigning ticket: {str(e)}')

    return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_http_methods(["POST"])
def add_comment(request, ticket_id):
    """Add comment to ticket"""
    try:
        content = request.POST.get('content')
        is_internal = request.POST.get('is_internal') == 'on'

        if not content or not content.strip():
            messages.error(request, 'Comment content is required')
            return redirect('support:ticket_detail', ticket_id=ticket_id)

        comment = SupportTicketService.add_comment(
            ticket_id=ticket_id,
            user=request.user,
            content=content.strip(),
            is_internal=is_internal
        )

        messages.success(request, 'Comment added successfully')

        # Dispatch event
        dispatch_event(
            'ticket_comment_added', 
            comment.ticket, 
            request.user, 
            is_internal=is_internal
        )

    except PermissionDenied as e:
        messages.error(request, str(e))
    except Exception as e:
        messages.error(request, f'Error adding comment: {str(e)}')

    return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_http_methods(["POST"])
def add_attachment(request, ticket_id):
    """Add file attachment to ticket"""
    try:
        file_obj = request.FILES.get('file')
        description = request.POST.get('description', '')

        if not file_obj:
            messages.error(request, 'Please select a file to upload')
            return redirect('support:ticket_detail', ticket_id=ticket_id)

        # File size validation (10MB limit)
        if file_obj.size > 10 * 1024 * 1024:
            messages.error(request, 'File size must be less than 10MB')
            return redirect('support:ticket_detail', ticket_id=ticket_id)

        attachment = SupportTicketService.add_attachment(
            ticket_id=ticket_id,
            user=request.user,
            file_obj=file_obj,
            description=description
        )

        messages.success(request, f'File "{attachment.original_filename}" uploaded successfully')

    except PermissionDenied as e:
        messages.error(request, str(e))
    except Exception as e:
        messages.error(request, f'Error uploading file: {str(e)}')

    return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
@require_http_methods(["POST"])
def escalate_ticket(request, ticket_id):
    """Escalate ticket priority"""
    try:
        reason = request.POST.get('reason', '')

        ticket = SupportTicketService.escalate_ticket(
            ticket_id=ticket_id,
            user=request.user,
            reason=reason
        )

        messages.success(
            request,
            f'Ticket escalated to level {ticket.escalation_level} with priority {dict(Support.Priority.choices)[ticket.priority]}'
        )

        # Dispatch event
        dispatch_event(
            'ticket_escalated', 
            ticket, 
            request.user, 
            reason=reason
        )

    except PermissionDenied as e:
        messages.error(request, str(e))
    except Exception as e:
        messages.error(request, f'Error escalating ticket: {str(e)}')

    return redirect('support:ticket_detail', ticket_id=ticket_id)


@login_required
def my_tickets(request):
    """View showing only current user's tickets"""
    tickets = Support.objects.filter(
        user=request.user,
        is_deleted=False
    ).order_by('-created_at')

    # Apply filters
    status_filter = request.GET.get('status')
    if status_filter:
        tickets = tickets.filter(status=status_filter)

    # Pagination
    paginator = Paginator(tickets, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'tickets': page_obj,
        'status_choices': Support.Status.choices,
        'current_status': status_filter or '',
    }

    return render(request, 'support/my_tickets.html', context)


@login_required
def ajax_ticket_stats(request):
    """AJAX endpoint for ticket statistics"""
    try:
        stats = SupportTicketService.get_dashboard_stats(request.user)
        return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def ajax_search_tickets(request):
    """AJAX endpoint for ticket search"""
    try:
        query = request.GET.get('q', '')
        if len(query) < 2:
            return JsonResponse({'tickets': []})

        tickets = SupportTicketService.get_tickets_for_user(request.user)
        tickets = tickets.filter(
            Q(ticket_id__icontains=query) |
            Q(subject__icontains=query)
        )[:10]

        ticket_data = [
            {
                'id': ticket.pk,
                'ticket_id': ticket.ticket_id,
                'subject': ticket.subject,
                'status': dict(Support.Status.choices)[ticket.status],
                'priority': dict(Support.Priority.choices)[ticket.priority],
                'created_at': ticket.created_at.strftime('%Y-%m-%d %H:%M'),
            }
            for ticket in tickets
        ]

        return JsonResponse({'tickets': ticket_data})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Error handlers for support views
def support_403(request, exception):
    """Custom 403 handler for support views"""
    return render(request, 'support/403.html', status=403)


def support_404(request, exception):
    """Custom 404 handler for support views"""
    return render(request, 'support/404.html', status=404)
