from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Q
from django.utils.translation import get_language, activate
from trueAlign.models import GlobalUpdate
from .forms import GlobalUpdateForm


def user_has_permission(user, permission_type):
    """Check if user has the required permission based on their group"""
    if not user.is_authenticated:
        return False

    # HR can manage all operations
    if user.groups.filter(name='HR').exists():
        return True

    # For viewing, allow HR, Manager, Employee
    if permission_type == 'view':
        return user.groups.filter(name__in=['HR', 'Manager', 'Employee']).exists()

    # For create, update, delete - only HR
    if permission_type in ['create', 'update', 'delete']:
        return user.groups.filter(name='HR').exists()

    return False


@login_required
def global_update_list(request):
    """List all global updates based on user role"""
    if not user_has_permission(request.user, 'view'):
        messages.error(request, 'You do not have permission to view global updates.')
        return redirect('core:dashboard')

    # Get language parameter
    language = request.GET.get('lang', 'en')
    if language not in ['en', 'hi', 'mr']:
        language = 'en'

    # Activate the selected language for this request
    activate(language)

    # Get filter parameters
    status_filter = request.GET.get('status', '')
    search_query = request.GET.get('search', '')

    # Base queryset
    updates = GlobalUpdate.objects.all().order_by('-created_at')

    # Apply filters
    if status_filter:
        updates = updates.filter(status=status_filter)

    if search_query:
        updates = updates.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query)
        )

    # For non-HR users, show only released and scheduled updates that are due
    if not request.user.groups.filter(name='HR').exists():
        current_time = timezone.now()
        updates = updates.filter(
            Q(status='released') |
            (Q(status='scheduled') & Q(scheduled_date__lte=current_time))
        )

    # Pagination
    paginator = Paginator(updates, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get status choices for filter dropdown
    status_choices = GlobalUpdate.STATUS_CHOICES

    context = {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'search_query': search_query,
        'status_choices': status_choices,
        'can_manage': user_has_permission(request.user, 'create'),
        'selected_language': language,
        'available_languages': [
            ('en', 'English'),
            ('hi', 'Hindi'),
            ('mr', 'Marathi'),
        ],
    }

    return render(request, 'notes/global_update_list.html', context)


@login_required
def global_update_detail(request, pk):
    """View details of a specific global update"""
    if not user_has_permission(request.user, 'view'):
        messages.error(request, 'You do not have permission to view global updates.')
        return redirect('core:dashboard')

    # Get language parameter
    language = request.GET.get('lang', 'en')
    if language not in ['en', 'hi', 'mr']:
        language = 'en'

    # Activate the selected language for this request
    activate(language)

    update = get_object_or_404(GlobalUpdate, pk=pk)

    # For non-HR users, check if update should be visible
    if not request.user.groups.filter(name='HR').exists():
        current_time = timezone.now()
        if update.status == 'upcoming' or (update.status == 'scheduled' and update.scheduled_date > current_time):
            messages.error(request, 'This update is not yet available.')
            return redirect('notes:global_update_list')

    context = {
        'update': update,
        'can_manage': user_has_permission(request.user, 'update'),
        'selected_language': language,
        'available_languages': [
            ('en', 'English'),
            ('hi', 'Hindi'),
            ('mr', 'Marathi'),
        ],
        # Add translated content
        'translated_title': update.get_title(language),
        'translated_description': update.get_description(language),
        'has_translation': update.has_translation(language),
    }

    return render(request, 'notes/global_update_detail.html', context)


@login_required
def global_update_create(request):
    """Create a new global update (HR only)"""
    if not user_has_permission(request.user, 'create'):
        messages.error(request, 'You do not have permission to create global updates.')
        return redirect('notes:global_update_list')

    if request.method == 'POST':
        form = GlobalUpdateForm(request.POST)
        if form.is_valid():
            update = form.save(commit=False)
            update.managed_by = request.user
            update.save()
            messages.success(request, 'Global update created successfully.')
            return redirect('notes:global_update_detail', pk=update.pk)
    else:
        form = GlobalUpdateForm()

    context = {
        'form': form,
        'title': 'Create Global Update',
        'button_text': 'Create Update',
    }

    return render(request, 'notes/global_update_form.html', context)


@login_required
def global_update_edit(request, pk):
    """Edit an existing global update (HR only)"""
    if not user_has_permission(request.user, 'update'):
        messages.error(request, 'You do not have permission to edit global updates.')
        return redirect('notes:global_update_list')

    update = get_object_or_404(GlobalUpdate, pk=pk)

    if request.method == 'POST':
        form = GlobalUpdateForm(request.POST, instance=update)
        if form.is_valid():
            form.save()
            messages.success(request, 'Global update updated successfully.')
            return redirect('notes:global_update_detail', pk=update.pk)
    else:
        form = GlobalUpdateForm(instance=update)

    context = {
        'form': form,
        'update': update,
        'title': 'Edit Global Update',
        'button_text': 'Update',
    }

    return render(request, 'notes/global_update_form.html', context)


@login_required
@require_http_methods(["POST"])
def global_update_delete(request, pk):
    """Delete a global update (HR only)"""
    if not user_has_permission(request.user, 'delete'):
        messages.error(request, 'You do not have permission to delete global updates.')
        return redirect('notes:global_update_list')

    update = get_object_or_404(GlobalUpdate, pk=pk)
    update_title = update.title
    update.delete()

    messages.success(request, f'Global update "{update_title}" has been deleted successfully.')
    return redirect('notes:global_update_list')


@login_required
def global_update_ajax_status(request):
    """AJAX endpoint to get updates with translations for dashboard"""
    if not user_has_permission(request.user, 'view'):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    # Get language parameter
    language = request.GET.get('lang', 'en')
    if language not in ['en', 'hi', 'mr']:
        language = 'en'

    # Get limit parameter (default 5 for dashboard card)
    limit = int(request.GET.get('limit', 5))

    # Base queryset
    updates = GlobalUpdate.objects.all().order_by('-created_at')

    # Apply user permission filters
    if not request.user.groups.filter(name='HR').exists():
        # Non-HR users can only see released and due scheduled updates
        current_time = timezone.now()
        updates = updates.filter(
            Q(status='released') |
            (Q(status='scheduled') & Q(scheduled_date__lte=current_time))
        )

    # Limit results
    updates = updates[:limit]

    # Build response data
    updates_data = []
    for update in updates:
        update_data = {
            'id': update.id,
            'title': update.title,
            'description': update.description,
            'translated_title': update.get_title(language),
            'translated_description': update.get_description(language),
            'status': update.status,
            'has_translation': update.has_translation(language),
            'created_at': update.created_at.isoformat(),
            'scheduled_date': update.scheduled_date.isoformat() if update.scheduled_date else None,
            'primary_language': update.primary_language,
        }
        updates_data.append(update_data)

    # Get counts for stats
    if request.user.groups.filter(name='HR').exists():
        # HR can see all updates
        upcoming_count = GlobalUpdate.objects.filter(status='upcoming').count()
        released_count = GlobalUpdate.objects.filter(status='released').count()
        scheduled_count = GlobalUpdate.objects.filter(status='scheduled').count()
    else:
        # Other users can only see released and due scheduled updates
        current_time = timezone.now()
        upcoming_count = 0  # Non-HR users don't see upcoming
        released_count = GlobalUpdate.objects.filter(status='released').count()
        scheduled_count = GlobalUpdate.objects.filter(
            status='scheduled',
            scheduled_date__lte=current_time
        ).count()

    return JsonResponse({
        'updates': updates_data,
        'counts': {
            'upcoming': upcoming_count,
            'released': released_count,
            'scheduled': scheduled_count,
            'total': upcoming_count + released_count + scheduled_count
        },
        'language': language,
        'total_updates': len(updates_data)
    })


@login_required
def global_update_mark_read(request, pk):
    """Mark a global update as read by the user"""
    if not user_has_permission(request.user, 'view'):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    update = get_object_or_404(GlobalUpdate, pk=pk)

    # Here you could implement a read tracking system
    # For now, just return success
    return JsonResponse({'success': True, 'message': 'Update marked as read'})
