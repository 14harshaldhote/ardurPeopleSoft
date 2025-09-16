from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from django.utils import timezone
from django.db.models import Q
from django.utils.translation import activate
from django.contrib.auth.models import User
from trueAlign.models import GlobalUpdate
from .forms import GlobalUpdateForm


def user_has_permission(user, permission_type):
    """Check if user has the required permission based on their group"""
    if not user.is_authenticated:
        return False

    user_groups = user.groups.all()
    is_hr = user_groups.filter(name='HR').exists()
    is_manager = user_groups.filter(name='Manager').exists()
    is_employee = user_groups.filter(name='Employee').exists()

    # HR can manage all operations
    if is_hr:
        return True

    # For viewing, allow HR, Manager, Employee
    if permission_type == 'view':
        return is_hr or is_manager or is_employee

    # For create, update, delete - only HR
    if permission_type in ['create', 'update', 'delete']:
        return is_hr

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

    # Get user roles
    is_hr = request.user.groups.filter(name='HR').exists()
    is_manager = request.user.groups.filter(name='Manager').exists()
    is_employee = request.user.groups.filter(name='Employee').exists()

    # For non-HR users, show only released and scheduled updates that are due
    if not is_hr:
        current_time = timezone.now()
        updates = updates.filter(
            Q(status='released') |
            (Q(status='scheduled') & Q(scheduled_date__lte=current_time))
        )

        # If user has no valid role, don't return any updates
        if not (is_manager or is_employee):
            updates = updates.none()

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
        'is_hr': is_hr,
        'is_manager': is_manager,
        'is_employee': is_employee,
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

    # Get user roles
    is_hr = request.user.groups.filter(name='HR').exists()
    is_manager = request.user.groups.filter(name='Manager').exists()
    is_employee = request.user.groups.filter(name='Employee').exists()

    # For non-HR users, check if update should be visible
    if not is_hr:
        # Check if user has valid role
        if not (is_manager or is_employee):
            messages.error(request, 'You do not have permission to view global updates.')
            return redirect('core:dashboard')

        current_time = timezone.now()
        if update.status == 'upcoming' or (update.status == 'scheduled' and update.scheduled_date > current_time):
            messages.error(request, 'This update is not yet available.')
            return redirect('notes:global_update_list')

    context = {
        'update': update,
        'can_manage': user_has_permission(request.user, 'update'),
        'is_hr': is_hr,
        'is_manager': is_manager,
        'is_employee': is_employee,
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
            messages.error(request, 'Please correct the errors below.')
    else:
        form = GlobalUpdateForm()

    context = {
        'form': form,
        'title': 'Create Global Update',
        'button_text': 'Create Update',
        'action_url': 'notes:global_update_create',
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
            messages.error(request, 'Please correct the errors below.')
    else:
        form = GlobalUpdateForm(instance=update)

    context = {
        'form': form,
        'update': update,
        'title': 'Edit Global Update',
        'button_text': 'Update',
        'action_url': 'notes:global_update_edit',
        'is_edit': True,
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

    try:
        update.delete()
        messages.success(request, f'Global update "{update_title}" has been deleted successfully.')
    except Exception as e:
        messages.error(request, f'Error deleting update: {str(e)}')

    return redirect('notes:global_update_list')


@login_required
def global_update_toggle_status(request, pk):
    """Toggle status of a global update (HR only)"""
    if not user_has_permission(request.user, 'update'):
        messages.error(request, 'You do not have permission to update global updates.')
        return redirect('notes:global_update_list')

    update = get_object_or_404(GlobalUpdate, pk=pk)

    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status in ['upcoming', 'scheduled', 'released']:
            update.status = new_status
            update.save()
            messages.success(request, f'Update status changed to {new_status}.')
        else:
            messages.error(request, 'Invalid status provided.')

    return redirect('notes:global_update_detail', pk=pk)


def global_update_ajax_status(request):
    """AJAX endpoint to get updates with translations for dashboard"""
    import logging
    logger = logging.getLogger(__name__)

    # Check authentication first and return JSON response for unauthenticated users
    if not request.user.is_authenticated:
        logger.warning("Unauthenticated request to global_update_ajax_status")
        return JsonResponse({
            'success': False,
            'error': 'Authentication required. Please log in to view global updates.',
            'updates': [],
            'can_view': False,
            'redirect_to_login': True
        }, status=401)

    try:
        # Simple role detection based on user groups only
        user_groups = request.user.groups.all()
        is_hr = user_groups.filter(name='HR').exists()
        is_manager = user_groups.filter(name='Manager').exists()
        is_employee = user_groups.filter(name='Employee').exists()

        logger.info(f"User {request.user.username} roles: HR={is_hr}, Manager={is_manager}, Employee={is_employee}")

        # Allow access if user has any valid role
        if not (is_hr or is_manager or is_employee):
            logger.warning(f"User {request.user.username} has no valid roles for global updates")
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to view global updates',
                'updates': [],
                'can_view': False
            }, status=403)

        # Get language parameter
        language = request.GET.get('lang', 'en')
        if language not in ['en', 'hi', 'mr']:
            language = 'en'

        logger.info(f"Loading updates for language: {language}")

        # Get limit parameter (default 5 for dashboard card)
        try:
            limit = int(request.GET.get('limit', 5))
            limit = max(1, min(limit, 50))  # Ensure reasonable limits
        except (ValueError, TypeError):
            limit = 5

        # Base queryset with error handling
        try:
            updates = GlobalUpdate.objects.all().order_by('-created_at')
            logger.info(f"Found {updates.count()} total updates")
        except Exception as e:
            logger.error(f"Error querying GlobalUpdate: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Database error occurred while loading updates',
                'updates': [],
                'can_view': False
            }, status=500)

        # Apply user permission filters
        if not is_hr:
            # Non-HR users can see released updates and scheduled updates that are due
            current_time = timezone.now()
            updates = updates.filter(
                Q(status='released') |
                (Q(status='scheduled') & Q(scheduled_date__lte=current_time))
            )
            logger.info(f"After filtering for non-HR user: {updates.count()} updates")

        # Limit results
        updates = updates[:limit]

        # Build response data with detailed error handling
        updates_data = []
        for update in updates:
            try:
                # Validate required fields
                if not hasattr(update, 'id') or not hasattr(update, 'title'):
                    logger.warning(f"Update missing required fields: {update}")
                    continue

                # Safely get translations
                try:
                    translated_title = update.get_title(language) if hasattr(update, 'get_title') else update.title
                    translated_description = update.get_description(language) if hasattr(update, 'get_description') else update.description
                    has_translation = update.has_translation(language) if hasattr(update, 'has_translation') else (language == 'en')
                except Exception as trans_e:
                    logger.warning(f"Translation error for update {update.id}: {str(trans_e)}")
                    translated_title = update.title
                    translated_description = update.description
                    has_translation = (language == 'en')

                update_data = {
                    'id': update.id,
                    'title': update.title or 'Untitled',
                    'description': update.description or 'No description',
                    'translated_title': translated_title or update.title or 'Untitled',
                    'translated_description': translated_description or update.description or 'No description',
                    'status': update.status or 'released',
                    'has_translation': has_translation,
                    'created_at': update.created_at.isoformat() if update.created_at else None,
                    'scheduled_date': update.scheduled_date.isoformat() if update.scheduled_date else None,
                    'primary_language': getattr(update, 'primary_language', 'en'),
                    'detail_url': f"/notes/global-updates/{update.id}/",
                }
                updates_data.append(update_data)
                logger.debug(f"Successfully processed update {update.id}")

            except Exception as e:
                logger.error(f"Error processing update {getattr(update, 'id', 'unknown')}: {str(e)}")
                # Add a fallback error update so users know something went wrong
                updates_data.append({
                    'id': getattr(update, 'id', 0),
                    'title': 'Error loading update',
                    'description': 'This update could not be displayed properly',
                    'translated_title': 'Error loading update',
                    'translated_description': 'This update could not be displayed properly',
                    'status': 'error',
                    'has_translation': True,
                    'created_at': None,
                    'scheduled_date': None,
                    'primary_language': 'en',
                    'detail_url': '#',
                })

        logger.info(f"Successfully processed {len(updates_data)} updates")

        # Get counts for stats with better error handling
        try:
            if is_hr:
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
        except Exception as count_e:
            logger.error(f"Error getting counts: {str(count_e)}")
            # Provide safe defaults if count queries fail
            upcoming_count = released_count = scheduled_count = 0

        response_data = {
            'success': True,
            'updates': updates_data,
            'counts': {
                'upcoming': upcoming_count,
                'released': released_count,
                'scheduled': scheduled_count,
                'total': upcoming_count + released_count + scheduled_count
            },
            'language': language,
            'total_updates': len(updates_data),
            'is_hr': is_hr,
            'is_manager': is_manager,
            'is_employee': is_employee,
            'can_view': True
        }

        logger.info(f"Returning successful response with {len(updates_data)} updates")
        return JsonResponse(response_data)

    except Exception as e:
        # Log the full error for debugging
        logger.error(f"Unexpected error in global_update_ajax_status: {str(e)}", exc_info=True)

        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred while loading updates. Please refresh the page.',
            'updates': [],
            'can_view': False,
            'debug_error': str(e) if request.user.is_superuser else None
        }, status=500)


def global_update_mark_read(request, pk):
    """Mark a global update as read by the user"""
    if not request.user.is_authenticated:
        return JsonResponse({
            'success': False,
            'error': 'Authentication required',
            'redirect_to_login': True
        }, status=401)

    is_hr = request.user.groups.filter(name='HR').exists()
    is_manager = request.user.groups.filter(name='Manager').exists()
    is_employee = request.user.groups.filter(name='Employee').exists()

    if not (is_hr or is_manager or is_employee):
        return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

    try:
        update = get_object_or_404(GlobalUpdate, pk=pk)

        # Here you could implement a read tracking system
        # For example, create a UserReadUpdate model to track what each user has read
        # UserReadUpdate.objects.get_or_create(user=request.user, update=update)

        return JsonResponse({
            'success': True,
            'message': 'Update marked as read'
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'An error occurred: {str(e)}'
        }, status=500)


def global_update_search(request):
    """AJAX search endpoint for global updates"""
    if not request.user.is_authenticated:
        return JsonResponse({
            'success': False,
            'error': 'Authentication required',
            'updates': [],
            'can_view': False,
            'redirect_to_login': True
        }, status=401)

    is_hr = request.user.groups.filter(name='HR').exists()
    is_manager = request.user.groups.filter(name='Manager').exists()
    is_employee = request.user.groups.filter(name='Employee').exists()

    if not (is_hr or is_manager or is_employee):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        query = request.GET.get('q', '').strip()
        if not query:
            return JsonResponse({'updates': []})

        # Get language parameter
        language = request.GET.get('lang', 'en')
        if language not in ['en', 'hi', 'mr']:
            language = 'en'

        # Search in updates
        updates = GlobalUpdate.objects.filter(
            Q(title__icontains=query) |
            Q(description__icontains=query)
        ).order_by('-created_at')

        # Apply user permission filters
        if not is_hr:
            current_time = timezone.now()
            updates = updates.filter(
                Q(status='released') |
                (Q(status='scheduled') & Q(scheduled_date__lte=current_time))
            )

            # If user has no valid role, don't return any updates
            if not (is_manager or is_employee):
                updates = updates.none()

        # Limit results
        updates = updates[:10]

        # Build response data
        updates_data = []
        for update in updates:
            update_data = {
                'id': update.id,
                'title': update.get_title(language),
                'description': update.get_description(language)[:100] + '...' if len(update.get_description(language)) > 100 else update.get_description(language),
                'status': update.status,
                'created_at': update.created_at.strftime('%Y-%m-%d'),
                'detail_url': f"/notes/global-updates/{update.id}/",
            }
            updates_data.append(update_data)

        return JsonResponse({
            'success': True,
            'updates': updates_data,
            'total': len(updates_data),
            'is_hr': is_hr,
            'is_manager': is_manager,
            'is_employee': is_employee,
            'can_view': is_hr or is_manager or is_employee
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Search failed: {str(e)}',
            'can_view': False
        }, status=500)
