"""
Appraisal Views
Clean views with proper exception handling and service layer delegation
"""
import json
import logging
import csv
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from django.db import transaction
from datetime import datetime

from trueAlign.models import Appraisal, AppraisalItem, AppraisalAttachment, AppraisalWorkflow
from .service import appraisal_service

logger = logging.getLogger(__name__)
User = get_user_model()


# Helper functions for role checks
def is_manager_or_admin(user):
    """Check if user is a manager or admin"""
    return user.groups.filter(name="Manager").exists() or user.is_superuser


def is_hr_or_admin(user):
    """Check if user is HR or admin"""
    return user.groups.filter(name="HR").exists() or user.is_superuser




@login_required
def appraisal_list(request):
    """View for listing appraisals based on user role"""
    logger.info(f"Accessing appraisal_list for user: {request.user.username}")
    
    try:
        user = request.user
        context = {}
        
        # Check if user is in any special groups
        special_groups = ["Manager", "HR"]
        is_special_user = user.groups.filter(name__in=special_groups).exists()
        context['is_special_user'] = is_special_user
        
        # Set group flags
        group_flags = {
            'is_manager': user.groups.filter(name="Manager").exists(),
            'is_hr': user.groups.filter(name="HR").exists()
        }
        context.update(group_flags)
        
        # Get appraisals based on role
        if group_flags['is_hr']:
            # HR sees appraisals pending their review
            appraisals = Appraisal.objects.filter(
                status__in=['hr_review', 'approved', 'rejected']
            ).select_related('user', 'manager')
            context['pending_reviews'] = appraisals.filter(status='hr_review').count()
            
        elif group_flags['is_manager']:
            # Managers can review their team's appraisals
            appraisals = Appraisal.objects.filter(
                manager=user
            ).select_related('user', 'manager')
            context['pending_reviews'] = appraisals.filter(status__in=['submitted', 'manager_review']).count()
            
        else:
            # Regular employees see their own appraisals
            appraisals = Appraisal.objects.filter(
                user=user
            ).select_related('user', 'manager')
        
        context['appraisals'] = appraisals.order_by('-created_at')
        logger.info(f"Found {appraisals.count()} appraisals for user {user.username}")
        
        return render(request, 'apprisal/appraisal_list.html', context)
        
    except Exception as e:
        logger.error(f"Error in appraisal_list: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while loading appraisals")
        return render(request, 'apprisal/appraisal_list.html', {'appraisals': []})


@login_required
def appraisal_detail(request, pk):
    """View for displaying appraisal details"""
    logger.info(f"Accessing appraisal_detail for pk: {pk}")
    
    try:
        appraisal = get_object_or_404(
            Appraisal.objects.select_related('user', 'manager'),
            pk=pk
        )
        user = request.user
        
        # Check permissions
        if not (user == appraisal.user or
                user == appraisal.manager or
                user.groups.filter(name='HR').exists()):
            logger.warning(f"Permission denied for user {user.username} on appraisal {pk}")
            raise PermissionDenied("You don't have permission to view this appraisal")
        
        context = {
            'appraisal': appraisal,
            'items': appraisal.items.all().order_by('category', '-date'),
            'attachments': appraisal.attachments.all().select_related('uploaded_by'),
            'workflow_history': appraisal.workflow_history.all().select_related('action_by'),
            'can_edit': appraisal_service.can_user_edit_appraisal(user, appraisal),
            'can_submit': appraisal_service.can_user_submit_appraisal(user, appraisal),
            'can_review': appraisal_service.can_user_review_appraisal(user, appraisal),
        }
        
        return render(request, 'apprisal/appraisal_detail.html', context)
        
    except PermissionDenied as e:
        messages.error(request, str(e))
        return redirect('appraisal:appraisal_list')
    except Exception as e:
        logger.error(f"Error in appraisal_detail for pk {pk}: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while loading the appraisal")
        return redirect('appraisal:appraisal_list')


@login_required
def appraisal_create(request):
    """View for creating new appraisal"""
    logger.info(f"Accessing appraisal_create for user: {request.user.username}")
    
    if request.method == 'POST':
        try:
            # Parse JSON items data
            items_data = json.loads(request.POST.get('items', '[]'))
            
            # Validate required fields
            required_fields = ['title', 'overview', 'period_start', 'period_end', 'manager']
            for field in required_fields:
                if not request.POST.get(field):
                    return JsonResponse({
                        'success': False,
                        'error': f"{field.replace('_', ' ').title()} is required"
                    })
            
            # Get manager
            manager_id = request.POST.get('manager')
            try:
                manager = User.objects.get(id=manager_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': "Invalid manager selected"
                })
            
            # Parse dates
            try:
                period_start = datetime.strptime(request.POST['period_start'], '%Y-%m-%d').date()
                period_end = datetime.strptime(request.POST['period_end'], '%Y-%m-%d').date()
            except ValueError as e:
                return JsonResponse({
                    'success': False,
                    'error': f"Invalid date format: {str(e)}"
                })
            
            # Get attachments
            attachments = request.FILES.getlist('attachments')
            
            # Call service to create appraisal
            success, message, appraisal = appraisal_service.create_appraisal(
                user=request.user,
                manager=manager,
                title=request.POST['title'],
                overview=request.POST['overview'],
                period_start=period_start,
                period_end=period_end,
                items_data=items_data,
                attachments=attachments
            )
            
            if success:
                logger.info(f"Appraisal created successfully: {appraisal.id}")
                return JsonResponse({
                    'success': True,
                    'appraisal_id': appraisal.id,
                    'message': message
                })
            else:
                logger.warning(f"Failed to create appraisal: {message}")
                return JsonResponse({
                    'success': False,
                    'error': message
                })
                
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': "Invalid items data format"
            })
        except Exception as e:
            logger.error(f"Error creating appraisal: {str(e)}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f"An error occurred: {str(e)}"
            })
    
    # GET request - show form
    try:
        managers = User.objects.filter(
            groups__name='Manager',
            is_active=True
        ).order_by('first_name', 'last_name')
        
        categories = dict(AppraisalItem.CATEGORY_CHOICES)
        ratings = dict(AppraisalItem.RATING_CHOICES)
        
        context = {
            'managers': managers,
            'categories': categories,
            'ratings': ratings
        }
        
        return render(request, 'apprisal/appraisal_form.html', context)
        
    except Exception as e:
        logger.error(f"Error loading appraisal form: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while loading the form")
        return redirect('appraisal:appraisal_list')


@login_required
def appraisal_update(request, pk):
    """View for updating appraisal"""
    logger.info(f"Accessing appraisal_update for pk: {pk}")
    
    try:
        appraisal = get_object_or_404(Appraisal, pk=pk)
        
        # Check permissions
        if not appraisal_service.can_user_edit_appraisal(request.user, appraisal):
            raise PermissionDenied("You don't have permission to edit this appraisal")
        
        if request.method == 'POST':
            try:
                # Parse JSON items data
                items_data = json.loads(request.POST.get('items', '[]'))
                
                # Parse dates if provided
                period_start = None
                period_end = None
                if request.POST.get('period_start'):
                    period_start = datetime.strptime(request.POST['period_start'], '%Y-%m-%d').date()
                if request.POST.get('period_end'):
                    period_end = datetime.strptime(request.POST['period_end'], '%Y-%m-%d').date()
                
                # Get new attachments
                attachments = request.FILES.getlist('attachments')
                
                # Get attachment IDs to delete
                delete_attachment_ids = request.POST.getlist('delete_attachments[]')
                
                # Call service to update appraisal
                success, message = appraisal_service.update_appraisal(
                    user=request.user,
                    appraisal=appraisal,
                    title=request.POST.get('title'),
                    overview=request.POST.get('overview'),
                    period_start=period_start,
                    period_end=period_end,
                    items_data=items_data if items_data else None,
                    attachments=attachments,
                    delete_attachment_ids=delete_attachment_ids
                )
                
                if success:
                    logger.info(f"Appraisal {pk} updated successfully")
                    return JsonResponse({
                        'success': True,
                        'message': message
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': message
                    })
                    
            except json.JSONDecodeError:
                return JsonResponse({
                    'success': False,
                    'error': "Invalid items data format"
                })
            except Exception as e:
                logger.error(f"Error updating appraisal {pk}: {str(e)}", exc_info=True)
                return JsonResponse({
                    'success': False,
                    'error': f"An error occurred: {str(e)}"
                })
        
        # GET request - show form
        categories = dict(AppraisalItem.CATEGORY_CHOICES)
        ratings = dict(AppraisalItem.RATING_CHOICES)
        
        context = {
            'appraisal': appraisal,
            'items': appraisal.items.all(),
            'attachments': appraisal.attachments.all(),
            'categories': categories,
            'ratings': ratings,
            'is_update': True
        }
        
        return render(request, 'apprisal/appraisal_form.html', context)
        
    except PermissionDenied as e:
        messages.error(request, str(e))
        return redirect('appraisal:appraisal_detail', pk=pk)
    except Exception as e:
        logger.error(f"Error in appraisal_update for pk {pk}: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred")
        return redirect('appraisal:appraisal_list')


@login_required
def appraisal_submit(request, pk):
    """View for submitting appraisal for review"""
    logger.info(f"Accessing appraisal_submit for pk: {pk}")
    
    if request.method != 'POST':
        return redirect('appraisal:appraisal_detail', pk=pk)
    
    try:
        appraisal = get_object_or_404(Appraisal, pk=pk)
        
        # Call service to submit
        success, message = appraisal_service.submit_appraisal(request.user, appraisal)
        
        if success:
            logger.info(f"Appraisal {pk} submitted successfully")
            messages.success(request, message)
        else:
            logger.warning(f"Failed to submit appraisal {pk}: {message}")
            messages.error(request, message)
        
        return redirect('appraisal:appraisal_detail', pk=pk)
        
    except Exception as e:
        logger.error(f"Error submitting appraisal {pk}: {str(e)}", exc_info=True)
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('appraisal:appraisal_detail', pk=pk)


@login_required
@user_passes_test(lambda u: is_manager_or_admin(u) or is_hr_or_admin(u))
def appraisal_review(request, pk):
    """View for reviewing appraisals (Manager and HR)"""
    logger.info(f"Accessing appraisal_review for pk: {pk}")
    
    try:
        appraisal = get_object_or_404(
            Appraisal.objects.select_related('user', 'manager'),
            pk=pk
        )
        user = request.user
        
        # Check review permissions
        if not appraisal_service.can_user_review_appraisal(user, appraisal):
            raise PermissionDenied("You don't have permission to review this appraisal")
        
        if request.method == 'POST':
            try:
                action = request.POST.get('action')
                comments = request.POST.get('comments', '')
                
                # Validate action
                if action not in ['approve', 'reject']:
                    messages.error(request, "Invalid action")
                    return redirect('appraisal:appraisal_review', pk=pk)
                
                # Parse item ratings and comments (Manager or HR ratings)
                item_ratings = {}
                item_comments = {}
                
                for item in appraisal.items.all():
                    item_id = str(item.id)
                    # Determine which rating field to use based on appraisal status
                    if appraisal.status in ['submitted', 'manager_review']:
                        rating = request.POST.get(f'items[{item_id}][manager_rating]')
                        comment = request.POST.get(f'items[{item_id}][manager_comments]', '')
                    else:
                        rating = request.POST.get(f'items[{item_id}][hr_rating]')
                        comment = request.POST.get(f'items[{item_id}][hr_comments]', '')
                    
                    if rating:
                        item_ratings[item_id] = int(rating)
                    if comment:
                        item_comments[item_id] = comment
                
                # Call service to review
                success, message = appraisal_service.review_appraisal(
                    user=user,
                    appraisal=appraisal,
                    action=action,
                    comments=comments,
                    item_ratings=item_ratings if item_ratings else None,
                    item_comments=item_comments if item_comments else None
                )
                
                if success:
                    logger.info(f"Appraisal {pk} reviewed successfully by {user.username}")
                    messages.success(request, message)
                    return redirect('appraisal:appraisal_list')
                else:
                    logger.warning(f"Failed to review appraisal {pk}: {message}")
                    messages.error(request, message)
                    return redirect('appraisal:appraisal_review', pk=pk)
                    
            except Exception as e:
                logger.error(f"Error reviewing appraisal {pk}: {str(e)}", exc_info=True)
                messages.error(request, f"An error occurred: {str(e)}")
                return redirect('appraisal:appraisal_review', pk=pk)
        
        # GET request - show review form
        context = {
            'appraisal': appraisal,
            'items': appraisal.items.all().order_by('category', '-date'),
            'attachments': appraisal.attachments.all().select_related('uploaded_by'),
            'workflow_history': appraisal.workflow_history.all().select_related('action_by'),
            'ratings': dict(AppraisalItem.RATING_CHOICES),
            'is_manager': is_manager_or_admin(user),
            'is_hr': is_hr_or_admin(user),
            'can_rate_items': True,
        }
        
        return render(request, 'apprisal/appraisal_review.html', context)
        
    except PermissionDenied as e:
        messages.error(request, str(e))
        return redirect('appraisal:appraisal_list')
    except Exception as e:
        logger.error(f"Error in appraisal_review for pk {pk}: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred")
        return redirect('appraisal:appraisal_list')


@login_required
@user_passes_test(lambda u: is_manager_or_admin(u) or is_hr_or_admin(u))
def appraisal_dashboard(request):
    """Dashboard view for managers and HR"""
    logger.info(f"Accessing appraisal_dashboard for user: {request.user.username}")
    
    try:
        # Get base queryset
        appraisals = Appraisal.objects.select_related('user', 'manager').all()
        
        # Calculate statistics
        total_appraisals = appraisals.count()
        status_distribution = {}
        
        for status_code, status_label in Appraisal.STATUS_CHOICES:
            count = appraisals.filter(status=status_code).count()
            status_distribution[status_label] = count
        
        # Calculate completion rate
        completed = appraisals.filter(status__in=['approved', 'rejected']).count()
        completion_rate = (completed / total_appraisals * 100) if total_appraisals > 0 else 0
        
        # Get recent appraisals
        recent_appraisals = appraisals.order_by('-created_at')[:10]
        
        # Get pending reviews count
        pending_reviews = appraisals.filter(status='submitted').count()
        
        context = {
            'overview_stats': {
                'total_appraisals': total_appraisals,
                'completed_appraisals': completed,
                'completion_rate': round(completion_rate, 1),
                'pending_reviews': pending_reviews,
            },
            'status_distribution': status_distribution,
            'recent_appraisals': recent_appraisals,
        }
        
        return render(request, 'apprisal/dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error in appraisal_dashboard: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while loading the dashboard")
        return render(request, 'apprisal/dashboard.html', {})


@login_required
@user_passes_test(is_hr_or_admin)
def appraisal_export(request):
    """Export appraisals to CSV (HR only)"""
    logger.info(f"Exporting appraisals for user: {request.user.username}")
    
    try:
        # Get all appraisals with related data
        appraisals = Appraisal.objects.select_related('user', 'manager').all()
        
        # Create the HttpResponse object with CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="appraisals_export.csv"'
        
        writer = csv.writer(response)
        # Write header row
        writer.writerow([
            'Employee Username',
            'Employee Name',
            'Manager Name',
            'Title',
            'Period Start',
            'Period End',
            'Status',
            'Employee Rating',
            'Manager Rating',
            'HR Rating',
            'Overall Rating',
            'Created At',
            'Submitted At',
            'Approved At'
        ])
        
        # Write data rows
        for appraisal in appraisals:
            employee_rating = appraisal.average_employee_rating
            manager_rating = appraisal.average_manager_rating
            hr_rating = appraisal.average_hr_rating
            overall_rating = appraisal.overall_rating
            
            writer.writerow([
                appraisal.user.username,
                appraisal.user.get_full_name() or appraisal.user.username,
                appraisal.manager.get_full_name() if appraisal.manager else 'N/A',
                appraisal.title,
                appraisal.period_start.strftime('%Y-%m-%d') if appraisal.period_start else '',
                appraisal.period_end.strftime('%Y-%m-%d') if appraisal.period_end else '',
                appraisal.get_status_display(),
                f"{employee_rating:.2f}" if employee_rating else 'N/A',
                f"{manager_rating:.2f}" if manager_rating else 'N/A',
                f"{hr_rating:.2f}" if hr_rating else 'N/A',
                f"{overall_rating:.2f}" if overall_rating else 'N/A',
                appraisal.created_at.strftime('%Y-%m-%d %H:%M') if appraisal.created_at else '',
                appraisal.submitted_at.strftime('%Y-%m-%d %H:%M') if appraisal.submitted_at else '',
                appraisal.approved_at.strftime('%Y-%m-%d %H:%M') if appraisal.approved_at else ''
            ])
        
        logger.info(f"Successfully exported {appraisals.count()} appraisals")
        return response
        
    except Exception as e:
        logger.error(f"Error exporting appraisals: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while exporting appraisals")
        return redirect('appraisal:appraisal_dashboard')
