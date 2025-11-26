from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import transaction
from trueAlign.models import LeaveRequest, LeaveType, UserLeaveBalance, LeaveRequestHistory

def apply_leave(user, leave_type_id, start_date, end_date, reason, half_day=False, approver=None, documentation=None, is_retroactive=False):
    """
    Apply for leave with strict business rules.
    """
    try:
        leave_type = LeaveType.objects.get(id=leave_type_id)
    except LeaveType.DoesNotExist:
        raise ValidationError("Invalid leave type")

    # Rule 10.1: Retroactive Leave
    today = timezone.localdate()
    # Ensure start_date is a date object
    if isinstance(start_date, str):
        start_date = timezone.datetime.strptime(start_date, "%Y-%m-%d").date()
        
    if start_date < today:
        is_retroactive = True
        # Check limit (e.g., 15 days)
        if (today - start_date).days > 15:
            # Rule 10.1: For very old dates, HR needs to step in. 
            # We allow creation but flag it, or reject if user is not HR.
            # Here we'll enforce the limit for regular employees.
            if not (user.groups.filter(name='HR').exists() or user.is_superuser):
                raise ValidationError("Retroactive leave cannot be applied for dates older than 15 days. Please contact HR.")

    leave_request = LeaveRequest(
        user=user,
        leave_type=leave_type,
        start_date=start_date,
        end_date=end_date,
        reason=reason,
        half_day=half_day,
        approver=approver,
        documentation=documentation,
        status='Pending',
        is_retroactive=is_retroactive
    )
    
    # Rule 11.1: Loss of Pay (LOP) - Insufficient Balance
    # Check balance before saving (which triggers clean())
    # Note: clean() calls has_sufficient_balance() which returns False if insufficient.
    # We want to intercept this to handle LOP auto-conversion or warning.
    if leave_request.leave_type.is_paid and not leave_request.has_sufficient_balance():
        # Try to find LOP leave type
        try:
            lop_type = LeaveType.objects.get(name='Loss of Pay', is_paid=False)
            # Auto-convert logic (Option A from requirements)
            # Or we could raise a specific error code to UI to ask for confirmation.
            # For now, we will auto-convert if LOP exists.
            leave_request.leave_type = lop_type
            # Re-validate balance (should be True for unpaid)
        except LeaveType.DoesNotExist:
            # If no LOP type, let standard validation fail
            pass

    # Validation happens in clean() which is called by save() or full_clean()
    leave_request.full_clean()
    leave_request.save()
    
    # Log history
    LeaveRequestHistory.log_action(
        leave_request=leave_request,
        action='created',
        performed_by=user,
        reason="Leave application submitted"
    )
    
    return leave_request

def update_leave_request(leave_request_id, user, **kwargs):
    """
    Update a pending leave request with strict edit rules (Rule 2.1).
    """
    with transaction.atomic():
        leave_request = LeaveRequest.objects.select_for_update().get(id=leave_request_id)
        
        if leave_request.status != 'Pending':
            raise ValidationError(f"Cannot edit leave in {leave_request.status} status")
            
        is_hr = user.groups.filter(name='HR').exists() or user.is_superuser
        is_manager = user.groups.filter(name='Manager').exists()
        is_owner = user == leave_request.user
        
        # Rule 2.1: Who can edit what?
        if is_owner:
            # Employee can edit all fields if Pending
            pass
        elif is_hr:
            # HR can edit all fields
            pass
        elif is_manager:
            # Manager can ONLY add comments (which we might handle separately) or minor things.
            # STRICT RULE: Manager CANNOT change dates/type/duration.
            # If kwargs contain core fields, reject.
            core_fields = ['start_date', 'end_date', 'leave_type', 'half_day']
            for field in core_fields:
                if field in kwargs and kwargs[field] != getattr(leave_request, field):
                     raise ValidationError("Managers cannot edit core leave details. Please ask the employee to resubmit or contact HR.")
        else:
            raise ValidationError("You do not have permission to edit this request.")
            
        # Apply updates
        for key, value in kwargs.items():
            if hasattr(leave_request, key):
                setattr(leave_request, key, value)
                
        leave_request.full_clean()
        leave_request.save()
        
        LeaveRequestHistory.log_action(
            leave_request=leave_request,
            action='updated',
            performed_by=user,
            reason="Leave request updated"
        )
        
        return leave_request

def approve_leave(leave_request_id, approver, reason=None):
    """
    Approve a leave request.
    """
    with transaction.atomic():
        leave_request = LeaveRequest.objects.select_for_update().get(id=leave_request_id)
        
        if leave_request.status != 'Pending':
            raise ValidationError(f"Cannot approve leave in {leave_request.status} status")
            
        # Rule 3.1: Manager can approve team, HR can approve anyone.
        # This check is usually done in the view/permission layer, but good to have here too.
        is_hr = approver.groups.filter(name='HR').exists() or approver.is_superuser
        if not is_hr and leave_request.user == approver:
             raise ValidationError("You cannot approve your own leave.")
             
        leave_request.status = 'Approved'
        leave_request._approved_by = approver
        leave_request.save()
        
        return leave_request

def reject_leave(leave_request_id, approver, rejection_reason):
    """
    Reject a leave request.
    """
    with transaction.atomic():
        leave_request = LeaveRequest.objects.select_for_update().get(id=leave_request_id)
        
        if leave_request.status != 'Pending':
            raise ValidationError(f"Cannot reject leave in {leave_request.status} status")
            
        leave_request.status = 'Rejected'
        leave_request.rejection_reason = rejection_reason
        leave_request._modified_by = approver
        leave_request.save()
        
        return leave_request

def cancel_leave(leave_request_id, user):
    """
    Cancel a leave request with strict Rule 4.1 enforcement.
    """
    with transaction.atomic():
        leave_request = LeaveRequest.objects.select_for_update().get(id=leave_request_id)
        
        is_hr = user.groups.filter(name='HR').exists() or user.is_superuser
        is_manager = user.groups.filter(name='Manager').exists()
        is_owner = user == leave_request.user
        
        # Rule 4.1.1: Employee cancelling own leave
        if is_owner:
            if leave_request.status == 'Pending':
                pass # Allowed
            elif leave_request.status == 'Approved':
                # Allowed only if future leave (start_date >= today)
                if leave_request.start_date < timezone.localdate():
                     if not is_hr: # Only HR can cancel past approved leave
                        raise ValidationError("Cannot cancel past leave. Please contact HR.")
            else:
                raise ValidationError(f"Cannot cancel leave in {leave_request.status} status")
                
        # Rule 4.1.2: Manager cancelling team member's leave
        elif is_manager and not is_hr:
             # Check if user is in manager's team (simplified check, assuming approver link)
             # Ideally we check reporting structure. For now, we check if manager is the designated approver.
             if leave_request.approver != user:
                 # If not direct approver, maybe check if in team (needs Team model or similar)
                 # For now, restrict to designated approver.
                 raise ValidationError("You can only cancel leaves for your team members.")
                 
             if leave_request.status == 'Approved' and leave_request.start_date < timezone.localdate():
                 raise ValidationError("Managers cannot cancel past leaves. Please contact HR.")
                 
        # Rule 4.1.3: HR/Admin cancelling
        elif is_hr:
            pass # HR can cancel anything
            
        else:
            raise ValidationError("You do not have permission to cancel this leave request")

        leave_request.status = 'Cancelled'
        leave_request._modified_by = user
        leave_request.save()
        
        return leave_request

def adjust_balance(user_id, leave_type_id, amount, reason, adjusted_by):
    """
    Manually adjust user leave balance (Rule 9.1).
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    # Rule 9.1: Only HR/Admin can manually adjust
    if not (adjusted_by.groups.filter(name='HR').exists() or adjusted_by.is_superuser):
        raise ValidationError("Only HR or Admin can manually adjust leave balances.")

    with transaction.atomic():
        user = User.objects.get(id=user_id)
        leave_type = LeaveType.objects.get(id=leave_type_id)
        year = timezone.now().year
        
        balance, created = UserLeaveBalance.objects.select_for_update().get_or_create(
            user=user,
            leave_type=leave_type,
            year=year,
            defaults={
                'allocated': 0,
                'used': 0,
                'carried_forward': 0,
                'additional': 0
            }
        )
        
        # Add to 'additional' field as per requirement
        balance.additional += amount
        balance.save()
        
        # Log this action
        # We can create a dummy LeaveRequestHistory entry or use a specific log model if available.
        # Since LeaveRequestHistory needs a leave_request, we'll skip it for now and rely on logger.
        # Ideally, we should have a BalanceAdjustmentLog model.
        
        return balance
