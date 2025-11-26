from django.core.exceptions import ValidationError
from django.db import transaction
from trueAlign.models import CompOffRequest

def request_comp_off(user, worked_date, hours_worked, reason, approver=None):
    """
    Request comp-off for worked hours.
    """
    comp_off_request = CompOffRequest(
        user=user,
        worked_date=worked_date,
        hours_worked=hours_worked,
        reason=reason,
        approver=approver,
        status='Pending'
    )
    comp_off_request.full_clean()
    comp_off_request.save()
    return comp_off_request

def approve_comp_off(request_id, approver):
    """
    Approve comp-off request.
    """
    with transaction.atomic():
        req = CompOffRequest.objects.select_for_update().get(id=request_id)
        if req.status != 'Pending':
            raise ValidationError("Request is not pending")
            
        req.status = 'Approved'
        req.save()
        return req

def reject_comp_off(request_id, approver, reason):
    """
    Reject comp-off request.
    """
    with transaction.atomic():
        req = CompOffRequest.objects.select_for_update().get(id=request_id)
        if req.status != 'Pending':
            raise ValidationError("Request is not pending")
            
        req.status = 'Rejected'
        req.rejection_reason = reason
        req.save()
        return req
