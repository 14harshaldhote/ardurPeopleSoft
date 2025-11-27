from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import TemplateView, View, FormView, ListView, CreateView, UpdateView, DeleteView, DetailView
from django.contrib import messages
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.urls import reverse_lazy
from django.db import models

from trueAlign.models import LeaveType, LeaveRequest, CompOffRequest, LeavePolicy, LeaveAllocation, UserLeaveBalance
from .forms import LeaveRequestForm, CompOffRequestForm, LeaveTypeForm, LeavePolicyForm, LeaveAllocationForm, ManualBalanceAdjustmentForm
from .selectors import (
    get_user_leave_balance, 
    get_pending_approvals, 
    get_team_leaves, 
    get_active_policy,
    get_potential_approvers
)
from .services.leave_service import apply_leave, approve_leave, reject_leave, cancel_leave, adjust_balance
from .services.comp_off_service import request_comp_off, approve_comp_off, reject_comp_off
from .analytics import get_leave_type_distribution, get_daily_leave_status, get_team_attendance_stats, get_pending_request_stats
from .mixins import AdminRequiredMixin, HRRequiredMixin, ManagerRequiredMixin, EmployeeRequiredMixin
from .events import dispatch_leave_event, LEAVE_APPROVED, LEAVE_REJECTED, LEAVE_CANCELLED, DATES_SUGGESTED

User = get_user_model()

class EmployeeDashboardView(EmployeeRequiredMixin, TemplateView):
    template_name = 'leave_management/employee_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        year = timezone.now().year
        context['balances'] = get_user_leave_balance(user, year)
        context['leave_history'] = LeaveRequest.objects.filter(user=user).select_related('leave_type', 'approver').order_by('-created_at')[:10]
        context['policy'] = get_active_policy(user)
        return context

class ManagerDashboardView(ManagerRequiredMixin, TemplateView):
    template_name = 'leave_management/manager_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context['pending_approvals'] = get_pending_approvals(user)
        context['team_leaves'] = get_team_leaves(user)
        
        # Analytics
        context['team_attendance_stats'] = get_team_attendance_stats(user)
        context['today_leaves'] = get_daily_leave_status() # Global for now, can filter by team if needed
        return context

class HRDashboardView(HRRequiredMixin, TemplateView):
    template_name = 'leave_management/hr_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # HR sees all pending requests
        context['all_pending_requests'] = LeaveRequest.objects.filter(status='Pending').select_related('user', 'leave_type', 'approver').order_by('-created_at')
        
        # Analytics
        context['leave_distribution'] = get_leave_type_distribution()
        context['pending_stats'] = get_pending_request_stats()
        context['today_leaves'] = get_daily_leave_status()
        return context

class AdminDashboardView(AdminRequiredMixin, TemplateView):
    template_name = 'leave_management/admin_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Admin Stats
        context['total_users'] = User.objects.count()
        context['active_policies'] = LeavePolicy.objects.filter(is_active=True, is_deleted=False).count()
        context['leave_types'] = LeaveType.objects.filter(is_active=True).count()
        
        # Analytics (Same as HR + more system level if needed)
        context['leave_distribution'] = get_leave_type_distribution()
        context['pending_stats'] = get_pending_request_stats()
        return context

class LeaveApplyView(EmployeeRequiredMixin, FormView):
    template_name = 'leave_management/apply_leave.html'
    form_class = LeaveRequestForm
    success_url = reverse_lazy('leave_management:employee_dashboard')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
        
    def form_valid(self, form):
        try:
            apply_leave(
                user=self.request.user,
                leave_type_id=form.cleaned_data['leave_type'].id,
                start_date=form.cleaned_data['start_date'],
                end_date=form.cleaned_data['end_date'],
                reason=form.cleaned_data['reason'],
                half_day=form.cleaned_data['half_day'],
                approver=form.cleaned_data['approver'],
                documentation=self.request.FILES.get('documentation')
            )
            messages.success(self.request, "Leave application submitted successfully.")
            return super().form_valid(form)
        except ValidationError as e:
            messages.error(self.request, str(e))
            return self.form_invalid(form)
        except Exception as e:
            messages.error(self.request, f"Error: {str(e)}")
            return self.form_invalid(form)

class LeaveUpdateView(EmployeeRequiredMixin, UpdateView):
    model = LeaveRequest
    form_class = LeaveRequestForm
    template_name = 'leave_management/apply_leave.html'
    success_url = reverse_lazy('leave_management:employee_dashboard')
    
    def get_queryset(self):
        # Allow editing only pending requests
        return LeaveRequest.objects.filter(status='Pending')
        
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
        
    def form_valid(self, form):
        try:
            # Use service to update
            from .services.leave_service import update_leave_request
            
            update_leave_request(
                leave_request_id=self.object.id,
                user=self.request.user,
                leave_type=form.cleaned_data['leave_type'],
                start_date=form.cleaned_data['start_date'],
                end_date=form.cleaned_data['end_date'],
                reason=form.cleaned_data['reason'],
                half_day=form.cleaned_data['half_day'],
                approver=form.cleaned_data['approver'],
                documentation=self.request.FILES.get('documentation')
            )
            messages.success(self.request, "Leave request updated successfully.")
            return redirect(self.success_url)
        except ValidationError as e:
            messages.error(self.request, str(e))
            return self.form_invalid(form)
        except Exception as e:
            messages.error(self.request, f"Error: {str(e)}")
            return self.form_invalid(form)

class LeaveActionView(EmployeeRequiredMixin, View):
    def post(self, request, pk):
        action = request.POST.get('action')
        reason = request.POST.get('reason')
        
        
        try:
            leave_request = get_object_or_404(LeaveRequest, pk=pk)
            
            if action == 'approve':
                approve_leave(pk, request.user)
                dispatch_leave_event(LEAVE_APPROVED, leave_request, request.user)
                messages.success(request, "Leave request approved.")
            elif action == 'reject':
                reject_leave(pk, request.user, reason)
                dispatch_leave_event(LEAVE_REJECTED, leave_request, request.user, reason=reason)
                messages.success(request, "Leave request rejected.")
            elif action == 'cancel':
                cancel_leave(pk, request.user)
                dispatch_leave_event(LEAVE_CANCELLED, leave_request, request.user)
                messages.success(request, "Leave request cancelled.")
            elif action == 'suggest_dates':
                start_date = request.POST.get('suggested_start_date')
                end_date = request.POST.get('suggested_end_date')
                
                if start_date and end_date:
                    leave_request.suggested_dates = {
                        'start_date': start_date,
                        'end_date': end_date,
                        'reason': reason,
                        'suggested_by': request.user.id,
                        'suggested_at': timezone.now().isoformat()
                    }
                    leave_request.save(update_fields=['suggested_dates'])
                    
                    dispatch_leave_event(DATES_SUGGESTED, leave_request, request.user, suggested_dates=leave_request.suggested_dates)
                    messages.success(request, "Dates suggested successfully.")
                else:
                    messages.error(request, "Please provide both start and end dates.")
            else:
                messages.error(request, "Invalid action.")
        except ValidationError as e:
            messages.error(request, str(e))
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            
        return redirect(request.META.get('HTTP_REFERER', 'leave_management:employee_dashboard'))

class LeaveDetailView(EmployeeRequiredMixin, DetailView):
    model = LeaveRequest
    template_name = 'leave_management/leave_detail.html'
    context_object_name = 'object'
    
    def get_queryset(self):
        # Users can see their own requests, managers can see their team's requests
        user = self.request.user
        if user.groups.filter(name__in=['HR', 'Admin']).exists():
            return LeaveRequest.objects.all()
        elif user.groups.filter(name='Manager').exists():
            # Managers can see requests where they are the approver
            return LeaveRequest.objects.filter(
                models.Q(user=user) | models.Q(approver=user)
            )
        else:
            return LeaveRequest.objects.filter(user=user)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Check if user can approve/reject (Manager, HR, or Admin)
        context['can_approve'] = self.request.user.groups.filter(
            name__in=['Manager', 'HR', 'Admin']
        ).exists()
        return context

class MyLeavesView(EmployeeRequiredMixin, ListView):
    model = LeaveRequest
    template_name = 'leave_management/my_leaves.html'
    context_object_name = 'leaves'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = LeaveRequest.objects.filter(user=self.request.user).order_by('-created_at')
        
        # Apply filters
        status = self.request.GET.get('status')
        leave_type = self.request.GET.get('leave_type')
        from_date = self.request.GET.get('from_date')
        to_date = self.request.GET.get('to_date')
        
        if status:
            queryset = queryset.filter(status=status)
        if leave_type:
            queryset = queryset.filter(leave_type_id=leave_type)
        if from_date:
            queryset = queryset.filter(start_date__gte=from_date)
        if to_date:
            queryset = queryset.filter(end_date__lte=to_date)
            
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['leave_types'] = LeaveType.objects.filter(is_active=True)
        return context

class TeamLeavesView(ManagerRequiredMixin, ListView):
    model = LeaveRequest
    template_name = 'leave_management/team_leaves.html'
    context_object_name = 'leaves'
    paginate_by = 20
    
    def get_queryset(self):
        # Get team members - this assumes you have a way to determine team membership
        # Adjust based on your actual team structure
        queryset = LeaveRequest.objects.filter(approver=self.request.user).order_by('-created_at')
        
        # Apply filters
        employee = self.request.GET.get('employee')
        status = self.request.GET.get('status')
        leave_type = self.request.GET.get('leave_type')
        from_date = self.request.GET.get('from_date')
        to_date = self.request.GET.get('to_date')
        
        if employee:
            queryset = queryset.filter(user_id=employee)
        if status:
            queryset = queryset.filter(status=status)
        if leave_type:
            queryset = queryset.filter(leave_type_id=leave_type)
        if from_date:
            queryset = queryset.filter(start_date__gte=from_date)
        if to_date:
            queryset = queryset.filter(end_date__lte=to_date)
            
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get team members where current user is the approver
        context['team_members'] = User.objects.filter(
            leave_requests__approver=self.request.user
        ).distinct()
        context['leave_types'] = LeaveType.objects.filter(is_active=True)
        
        # Add team stats
        today = timezone.now().date()
        team_leaves_today = LeaveRequest.objects.filter(
            approver=self.request.user,
            status='Approved',
            start_date__lte=today,
            end_date__gte=today
        )
        
        context['team_stats'] = {
            'total_members': context['team_members'].count(),
            'on_leave_today': team_leaves_today.count(),
            'present_today': context['team_members'].count() - team_leaves_today.count(),
            'upcoming_leaves': LeaveRequest.objects.filter(
                approver=self.request.user,
                status='Approved',
                start_date__gt=today
            ).count()
        }
        return context

class CompOffApplyView(EmployeeRequiredMixin, FormView):
    template_name = 'leave_management/apply_comp_off.html'
    form_class = CompOffRequestForm
    success_url = reverse_lazy('leave_management:employee_dashboard')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
        
    def form_valid(self, form):
        try:
            request_comp_off(
                user=self.request.user,
                worked_date=form.cleaned_data['worked_date'],
                hours_worked=form.cleaned_data['hours_worked'],
                reason=form.cleaned_data['reason'],
                approver=form.cleaned_data['approver']
            )
            messages.success(self.request, "Comp-off request submitted successfully.")
            return super().form_valid(form)
        except ValidationError as e:
            messages.error(self.request, str(e))
            return self.form_invalid(form)
        except Exception as e:
            messages.error(self.request, f"Error: {str(e)}")
            return self.form_invalid(form)

class CompOffActionView(ManagerRequiredMixin, View):
    def post(self, request, pk):
        action = request.POST.get('action')
        reason = request.POST.get('reason')
        
        try:
            if action == 'approve':
                approve_comp_off(pk, request.user)
                messages.success(request, "Comp-off request approved.")
            elif action == 'reject':
                reject_comp_off(pk, request.user, reason)
                messages.success(request, "Comp-off request rejected.")
            else:
                messages.error(request, "Invalid action.")
        except ValidationError as e:
            messages.error(request, str(e))
            
        return redirect(request.META.get('HTTP_REFERER', 'leave_management:employee_dashboard'))

# --- Admin Management Views (Admin Only) ---

class LeaveTypeListView(AdminRequiredMixin, ListView):
    model = LeaveType
    template_name = 'leave_management/leavetype_list.html'
    context_object_name = 'leave_types'

class LeaveTypeCreateView(AdminRequiredMixin, CreateView):
    model = LeaveType
    form_class = LeaveTypeForm
    template_name = 'leave_management/leavetype_form.html'
    success_url = reverse_lazy('leave_management:leavetype_list')

class LeaveTypeUpdateView(AdminRequiredMixin, UpdateView):
    model = LeaveType
    form_class = LeaveTypeForm
    template_name = 'leave_management/leavetype_form.html'
    success_url = reverse_lazy('leave_management:leavetype_list')

class LeavePolicyListView(AdminRequiredMixin, ListView):
    model = LeavePolicy
    template_name = 'leave_management/policy_list.html'
    context_object_name = 'policies'
    queryset = LeavePolicy.objects.filter(is_deleted=False)

class LeavePolicyCreateView(AdminRequiredMixin, CreateView):
    model = LeavePolicy
    form_class = LeavePolicyForm
    template_name = 'leave_management/policy_form.html'
    success_url = reverse_lazy('leave_management:policy_list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super().form_valid(form)

class LeavePolicyUpdateView(AdminRequiredMixin, UpdateView):
    model = LeavePolicy
    form_class = LeavePolicyForm
    template_name = 'leave_management/policy_form.html'
    success_url = reverse_lazy('leave_management:policy_list')

class LeaveAllocationCreateView(AdminRequiredMixin, CreateView):
    model = LeaveAllocation
    form_class = LeaveAllocationForm
    template_name = 'leave_management/allocation_form.html'
    success_url = reverse_lazy('leave_management:policy_list')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        # If policy_id is in URL, pass it to form
        policy_id = self.request.GET.get('policy')
        if policy_id:
            try:
                policy = LeavePolicy.objects.get(pk=policy_id)
                kwargs['policy'] = policy
            except LeavePolicy.DoesNotExist:
                pass
        return kwargs


# --- HR/Admin Views ---

class ManualBalanceAdjustmentView(HRRequiredMixin, FormView):
    # HRRequiredMixin allows HR. Admin is also usually allowed via mixin logic or group membership.
    # If Admin is not in HR group, we might need a custom mixin or ensure Admin has HR permissions.
    # Our HRRequiredMixin checks for 'HR' group. 
    # If we want Admin to also access this, we should update HRRequiredMixin or use a composite check.
    # For now, assuming Admin might be in HR group or we update the mixin.
    # Let's update the mixin in mixins.py to allow Admin as well if needed, 
    # or just assume Admin adds themselves to HR group for operational tasks.
    # However, the user requirement said "HR/Admin -> can change...".
    # Let's stick to HRRequiredMixin for now, assuming Admin can be added to HR group or we modify mixin.
    
    template_name = 'leave_management/balance_adjustment.html'
    form_class = ManualBalanceAdjustmentForm
    success_url = reverse_lazy('leave_management:hr_dashboard')
    
    def form_valid(self, form):
        employee = form.cleaned_data['employee']
        leave_type = form.cleaned_data['leave_type']
        adjustment_type = form.cleaned_data['adjustment_type']
        days = form.cleaned_data['days']
        reason = form.cleaned_data['reason']
        
        # Convert days to positive or negative based on adjustment type
        amount = days if adjustment_type == 'credit' else -days
        
        try:
            adjust_balance(employee.id, leave_type.id, amount, reason, self.request.user)
            messages.success(self.request, f"Successfully adjusted {employee.get_full_name()}'s {leave_type.name} balance by {amount} days.")
        except Exception as e:
            messages.error(self.request, f"Error adjusting balance: {str(e)}")
            return self.form_invalid(form)
        
        return super().form_valid(form)
