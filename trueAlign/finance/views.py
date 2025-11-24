"""
Views for Finance Module
Handles all finance-related views including expenses, vouchers, bank payments, subscriptions, and invoices
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.db.models import Q, Sum, Count
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import datetime, timedelta
from decimal import Decimal

from trueAlign.models import (
    FinancialParameter, DailyExpense, Voucher, VoucherDetail,
    BankAccount, BankPayment, Subscription, ClientInvoice, ChartOfAccount
)
from .forms import (
    FinancialParameterForm, DailyExpenseForm, ExpenseApprovalForm,
    VoucherForm, VoucherDetailFormSet, BankAccountForm, BankPaymentForm, BankPaymentApprovalForm,
    SubscriptionForm, ClientInvoiceForm, ChartOfAccountForm,
    ExpenseFilterForm, VoucherFilterForm, BankPaymentFilterForm, InvoiceFilterForm
)
from .services import (
    FinancialParameterService, ExpenseService, VoucherService,
    BankPaymentService, SubscriptionService, InvoiceService
)
from .decorators import (
    finance_manager_required, department_head_required, can_approve_expense,
    can_approve_voucher, can_approve_payment
)
from .utils import (
    export_expenses_to_excel, export_vouchers_to_excel, export_bank_payments_to_excel,
    export_invoices_to_excel, export_subscriptions_to_excel
)
from .letterhead import generate_voucher_pdf, generate_invoice_pdf, generate_expense_pdf


# ==================== Dashboard ====================

@login_required
def finance_dashboard(request):
    """Main dashboard for finance module"""
    # Get summary statistics
    today = timezone.now().date()
    this_month_start = today.replace(day=1)
    
    # Expenses
    pending_expenses_count = DailyExpense.objects.filter(status='submitted').count()
    this_month_expenses = DailyExpense.objects.filter(
        date__gte=this_month_start
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    # Vouchers
    pending_vouchers_count = Voucher.objects.filter(
        status__in=['pending_approval', 'pending_finance']
    ).count()
    
    # Bank Payments
    pending_payments_count = BankPayment.objects.filter(
        status__in=['pending', 'verified', 'approved']
    ).count()
    this_month_payments = BankPayment.objects.filter(
        payment_date__gte=this_month_start,
        status='executed'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    # Invoices
    pending_invoice_count = ClientInvoice.objects.filter(status='draft').count()
    overdue_invoice_count = ClientInvoice.objects.filter(status='overdue').count()
    this_month_revenue = ClientInvoice.objects.filter(
        billing_cycle_start__gte=this_month_start,
        status='paid'
    ).aggregate(total=Sum('total_amount'))['total'] or Decimal('0')
    
    # Subscriptions
    upcoming_subscriptions = Subscription.objects.filter(
        status='active',
        next_payment_date__gte=today,
        next_payment_date__lte=today + timedelta(days=30)
    ).order_by('next_payment_date')[:5]
    
    # Recent activities (last 10)
    recent_expenses = DailyExpense.objects.all().order_by('-created_at')[:5]
    recent_vouchers = Voucher.objects.all().order_by('-created_at')[:5]
    
    context = {
        'pending_expenses_count': pending_expenses_count,
        'this_month_expenses': this_month_expenses,
        'pending_vouchers_count': pending_vouchers_count,
        'pending_payments_count': pending_payments_count,
        'this_month_payments': this_month_payments,
        'pending_invoice_count': pending_invoice_count,
        'overdue_invoice_count': overdue_invoice_count,
        'this_month_revenue': this_month_revenue,
        'upcoming_subscriptions': upcoming_subscriptions,
        'recent_expenses': recent_expenses,
        'recent_vouchers': recent_vouchers,
    }
    
    return render(request, 'finance/dashboard.html', context)


# ==================== Financial Parameters ====================

@login_required
@finance_manager_required
def financial_parameter_list(request):
    """List all financial parameters"""
    parameters = FinancialParameter.objects.all().order_by('-created_at')
    
    # Filter by category if provided
    category = request.GET.get('category')
    if category:
        parameters = parameters.filter(category=category)
    
    # Filter by approval status
    is_approved = request.GET.get('is_approved')
    if is_approved == 'true':
        parameters = parameters.filter(is_approved=True)
    elif is_approved == 'false':
        parameters = parameters.filter(is_approved=False)
    
    paginator = Paginator(parameters, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'categories': FinancialParameter.CATEGORY_CHOICES,
    }
    
    return render(request, 'finance/parameters/list.html', context)


@login_required
@finance_manager_required
def financial_parameter_create(request):
    """Create a new financial parameter"""
    if request.method == 'POST':
        form = FinancialParameterForm(request.POST)
        if form.is_valid():
            param = form.save(commit=False)
            param.created_by = request.user
            param.updated_by = request.user
            # Set the value using the helper method
            value = form.cleaned_data.get('value')
            param.set_value(value)
            param.save()
            messages.success(request, f"Financial parameter '{param.name}' created successfully.")
            return redirect('finance:parameter_list')
    else:
        form = FinancialParameterForm()
    
    context = {'form': form}
    return render(request, 'finance/parameters/form.html', context)


@login_required
@finance_manager_required
def financial_parameter_edit(request, pk):
    """Edit a financial parameter"""
    param = get_object_or_404(FinancialParameter, pk=pk)
    
    if request.method == 'POST':
        form = FinancialParameterForm(request.POST, instance=param)
        if form.is_valid():
            param = form.save(commit=False)
            param.updated_by = request.user
            value = form.cleaned_data.get('value')
            param.set_value(value)
            param.save()
            messages.success(request, f"Financial parameter '{param.name}' updated successfully.")
            return redirect('finance:parameter_list')
    else:
        form = FinancialParameterForm(instance=param)
    
    context = {'form': form, 'param': param}
    return render(request, 'finance/parameters/form.html', context)


@login_required
@finance_manager_required
def financial_parameter_approve(request, pk):
    """Approve a financial parameter"""
    param = get_object_or_404(FinancialParameter, pk=pk)
    
    if request.method == 'POST':
        param.approve(request.user)
        messages.success(request, f"Financial parameter '{param.name}' approved successfully.")
        return redirect('finance:parameter_list')
    
    context = {'param': param}
    return render(request, 'finance/parameters/approve.html', context)


# ==================== Daily Expenses ====================

@login_required
def expense_list(request):
    """List all expenses with filters"""
    # Get all expenses with related data
    expenses = DailyExpense.objects.select_related('paid_by', 'approved_by').all()
    
    # Apply filters
    filter_form = ExpenseFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('department'):
            expenses = expenses.filter(department=filter_form.cleaned_data['department'])
        if filter_form.cleaned_data.get('status'):
            expenses = expenses.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('category'):
            expenses = expenses.filter(category=filter_form.cleaned_data['category'])
        if filter_form.cleaned_data.get('date_from'):
            expenses = expenses.filter(date__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            expenses = expenses.filter(date__lte=filter_form.cleaned_data['date_to'])
    
    # If not finance manager, show only own expenses
    if not (request.user.groups.filter(name__in=['Finance', 'Manager']).exists() or request.user.is_superuser):
        expenses = expenses.filter(paid_by=request.user)
    
    expenses = expenses.order_by('-date', '-created_at')
    
    paginator = Paginator(expenses, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_form': filter_form,
    }
    
    return render(request, 'finance/expenses/list.html', context)


@login_required
def expense_create(request):
    """Create a new expense"""
    if request.method == 'POST':
        form = DailyExpenseForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                expense = ExpenseService.create_expense(
                    department=form.cleaned_data['department'],
                    date=form.cleaned_data['date'],
                    category=form.cleaned_data['category'],
                    description=form.cleaned_data['description'],
                    amount=form.cleaned_data['amount'],
                    paid_by=request.user,
                    attachments=form.cleaned_data.get('attachments')
                )
                messages.success(request, f"Expense {expense.expense_id} created successfully.")
                return redirect('finance:expense_detail', pk=expense.pk)
            except Exception as e:
                messages.error(request, f"Error creating expense: {str(e)}")
    else:
        form = DailyExpenseForm()
    
    context = {'form': form}
    return render(request, 'finance/expenses/form.html', context)


@login_required
def expense_detail(request, pk):
    """View expense details"""
    expense = get_object_or_404(DailyExpense, pk=pk)
    
    # Check permission
    can_view = (
        expense.paid_by == request.user or
        request.user.groups.filter(name__in=['Finance', 'Manager']).exists() or
        request.user.is_superuser
    )
    
    if not can_view:
        messages.error(request, "You don't have permission to view this expense.")
        return redirect('finance:expense_list')
    
    context = {'expense': expense}
    return render(request, 'finance/expenses/detail.html', context)


@login_required
def expense_submit(request, pk):
    """Submit expense for approval"""
    expense = get_object_or_404(DailyExpense, pk=pk)
    
    if expense.paid_by != request.user:
        messages.error(request, "You can only submit your own expenses.")
        return redirect('finance:expense_detail', pk=pk)
    
    try:
        ExpenseService.submit_expense(expense.expense_id, request.user)
        messages.success(request, f"Expense {expense.expense_id} submitted for approval.")
    except (PermissionError, ValueError) as e:
        messages.error(request, str(e))
    
    return redirect('finance:expense_detail', pk=pk)


@login_required
@can_approve_expense
def expense_approve(request, pk):
    """Approve or reject an expense"""
    expense = get_object_or_404(DailyExpense, pk=pk)
    
    if request.method == 'POST':
        form = ExpenseApprovalForm(request.POST, instance=expense)
        if form.is_valid():
            status = form.cleaned_data['status']
            rejection_reason = form.cleaned_data.get('rejection_reason')
            
            try:
                if status == 'approved':
                    ExpenseService.approve_expense(expense.expense_id, request.user)
                    messages.success(request, f"Expense {expense.expense_id} approved.")
                elif status == 'rejected':
                    ExpenseService.reject_expense(expense.expense_id, request.user, rejection_reason)
                    messages.success(request, f"Expense {expense.expense_id} rejected.")
                
                return redirect('finance:expense_list')
            except ValueError as e:
                messages.error(request, str(e))
    else:
        form = ExpenseApprovalForm(instance=expense)
    
    context = {'form': form, 'expense': expense}
    return render(request, 'finance/expenses/approve.html', context)


@login_required
@finance_manager_required
def expense_mark_paid(request, pk):
    """Mark expense as paid"""
    expense = get_object_or_404(DailyExpense, pk=pk)
    
    if request.method == 'POST':
        try:
            ExpenseService.mark_as_paid(expense.expense_id)
            messages.success(request, f"Expense {expense.expense_id} marked as paid.")
        except ValueError as e:
            messages.error(request, str(e))
    
    return redirect('finance:expense_detail', pk=pk)


@login_required
def expense_export_excel(request):
    """Export expenses to Excel"""
    expenses = DailyExpense.objects.all().select_related('department', 'paid_by', 'approved_by')
    
    # Apply same filters as list view
    filter_form = ExpenseFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('department'):
            expenses = expenses.filter(department=filter_form.cleaned_data['department'])
        if filter_form.cleaned_data.get('status'):
            expenses = expenses.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('category'):
            expenses = expenses.filter(category=filter_form.cleaned_data['category'])
        if filter_form.cleaned_data.get('date_from'):
            expenses = expenses.filter(date__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            expenses = expenses.filter(date__lte=filter_form.cleaned_data['date_to'])
    
    expenses = expenses.order_by('-date')
    
    # Generate Excel
    excel_file = export_expenses_to_excel(expenses)
    
    # Create response
    response = HttpResponse(
        excel_file.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=expenses_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response


@login_required
def expense_print_pdf(request, pk):
    """Print expense as PDF"""
    expense = get_object_or_404(DailyExpense, pk=pk)
    
    # Generate PDF
    pdf_file = generate_expense_pdf(expense)
    
    # Create response
    response = HttpResponse(pdf_file.read(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename=expense_{expense.expense_id}.pdf'
    
    return response


# ==================== Vouchers ====================

@login_required
def voucher_list(request):
    """List all vouchers with filters"""
    vouchers = Voucher.objects.all().select_related('created_by', 'department_approved_by', 'finance_approved_by')
    
    # Apply filters
    filter_form = VoucherFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('type'):
            vouchers = vouchers.filter(type=filter_form.cleaned_data['type'])
        if filter_form.cleaned_data.get('status'):
            vouchers = vouchers.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('date_from'):
            vouchers = vouchers.filter(date__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            vouchers = vouchers.filter(date__lte=filter_form.cleaned_data['date_to'])
    
    vouchers = vouchers.order_by('-date', '-created_at')
    
    paginator = Paginator(vouchers, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_form': filter_form,
    }
    
    return render(request, 'finance/vouchers/list.html', context)


@login_required
def voucher_create(request):
    """Create a new voucher"""
    if request.method == 'POST':
        form = VoucherForm(request.POST, request.FILES)
        formset = VoucherDetailFormSet(request.POST)
        
        if form.is_valid() and formset.is_valid():
            # Save voucher
            voucher = form.save(commit=False)
            voucher.created_by = request.user
            voucher.save()
            
            # Save voucher details
            formset.instance = voucher
            formset.save()
            
            messages.success(request, f"Voucher {voucher.voucher_number} created successfully.")
            return redirect('finance:voucher_detail', pk=voucher.pk)
    else:
        form = VoucherForm()
        formset = VoucherDetailFormSet()
    
    context = {
        'form': form,
        'formset': formset,
    }
    
    return render(request, 'finance/vouchers/form.html', context)


@login_required
def voucher_detail(request, pk):
    """View voucher details"""
    voucher = get_object_or_404(Voucher.objects.prefetch_related('details__account'), pk=pk)
    
    context = {'voucher': voucher}
    return render(request, 'finance/vouchers/detail.html', context)


@login_required
@department_head_required
def voucher_department_approve(request, pk):
    """Approve voucher at department level"""
    voucher = get_object_or_404(Voucher, pk=pk)
    
    if request.method == 'POST':
        try:
            VoucherService.department_approve(voucher.id, request.user)
            messages.success(request, f"Voucher {voucher.voucher_number} approved at department level.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:voucher_detail', pk=pk)
    
    context = {'voucher': voucher}
    return render(request, 'finance/vouchers/approve.html', context)


@login_required
@finance_manager_required
def voucher_finance_approve(request, pk):
    """Approve voucher at finance level"""
    voucher = get_object_or_404(Voucher, pk=pk)
    
    if request.method == 'POST':
        try:
            VoucherService.finance_approve(voucher.id, request.user)
            messages.success(request, f"Voucher {voucher.voucher_number} approved at finance level.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:voucher_detail', pk=pk)
    
    context = {'voucher': voucher}
    return render(request, 'finance/vouchers/approve.html', context)


@login_required
@finance_manager_required
def voucher_post(request, pk):
    """Post voucher to accounts"""
    voucher = get_object_or_404(Voucher, pk=pk)
    
    if request.method == 'POST':
        try:
            VoucherService.post_to_accounts(voucher.id)
            messages.success(request, f"Voucher {voucher.voucher_number} posted to accounts.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:voucher_detail', pk=pk)
    
    context = {'voucher': voucher}
    return render(request, 'finance/vouchers/post.html', context)


@login_required
def voucher_print_pdf(request, pk):
    """Print voucher as PDF"""
    voucher = get_object_or_404(Voucher.objects.prefetch_related('details__account'), pk=pk)
    
    # Generate PDF
    pdf_file = generate_voucher_pdf(voucher)
    
    # Create response
    response = HttpResponse(pdf_file.read(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename=voucher_{voucher.voucher_number}.pdf'
    
    return response


@login_required
def voucher_export_excel(request):
    """Export vouchers to Excel"""
    vouchers = Voucher.objects.all().select_related('created_by')
    
    # Apply same filters as list view
    filter_form = VoucherFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('type'):
            vouchers = vouchers.filter(type=filter_form.cleaned_data['type'])
        if filter_form.cleaned_data.get('status'):
            vouchers = vouchers.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('date_from'):
            vouchers = vouchers.filter(date__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            vouchers = vouchers.filter(date__lte=filter_form.cleaned_data['date_to'])
    
    vouchers = vouchers.order_by('-date')
    
    # Generate Excel
    excel_file = export_vouchers_to_excel(vouchers)
    
    # Create response
    response = HttpResponse(
        excel_file.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=vouchers_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response


# ==================== Bank Accounts ====================

@login_required
@finance_manager_required
def bank_account_list(request):
    """List all bank accounts"""
    accounts = BankAccount.objects.all().order_by('-is_active', 'bank_name')
    
    context = {'accounts': accounts}
    return render(request, 'finance/bank_accounts/list.html', context)


@login_required
@finance_manager_required
def bank_account_create(request):
    """Create a new bank account"""
    if request.method == 'POST':
        form = BankAccountForm(request.POST)
        if form.is_valid():
            account = form.save()
            messages.success(request, f"Bank account {account.account_number} created successfully.")
            return redirect('finance:bank_account_list')
    else:
        form = BankAccountForm()
    
    context = {'form': form}
    return render(request, 'finance/bank_accounts/form.html', context)


@login_required
@finance_manager_required
def bank_account_edit(request, pk):
    """Edit a bank account"""
    account = get_object_or_404(BankAccount, pk=pk)
    
    if request.method == 'POST':
        form = BankAccountForm(request.POST, instance=account)
        if form.is_valid():
            account = form.save()
            messages.success(request, f"Bank account {account.account_number} updated successfully.")
            return redirect('finance:bank_account_list')
    else:
        form = BankAccountForm(instance=account)
    
    context = {'form': form, 'account': account}
    return render(request, 'finance/bank_accounts/form.html', context)


# ==================== Bank Payments ====================

@login_required
def bank_payment_list(request):
    """List all bank payments with filters"""
    payments = BankPayment.objects.all().select_related('bank_account', 'created_by', 'verified_by', 'approved_by')
    
    # Apply filters
    filter_form = BankPaymentFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('bank_account'):
            payments = payments.filter(bank_account=filter_form.cleaned_data['bank_account'])
        if filter_form.cleaned_data.get('status'):
            payments = payments.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('date_from'):
            payments = payments.filter(payment_date__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            payments = payments.filter(payment_date__lte=filter_form.cleaned_data['date_to'])
    
    payments = payments.order_by('-payment_date', '-created_at')
    
    paginator = Paginator(payments, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_form': filter_form,
    }
    
    return render(request, 'finance/bank_payments/list.html', context)


@login_required
def bank_payment_create(request):
    """Create a new bank payment"""
    if request.method == 'POST':
        form = BankPaymentForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                payment = BankPaymentService.create_payment(
                    bank_account=form.cleaned_data['bank_account'],
                    party_name=form.cleaned_data['party_name'],
                    payment_reason=form.cleaned_data['payment_reason'],
                    amount=form.cleaned_data['amount'],
                    payment_date=form.cleaned_data['payment_date'],
                    created_by=request.user,
                    reference_number=form.cleaned_data.get('reference_number'),
                    attachments=form.cleaned_data.get('attachments')
                )
                messages.success(request, f"Payment {payment.payment_id} created successfully.")
                return redirect('finance:bank_payment_detail', pk=payment.pk)
            except Exception as e:
                messages.error(request, f"Error creating payment: {str(e)}")
    else:
        form = BankPaymentForm()
    
    context = {'form': form}
    return render(request, 'finance/bank_payments/form.html', context)


@login_required
def bank_payment_detail(request, pk):
    """View payment details"""
    payment = get_object_or_404(BankPayment, pk=pk)
    
    context = {'payment': payment}
    return render(request, 'finance/bank_payments/detail.html', context)


@login_required
@can_approve_payment
def bank_payment_verify(request, pk):
    """Verify a payment"""
    payment = get_object_or_404(BankPayment, pk=pk)
    
    if request.method == 'POST':
        try:
            BankPaymentService.verify_payment(payment.id, request.user)
            messages.success(request, f"Payment {payment.payment_id} verified.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:bank_payment_detail', pk=pk)
    
    context = {'payment': payment}
    return render(request, 'finance/bank_payments/verify.html', context)


@login_required
@can_approve_payment
def bank_payment_approve(request, pk):
    """Approve a payment"""
    payment = get_object_or_404(BankPayment, pk=pk)
    
    if request.method == 'POST':
        try:
            BankPaymentService.approve_payment(payment.id, request.user)
            messages.success(request, f"Payment {payment.payment_id} approved.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:bank_payment_detail', pk=pk)
    
    context = {'payment': payment}
    return render(request, 'finance/bank_payments/approve.html', context)


@login_required
@can_approve_payment
def bank_payment_execute(request, pk):
    """Execute a payment"""
    payment = get_object_or_404(BankPayment, pk=pk)
    
    if request.method == 'POST':
        try:
            BankPaymentService.execute_payment(payment.id)
            messages.success(request, f"Payment {payment.payment_id} executed successfully.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:bank_payment_detail', pk=pk)
    
    context = {'payment': payment}
    return render(request, 'finance/bank_payments/execute.html', context)


@login_required
def bank_payment_export_excel(request):
    """Export bank payments to Excel"""
    payments = BankPayment.objects.all().select_related('bank_account', 'created_by')
    
    # Apply same filters as list view
    filter_form = BankPaymentFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('bank_account'):
            payments = payments.filter(bank_account=filter_form.cleaned_data['bank_account'])
        if filter_form.cleaned_data.get('status'):
            payments = payments.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('date_from'):
            payments = payments.filter(payment_date__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            payments = payments.filter(payment_date__lte=filter_form.cleaned_data['date_to'])
    
    payments = payments.order_by('-payment_date')
    
    # Generate Excel
    excel_file = export_bank_payments_to_excel(payments)
    
    # Create response
    response = HttpResponse(
        excel_file.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=bank_payments_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response


# ==================== Subscriptions ====================

@login_required
def subscription_list(request):
    """List all subscriptions"""
    subscriptions = Subscription.objects.all().order_by('next_payment_date')
    
    # Filter by status
    status = request.GET.get('status')
    if status:
        subscriptions = subscriptions.filter(status=status)
    
    # Highlight upcoming renewals
    today = timezone.now().date()
    for sub in subscriptions:
        if sub.status == 'active' and sub.next_payment_date:
            days_until = (sub.next_payment_date - today).days
            sub.days_until_renewal = days_until
            sub.alert_renewal = days_until <= sub.alert_days
    
    paginator = Paginator(subscriptions, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'status_choices': Subscription.STATUS_CHOICES,
    }
    
    return render(request, 'finance/subscriptions/list.html', context)


@login_required
@finance_manager_required
def subscription_create(request):
    """Create a new subscription"""
    if request.method == 'POST':
        form = SubscriptionForm(request.POST)
        if form.is_valid():
            subscription = form.save()
            messages.success(request, f"Subscription '{subscription.name}' created successfully.")
            return redirect('finance:subscription_list')
    else:
        form = SubscriptionForm()
    
    context = {'form': form}
    return render(request, 'finance/subscriptions/form.html', context)


@login_required
@finance_manager_required
def subscription_edit(request, pk):
    """Edit a subscription"""
    subscription = get_object_or_404(Subscription, pk=pk)
    
    if request.method == 'POST':
        form = SubscriptionForm(request.POST, instance=subscription)
        if form.is_valid():
            subscription = form.save()
            messages.success(request, f"Subscription '{subscription.name}' updated successfully.")
            return redirect('finance:subscription_list')
    else:
        form = SubscriptionForm(instance=subscription)
    
    context = {'form': form, 'subscription': subscription}
    return render(request, 'finance/subscriptions/form.html', context)


@login_required
@finance_manager_required
def subscription_renew(request, pk):
    """Renew a subscription"""
    subscription = get_object_or_404(Subscription, pk=pk)
    
    if request.method == 'POST':
        try:
            SubscriptionService.renew_subscription(subscription.id)
            messages.success(request, f"Subscription '{subscription.name}' renewed. Next payment: {subscription.next_payment_date}")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:subscription_list')
    
    context = {'subscription': subscription}
    return render(request, 'finance/subscriptions/renew.html', context)


@login_required
@finance_manager_required
def subscription_cancel(request, pk):
    """Cancel a subscription"""
    subscription = get_object_or_404(Subscription, pk=pk)
    
    if request.method == 'POST':
        SubscriptionService.cancel_subscription(subscription.id)
        messages.success(request, f"Subscription '{subscription.name}' cancelled.")
        return redirect('finance:subscription_list')
    
    context = {'subscription': subscription}
    return render(request, 'finance/subscriptions/cancel.html', context)


@login_required
def subscription_export_excel(request):
    """Export subscriptions to Excel"""
    subscriptions = Subscription.objects.all().order_by('next_payment_date')
    
    # Filter by status if provided
    status = request.GET.get('status')
    if status:
        subscriptions = subscriptions.filter(status=status)
    
    # Generate Excel
    excel_file = export_subscriptions_to_excel(subscriptions)
    
    # Create response
    response = HttpResponse(
        excel_file.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=subscriptions_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response


# ==================== Client Invoices ====================

@login_required
def invoice_list(request):
    """List all invoices with filters"""
    invoices = ClientInvoice.objects.all().select_related('client', 'approved_by')
    
    # Apply filters
    filter_form = InvoiceFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('status'):
            invoices = invoices.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('billing_model'):
            invoices = invoices.filter(billing_model=filter_form.cleaned_data['billing_model'])
        if filter_form.cleaned_data.get('date_from'):
            invoices = invoices.filter(billing_cycle_start__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            invoices = invoices.filter(billing_cycle_end__lte=filter_form.cleaned_data['date_to'])
    
    invoices = invoices.order_by('-created_at')
    
    paginator = Paginator(invoices, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_form': filter_form,
    }
    
    return render(request, 'finance/invoices/list.html', context)


@login_required
@finance_manager_required
def invoice_create(request):
    """Create a new invoice"""
    if request.method == 'POST':
        form = ClientInvoiceForm(request.POST)
        if form.is_valid():
            try:
                invoice = InvoiceService.generate_invoice(
                    client=form.cleaned_data['client'],
                    billing_model=form.cleaned_data['billing_model'],
                    billing_cycle_start=form.cleaned_data['billing_cycle_start'],
                    billing_cycle_end=form.cleaned_data['billing_cycle_end'],
                    rate=form.cleaned_data['rate'],
                    order_count=form.cleaned_data.get('order_count'),
                    fte_count=form.cleaned_data.get('fte_count'),
                    discount=form.cleaned_data.get('discount', 0),
                    due_date=form.cleaned_data.get('due_date')
                )
                messages.success(request, f"Invoice {invoice.invoice_number} created successfully.")
                return redirect('finance:invoice_detail', pk=invoice.pk)
            except Exception as e:
                messages.error(request, f"Error creating invoice: {str(e)}")
    else:
        form = ClientInvoiceForm()
    
    context = {'form': form}
    return render(request, 'finance/invoices/form.html', context)


@login_required
def invoice_detail(request, pk):
    """View invoice details"""
    invoice = get_object_or_404(ClientInvoice, pk=pk)
    
    context = {'invoice': invoice}
    return render(request, 'finance/invoices/detail.html', context)


@login_required
@finance_manager_required
def invoice_approve(request, pk):
    """Approve an invoice"""
    invoice = get_object_or_404(ClientInvoice, pk=pk)
    
    if request.method == 'POST':
        try:
            InvoiceService.approve_invoice(invoice.id, request.user)
            messages.success(request, f"Invoice {invoice.invoice_number} approved.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:invoice_detail', pk=pk)
    
    context = {'invoice': invoice}
    return render(request, 'finance/invoices/approve.html', context)


@login_required
@finance_manager_required
def invoice_send(request, pk):
    """Send invoice to client"""
    invoice = get_object_or_404(ClientInvoice, pk=pk)
    
    if request.method == 'POST':
        try:
            InvoiceService.send_invoice(invoice.id)
            messages.success(request, f"Invoice {invoice.invoice_number} marked as sent.")
            # Here you would typically integrate with email service to send the actual invoice
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:invoice_detail', pk=pk)
    
    context = {'invoice': invoice}
    return render(request, 'finance/invoices/send.html', context)


@login_required
@finance_manager_required
def invoice_mark_paid(request, pk):
    """Mark invoice as paid"""
    invoice = get_object_or_404(ClientInvoice, pk=pk)
    
    if request.method == 'POST':
        try:
            InvoiceService.mark_as_paid(invoice.id)
            messages.success(request, f"Invoice {invoice.invoice_number} marked as paid.")
        except ValueError as e:
            messages.error(request, str(e))
        
        return redirect('finance:invoice_detail', pk=pk)
    
    context = {'invoice': invoice}
    return render(request, 'finance/invoices/mark_paid.html', context)


@login_required
def invoice_print_pdf(request, pk):
    """Print invoice as PDF"""
    invoice = get_object_or_404(ClientInvoice, pk=pk)
    
    # Generate PDF
    pdf_file = generate_invoice_pdf(invoice)
    
    # Create response
    response = HttpResponse(pdf_file.read(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename=invoice_{invoice.invoice_number}.pdf'
    
    return response


@login_required
def invoice_export_excel(request):
    """Export invoices to Excel"""
    invoices = ClientInvoice.objects.all().select_related('client')
    
    # Apply same filters as list view
    filter_form = InvoiceFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data.get('status'):
            invoices = invoices.filter(status=filter_form.cleaned_data['status'])
        if filter_form.cleaned_data.get('billing_model'):
            invoices = invoices.filter(billing_model=filter_form.cleaned_data['billing_model'])
        if filter_form.cleaned_data.get('date_from'):
            invoices = invoices.filter(billing_cycle_start__gte=filter_form.cleaned_data['date_from'])
        if filter_form.cleaned_data.get('date_to'):
            invoices = invoices.filter(billing_cycle_end__lte=filter_form.cleaned_data['date_to'])
    
    invoices = invoices.order_by('-created_at')
    
    # Generate Excel
    excel_file = export_invoices_to_excel(invoices)
    
    # Create response
    response = HttpResponse(
        excel_file.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=invoices_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response


# ==================== Chart of Accounts ====================

@login_required
@finance_manager_required
def chart_of_account_list(request):
    """List all accounts in hierarchy"""
    accounts = ChartOfAccount.objects.filter(parent__isnull=True).prefetch_related('children')
    
    # Filter by account type
    account_type = request.GET.get('account_type')
    if account_type:
        accounts = accounts.filter(account_type=account_type)
    
    context = {
        'accounts': accounts,
        'account_types': ChartOfAccount.ACCOUNT_TYPES,
    }
    
    return render(request, 'finance/chart_of_accounts/list.html', context)


@login_required
@finance_manager_required
def chart_of_account_create(request):
    """Create a new account"""
    if request.method == 'POST':
        form = ChartOfAccountForm(request.POST)
        if form.is_valid():
            account = form.save()
            messages.success(request, f"Account '{account.name}' (Code: {account.code}) created successfully.")
            return redirect('finance:chart_of_account_list')
    else:
        form = ChartOfAccountForm()
    
    context = {'form': form}
    return render(request, 'finance/chart_of_accounts/form.html', context)


@login_required
@finance_manager_required
def chart_of_account_edit(request, pk):
    """Edit an account"""
    account = get_object_or_404(ChartOfAccount, pk=pk)
    
    if request.method == 'POST':
        form = ChartOfAccountForm(request.POST, instance=account)
        if form.is_valid():
            account = form.save()
            messages.success(request, f"Account '{account.name}' updated successfully.")
            return redirect('finance:chart_of_account_list')
    else:
        form = ChartOfAccountForm(instance=account)
    
    context = {'form': form, 'account': account}
    return render(request, 'finance/chart_of_accounts/form.html', context)
