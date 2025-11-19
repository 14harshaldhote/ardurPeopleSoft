"""
Service layer for Finance Module
Contains business logic and workflows
"""

from django.utils import timezone
from django.db import transaction
from decimal import Decimal
from trueAlign.models import (
    FinancialParameter, DailyExpense, Voucher, VoucherDetail,
    BankAccount, BankPayment, Subscription, ClientInvoice
)
from .utils import generate_unique_id, calculate_invoice_totals, update_subscription_next_payment


class FinancialParameterService:
    """Service for managing financial parameters"""
    
    @staticmethod
    def create_parameter(key, name, value, value_type, created_by, **kwargs):
        """Create a new financial parameter"""
        param = FinancialParameter(
            key=key,
            name=name,
            value_type=value_type,
            created_by=created_by,
            updated_by=created_by,
            **kwargs
        )
        param.set_value(value)
        param.save()
        return param
    
    @staticmethod
    def approve_parameter(param_id, approved_by):
        """Approve a financial parameter"""
        param = FinancialParameter.objects.get(id=param_id)
        param.approve(approved_by)
        return param
    
    @staticmethod
    def get_active_parameters(category=None, entity=None, fiscal_year=None):
        """Get all active parameters"""
        return FinancialParameter.get_all_params(
            category=category,
            entity=entity,
            fiscal_year=fiscal_year
        )


class ExpenseService:
    """Service for managing daily expenses"""
    
    @staticmethod
    def create_expense(department, date, category, description, amount, paid_by, attachments=None):
        """Create a new expense claim"""
        expense_id = generate_unique_id('EXP', DailyExpense, 'expense_id')
        
        expense = DailyExpense.objects.create(
            expense_id=expense_id,
            department=department,
            date=date,
            category=category,
            description=description,
            amount=amount,
            paid_by=paid_by,
            attachments=attachments,
            status='draft'
        )
        return expense
    
    @staticmethod
    def submit_expense(expense_id, user):
        """Submit expense for approval"""
        expense = DailyExpense.objects.get(expense_id=expense_id)
        
        if expense.paid_by != user:
            raise PermissionError("You can only submit your own expenses")
        
        if expense.status != 'draft':
            raise ValueError("Only draft expenses can be submitted")
        
        expense.status = 'submitted'
        expense.save(update_fields=['status', 'updated_at'])
        return expense
    
    @staticmethod
    @transaction.atomic
    def approve_expense(expense_id, approved_by, rejection_reason=None):
        """Approve an expense"""
        expense = DailyExpense.objects.get(expense_id=expense_id)
        
        if expense.status not in ['submitted', 'approved']:
            raise ValueError("Only submitted expenses can be approved")
        
        expense.status = 'approved'
        expense.approved_by = approved_by
        expense.approved_at = timezone.now()
        expense.save(update_fields=['status', 'approved_by', 'approved_at', 'updated_at'])
        return expense
    
    @staticmethod
    @transaction.atomic
    def reject_expense(expense_id, rejected_by, rejection_reason):
        """Reject an expense"""
        expense = DailyExpense.objects.get(expense_id=expense_id)
        
        if expense.status != 'submitted':
            raise ValueError("Only submitted expenses can be rejected")
        
        expense.status = 'rejected'
        expense.rejection_reason = rejection_reason
        expense.approved_by = rejected_by
        expense.approved_at = timezone.now()
        expense.save(update_fields=['status', 'rejection_reason', 'approved_by', 'approved_at', 'updated_at'])
        return expense
    
    @staticmethod
    def mark_as_paid(expense_id):
        """Mark expense as paid"""
        expense = DailyExpense.objects.get(expense_id=expense_id)
        
        if expense.status != 'approved':
            raise ValueError("Only approved expenses can be marked as paid")
        
        expense.status = 'paid'
        expense.save(update_fields=['status', 'updated_at'])
        return expense


class VoucherService:
    """Service for managing vouchers"""
    
    @staticmethod
    @transaction.atomic
    def create_voucher(voucher_type, date, party_name, purpose, amount, created_by, reference_no=None, attachments=None, details=None):
        """Create a new voucher with details"""
        voucher_number = generate_unique_id('VCH', Voucher, 'voucher_number')
        
        voucher = Voucher.objects.create(
            voucher_number=voucher_number,
            type=voucher_type,
            date=date,
            reference_no=reference_no,
            party_name=party_name,
            purpose=purpose,
            amount=amount,
            created_by=created_by,
            attachments=attachments,
            status='draft'
        )
        
        # Create voucher details if provided
        if details:
            for detail in details:
                VoucherDetail.objects.create(
                    voucher=voucher,
                    account=detail['account'],
                    debit_amount=detail.get('debit_amount', 0),
                    credit_amount=detail.get('credit_amount', 0),
                    description=detail.get('description', '')
                )
        
        return voucher
    
    @staticmethod
    def submit_for_approval(voucher_id):
        """Submit voucher for department approval"""
        voucher = Voucher.objects.get(id=voucher_id)
        
        if voucher.status != 'draft':
            raise ValueError("Only draft vouchers can be submitted")
        
        voucher.status = 'pending_approval'
        voucher.save(update_fields=['status', 'updated_at'])
        return voucher
    
    @staticmethod
    def department_approve(voucher_id, approved_by):
        """Approve voucher at department level"""
        voucher = Voucher.objects.get(id=voucher_id)
        
        if voucher.status != 'pending_approval':
            raise ValueError("Invalid voucher status for department approval")
        
        voucher.status = 'pending_finance'
        voucher.department_approved_by = approved_by
        voucher.save(update_fields=['status', 'department_approved_by', 'updated_at'])
        return voucher
    
    @staticmethod
    def finance_approve(voucher_id, approved_by):
        """Approve voucher at finance level"""
        voucher = Voucher.objects.get(id=voucher_id)
        
        if voucher.status != 'pending_finance':
            raise ValueError("Invalid voucher status for finance approval")
        
        voucher.status = 'approved'
        voucher.finance_approved_by = approved_by
        voucher.save(update_fields=['status', 'finance_approved_by', 'updated_at'])
        return voucher
    
    @staticmethod
    def post_to_accounts(voucher_id):
        """Post voucher to accounts"""
        voucher = Voucher.objects.get(id=voucher_id)
        
        if voucher.status != 'approved':
            raise ValueError("Only approved vouchers can be posted")
        
        # Verify debit-credit balance
        total_debit = sum(d.debit_amount for d in voucher.details.all())
        total_credit = sum(d.credit_amount for d in voucher.details.all())
        
        if total_debit != total_credit:
            raise ValueError("Voucher is not balanced. Debit and credit amounts must be equal.")
        
        voucher.status = 'posted'
        voucher.save(update_fields=['status', 'updated_at'])
        return voucher
    
    @staticmethod
    def reject_voucher(voucher_id):
        """Reject voucher"""
        voucher = Voucher.objects.get(id=voucher_id)
        
        if voucher.status in ['posted', 'rejected']:
            raise ValueError("Cannot reject already posted or rejected voucher")
        
        voucher.status = 'rejected'
        voucher.save(update_fields=['status', 'updated_at'])
        return voucher


class BankPaymentService:
    """Service for managing bank payments"""
    
    @staticmethod
    def create_payment(bank_account, party_name, payment_reason, amount, payment_date, created_by, reference_number=None, attachments=None):
        """Create a new bank payment"""
        payment_id = generate_unique_id('PMT', BankPayment, 'payment_id')
        
        payment = BankPayment.objects.create(
            payment_id=payment_id,
            bank_account=bank_account,
            party_name=party_name,
            payment_reason=payment_reason,
            amount=amount,
            payment_date=payment_date,
            reference_number=reference_number,
            created_by=created_by,
            attachments=attachments,
            status='pending'
        )
        return payment
    
    @staticmethod
    def verify_payment(payment_id, verified_by):
        """Verify a payment"""
        payment = BankPayment.objects.get(id=payment_id)
        
        if payment.status != 'pending':
            raise ValueError("Only pending payments can be verified")
        
        payment.status = 'verified'
        payment.verified_by = verified_by
        payment.save(update_fields=['status', 'verified_by', 'updated_at'])
        return payment
    
    @staticmethod
    def approve_payment(payment_id, approved_by):
        """Approve a payment"""
        payment = BankPayment.objects.get(id=payment_id)
        
        if payment.status != 'verified':
            raise ValueError("Only verified payments can be approved")
        
        payment.status = 'approved'
        payment.approved_by = approved_by
        payment.save(update_fields=['status', 'approved_by', 'updated_at'])
        return payment
    
    @staticmethod
    @transaction.atomic
    def execute_payment(payment_id):
        """Mark payment as executed and update bank balance"""
        payment = BankPayment.objects.select_for_update().get(id=payment_id)
        
        if payment.status != 'approved':
            raise ValueError("Only approved payments can be executed")
        
        bank_account = payment.bank_account
        if bank_account.current_balance < payment.amount:
            raise ValueError("Insufficient balance in bank account")
        
        # Update bank balance
        bank_account.current_balance -= payment.amount
        bank_account.save(update_fields=['current_balance', 'updated_at'])
        
        payment.status = 'executed'
        payment.save(update_fields=['status', 'updated_at'])
        return payment
    
    @staticmethod
    def mark_as_failed(payment_id):
        """Mark payment as failed"""
        payment = BankPayment.objects.get(id=payment_id)
        
        if payment.status != 'approved':
            raise ValueError("Only approved payments can be marked as failed")
        
        payment.status = 'failed'
        payment.save(update_fields=['status', 'updated_at'])
        return payment


class SubscriptionService:
    """Service for managing subscriptions"""
    
    @staticmethod
    def create_subscription(name, vendor, subscription_type, amount, frequency, start_date, next_payment_date, **kwargs):
        """Create a new subscription"""
        subscription = Subscription.objects.create(
            name=name,
            vendor=vendor,
            subscription_type=subscription_type,
            amount=amount,
            frequency=frequency,
            start_date=start_date,
            next_payment_date=next_payment_date,
            **kwargs
        )
        return subscription
    
    @staticmethod
    def renew_subscription(subscription_id):
        """Renew a subscription and update next payment date"""
        subscription = Subscription.objects.get(id=subscription_id)
        
        if subscription.status != 'active':
            raise ValueError("Only active subscriptions can be renewed")
        
        update_subscription_next_payment(subscription)
        return subscription
    
    @staticmethod
    def cancel_subscription(subscription_id):
        """Cancel a subscription"""
        subscription = Subscription.objects.get(id=subscription_id)
        subscription.status = 'cancelled'
        subscription.save(update_fields=['status', 'updated_at'])
        return subscription
    
    @staticmethod
    def get_upcoming_renewals(days=30):
        """Get subscriptions due for renewal"""
        from .utils import get_upcoming_subscriptions
        return get_upcoming_subscriptions(days)


class InvoiceService:
    """Service for managing client invoices"""
    
    @staticmethod
    def generate_invoice(client, billing_model, billing_cycle_start, billing_cycle_end, rate, 
                        order_count=None, fte_count=None, discount=0, due_date=None):
        """Generate a client invoice"""
        invoice_number = generate_unique_id('INV', ClientInvoice, 'invoice_number')
        
        # Get tax rate from financial parameters
        tax_rate = FinancialParameter.get_param('gst_rate', category='tax') or Decimal('0.18')
        
        # Calculate totals
        totals = calculate_invoice_totals(
            billing_model=billing_model,
            order_count=order_count,
            fte_count=fte_count,
            rate=rate,
            tax_rate=tax_rate,
            discount=discount
        )
        
        # Set due date if not provided (default 30 days from cycle end)
        if not due_date:
            from datetime import timedelta
            due_date = billing_cycle_end + timedelta(days=30)
        
        invoice = ClientInvoice.objects.create(
            invoice_number=invoice_number,
            client=client,
            billing_model=billing_model,
            billing_cycle_start=billing_cycle_start,
            billing_cycle_end=billing_cycle_end,
            order_count=order_count,
            fte_count=fte_count,
            rate=rate,
            subtotal=totals['subtotal'],
            tax_amount=totals['tax_amount'],
            discount=discount,
            total_amount=totals['total_amount'],
            due_date=due_date,
            status='draft'
        )
        return invoice
    
    @staticmethod
    def approve_invoice(invoice_id, approved_by):
        """Approve an invoice"""
        invoice = ClientInvoice.objects.get(id=invoice_id)
        
        if invoice.status != 'draft':
            raise ValueError("Only draft invoices can be approved")
        
        invoice.status = 'approved'
        invoice.approved_by = approved_by
        invoice.save(update_fields=['status', 'approved_by', 'updated_at'])
        return invoice
    
    @staticmethod
    def send_invoice(invoice_id):
        """Mark invoice as sent to client"""
        invoice = ClientInvoice.objects.get(id=invoice_id)
        
        if invoice.status not in ['approved', 'draft']:
            raise ValueError("Invoice must be approved before sending")
        
        invoice.status = 'sent'
        invoice.save(update_fields=['status', 'updated_at'])
        return invoice
    
    @staticmethod
    def mark_as_paid(invoice_id):
        """Mark invoice as paid"""
        invoice = ClientInvoice.objects.get(id=invoice_id)
        
        if invoice.status not in ['sent', 'approved', 'overdue']:
            raise ValueError("Invalid invoice status for payment")
        
        invoice.status = 'paid'
        invoice.save(update_fields=['status', 'updated_at'])
        return invoice
    
    @staticmethod
    def mark_overdue_invoices():
        """Mark invoices as overdue"""
        from .utils import get_overdue_invoices
        overdue_invoices = get_overdue_invoices()
        
        for invoice in overdue_invoices:
            invoice.status = 'overdue'
            invoice.save(update_fields=['status', 'updated_at'])
        
        return overdue_invoices.count()
