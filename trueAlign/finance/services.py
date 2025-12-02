"""
Service layer for Finance Module
Contains business logic and workflows
"""

from django.utils import timezone
from django.db import transaction
from decimal import Decimal
from trueAlign.models import (
    FinancialParameter, DailyExpense, Voucher, VoucherDetail,
    BankAccount, BankPayment, Subscription, ClientInvoice,
    CashBox, CashTransaction, PaymentAllocation, PayrollAdjustment, ShadowEntry,
    BankStatement, BankStatementLine
)
from .utils import generate_unique_id, calculate_invoice_totals, update_subscription_next_payment
from trueAlign.finance.nlp.core import FinanceNLPProcessor


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
        from .integration_service import FinanceIntegrationService
        
        expense_id = generate_unique_id('EXP', DailyExpense, 'expense_id')
        
        # Initialize integration service
        service = FinanceIntegrationService()
        
        # Prepare expense data for processing
        expense_data = {
            'description': description,
            'amount': amount,
            'department': department,
            'category': category,
            'date': date,
            'attachments': attachments
        }
        
        # Run intelligent processing (Auto-categorize + Rules + NLP)
        processed = service.process_new_expense(expense_data)
        
        # Use auto-categorized value if original category was empty/misc
        final_category = category
        if not final_category or final_category.lower() in ['misc', 'miscellaneous', 'other']:
            if processed.get('category') and processed.get('category_confidence', 0) > 80:
                final_category = processed['category']
        
        # Run Legacy NLP Analysis (keeping for backward compatibility)
        nlp_result = FinanceNLPProcessor.analyze_transaction(description, amount)
        
        expense = DailyExpense.objects.create(
            expense_id=expense_id,
            department=department,
            date=date,
            category=final_category,
            description=description,
            amount=amount,
            paid_by=paid_by,
            attachments=attachments,
            status='draft',
            # NLP Fields
            nlp_data=nlp_result,
            risk_score=nlp_result['risk_score'],
            risk_factors=nlp_result['risk_factors'],
            normalized_description=nlp_result['normalized_text'],
            # New Automation Fields
            auto_matched=processed.get('auto_approved', False),
            match_confidence=processed.get('category_confidence', 0)
        )
        
        # Apply auto-approval rule if triggered
        if processed.get('auto_approved'):
            expense.status = 'approved'
            expense.approved_by = None  # System approval
            expense.approved_at = timezone.now()
            expense.save()
            
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


class CashService:
    """Service for managing Cash Boxes and Transactions"""

    @staticmethod
    def create_cash_box(name, location, managed_by):
        """Create a new cash box"""
        return CashBox.objects.create(
            name=name,
            location=location,
            managed_by=managed_by,
            balance=0
        )

    @staticmethod
    @transaction.atomic
    def record_transaction(box_id, txn_type, amount, performed_by, description, related_bank_payment_id=None):
        """
        Record a cash transaction (Deposit, Withdrawal, Expense).
        Updates the box balance automatically.
        """
        
        box = CashBox.objects.select_for_update().get(id=box_id)
        
        # Validate Balance for Outflows
        if txn_type in ['WITHDRAWAL', 'EXPENSE', 'TRANSFER'] and box.balance < amount:
            raise ValueError(f"Insufficient cash balance in {box.name}. Current: {box.balance}, Required: {amount}")

        # Run NLP Analysis
        nlp_result = FinanceNLPProcessor.analyze_transaction(description, amount)

        # Create Transaction
        txn = CashTransaction.objects.create(
            box=box,
            type=txn_type,
            amount=amount,
            performed_by=performed_by,
            description=description,
            related_bank_payment_id=related_bank_payment_id,
            # NLP Fields
            nlp_data=nlp_result,
            risk_score=nlp_result['risk_score'],
            risk_factors=nlp_result['risk_factors'],
            normalized_description=nlp_result['normalized_text']
        )

        # Update Balance
        if txn_type == 'DEPOSIT':
            box.balance += amount
        else:
            box.balance -= amount
        
        box.save()
        return txn

    @staticmethod
    @transaction.atomic
    def withdraw_from_bank_to_cash(bank_payment_id, target_box_id, performed_by):
        """
        Special workflow: Withdraw cash from Bank -> Put into Cash Box.
        1. Verify BankPayment is 'executed'.
        2. Create CashTransaction (DEPOSIT) linked to BankPayment.
        """
        
        payment = BankPayment.objects.get(id=bank_payment_id)
        if payment.status != 'executed':
            raise ValueError("Bank payment must be executed before cash can be received.")
        
        # Create the deposit in cash box
        return CashService.record_transaction(
            box_id=target_box_id,
            txn_type='DEPOSIT',
            amount=payment.amount,
            performed_by=performed_by,
            description=f"Cash withdrawal from Bank (Ref: {payment.payment_id})",
            related_bank_payment_id=bank_payment_id
        )


class PaymentAllocationService:
    """
    Service for the 'Bridge' logic (Allocating Payments to Expenses).
    """

    @staticmethod
    @transaction.atomic
    def allocate_payment(expense_id, amount, payment_source_type, source_id):
        """
        Allocate a payment (Bank or Cash) to an Expense.
        """
        
        expense = DailyExpense.objects.get(expense_id=expense_id)
        
        # Validate Source
        bank_payment = None
        cash_txn = None
        
        if payment_source_type == 'BANK':
            bank_payment = BankPayment.objects.get(id=source_id)
        elif payment_source_type == 'CASH':
            cash_txn = CashTransaction.objects.get(id=source_id)
        else:
            raise ValueError("Invalid payment source type")

        # Create Allocation
        allocation = PaymentAllocation.objects.create(
            payment_source_type=payment_source_type,
            bank_payment=bank_payment,
            cash_transaction=cash_txn,
            expense=expense,
            amount_allocated=amount
        )

        # Update Expense Status logic
        # Check total allocated vs expense amount
        total_allocated = sum(a.amount_allocated for a in expense.allocations.all()) # type: ignore
        
        if total_allocated >= expense.amount:
            expense.status = 'paid'
            expense.save(update_fields=['status'])
            
        return allocation


class PayrollRealityService:
    """Service for Real vs Formal Payroll tracking"""

    @staticmethod
    def record_payroll_adjustment(employee, month, formal_amount, actual_bank, actual_cash, returned_cash, reason, created_by):
        """
        Record the complex reality of a payroll month for an employee.
        """
        
        adj, created = PayrollAdjustment.objects.update_or_create(
            employee=employee,
            month=month,
            defaults={
                'formal_salary_payable': formal_amount,
                'actual_payout_bank': actual_bank,
                'actual_payout_cash': actual_cash,
                'cash_returned_by_employee': returned_cash,
                'adjustment_reason': reason,
                'created_by': created_by,
                'is_shadow_record': True
            }
        )
        return adj


class ReconciliationService:
    """
    Service for Bank Reconciliation and Intelligence.
    """

    @staticmethod
    def import_statement(bank_account_id, file_path, uploaded_by):
        """
        Import a Bank Statement (CSV or PDF) and create StatementLines.
        """
        import csv
        from datetime import datetime
        from decimal import Decimal
        from django.utils import timezone
        from trueAlign.models import BankStatement, BankStatementLine, BankAccount
        from .integration_service import FinanceIntegrationService
        
        account = BankAccount.objects.get(id=bank_account_id)
        service = FinanceIntegrationService()
        
        # Create Statement Header
        statement = BankStatement.objects.create(
            bank_account=account,
            file=file_path,
            period_start=timezone.now().date(), # Placeholder
            period_end=timezone.now().date(),   # Placeholder
            uploaded_by=uploaded_by
        )
        
        lines_created = 0
        min_date = None
        max_date = None
        
        # Check file type
        is_pdf = str(file_path).lower().endswith('.pdf')
        
        try:
            if is_pdf:
                # Process PDF using new parser
                result = service.process_bank_statement_pdf(file_path)
                transactions = result['transactions']
                
                for txn in transactions:
                    BankStatementLine.objects.create(
                        statement=statement,
                        date=txn['date'],
                        description=txn['description'],
                        amount=txn['amount'],
                        reference_no=txn.get('reference_no', ''),
                        # Enhanced Fields
                        vendor=txn.get('vendor_normalized'),
                        category=txn.get('category'),
                        match_confidence=txn.get('category_confidence', 0)
                    )
                    lines_created += 1
                    
                    if not min_date or txn['date'] < min_date:
                        min_date = txn['date']
                    if not max_date or txn['date'] > max_date:
                        max_date = txn['date']
                        
            else:
                # Process CSV (Legacy + Enhanced)
                with open(file_path, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        try:
                            date_str = row.get('Date')
                            desc = row.get('Description')
                            ref = row.get('Reference')
                            amount_str = row.get('Amount')
                            
                            if not (date_str and amount_str):
                                continue
                                
                            txn_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                            amount = Decimal(amount_str)
                            
                            # Run Intelligent Processing
                            processed = service.process_new_expense({
                                'description': desc,
                                'amount': amount,
                                'date': txn_date
                            })
                            
                            BankStatementLine.objects.create(
                                statement=statement,
                                date=txn_date,
                                description=desc,
                                amount=amount,
                                reference_no=ref,
                                # Enhanced Fields
                                vendor=processed.get('vendor_normalized'),
                                category=processed.get('category'),
                                match_confidence=processed.get('category_confidence', 0)
                            )
                            
                            lines_created += 1
                            
                            if not min_date or txn_date < min_date:
                                min_date = txn_date
                            if not max_date or txn_date > max_date:
                                max_date = txn_date
                                
                        except Exception as e:
                            print(f"Error parsing row {row}: {e}")
                            continue
        
        except Exception as e:
            statement.delete()
            raise e
        
        # Update Statement Meta
        if min_date and max_date:
            statement.period_start = min_date
            statement.period_end = max_date
            
        statement.total_lines = lines_created
        statement.is_processed = True
        statement.save()
        
        return statement

    @staticmethod
    def auto_reconcile(statement_id):
        """
        The 'Intelligence' Engine.
        Matches StatementLines to BankPayments using advanced matching.
        """
        from trueAlign.models import BankStatement, BankPayment
        from .integration_service import FinanceIntegrationService
        
        statement = BankStatement.objects.get(id=statement_id)
        unreconciled_lines = statement.lines.filter(is_reconciled=False)
        
        # Get all executed payments for the period (+ buffer)
        period_start = statement.period_start
        period_end = statement.period_end
        
        # Fetch candidate payments
        candidate_payments = list(BankPayment.objects.filter(
            bank_account=statement.bank_account,
            status='executed',
            reconciled_lines__isnull=True  # Not yet reconciled
        ).values('id', 'payment_date', 'amount', 'party_name', 'payment_reason'))
        
        # Map to format expected by matcher
        internal_records = []
        payment_map = {}
        
        for p in candidate_payments:
            record = {
                'date': p['payment_date'],
                'amount': p['amount'],
                'description': f"{p['party_name']} {p['payment_reason']}",
                'id': p['id']
            }
            internal_records.append(record)
            payment_map[p['id']] = p
            
        # Run matching
        service = FinanceIntegrationService()
        
        # Convert lines to dicts
        bank_txns = []
        line_map = {}
        for line in unreconciled_lines:
            # Only reconcile withdrawals (debits) against payments
            if line.amount < 0:
                txn = {
                    'date': line.date,
                    'amount': abs(line.amount),
                    'description': line.description,
                    'id': line.id
                }
                bank_txns.append(txn)
                line_map[line.id] = line
        
        # Match
        results = service.match_bank_to_internal(bank_txns, internal_records)
        
        matches_found = 0
        
        # Process matches
        for match in results['matches']:
            line_id = match['bank_transaction']['id']
            best_match = match['best_match']
            
            if best_match and best_match[1] >= 85:  # High confidence threshold
                payment_id = best_match[0]['id']
                confidence = best_match[1]
                
                line = line_map[line_id]
                payment = BankPayment.objects.get(id=payment_id)
                
                line.matched_payment = payment
                line.is_reconciled = True
                line.reconciled_at = timezone.now()
                line.match_confidence = confidence / 100.0
                line.match_notes = f"Auto-matched (Confidence: {confidence}%)"
                line.save()
                
                matches_found += 1
        
        statement.reconciled_lines += matches_found
        statement.save()
        
        return matches_found


class FinanceIntelligenceService:
    """
    Service for Pattern Detection and Anomaly Analysis.
    """

    @staticmethod
    def detect_round_number_anomalies(threshold=1000):
        """
        Find transactions with round numbers (e.g., 5000.00, 10000.00) 
        that are often indicative of estimates or potential fraud in certain contexts.
        """
        from trueAlign.models import DailyExpense, CashTransaction
        from django.db.models import F
        
        # Expenses ending in .00 and > threshold
        round_expenses = DailyExpense.objects.filter(
            amount__gt=threshold,
            amount__iregex=r'\.00$' # Simple regex for round numbers
        ).values('expense_id', 'amount', 'description', 'paid_by__username')
        
        # Cash Txns ending in .00
        round_cash = CashTransaction.objects.filter(
            amount__gt=threshold,
            amount__iregex=r'\.00$'
        ).values('id', 'type', 'amount', 'description', 'performed_by__username')
        
        return {
            'expenses': list(round_expenses),
            'cash_txns': list(round_cash)
        }

    @staticmethod
    def detect_high_cash_volume_employees(month_start, month_end, threshold=50000):
        """
        Identify employees handling excessive cash.
        """
        from trueAlign.models import CashTransaction
        from django.db.models import Sum
        
        high_volume = CashTransaction.objects.filter(
            date__range=(month_start, month_end)
        ).values('performed_by__username').annotate(
            total_cash=Sum('amount')
        ).filter(total_cash__gt=threshold).order_by('-total_cash')
        
        return list(high_volume)

    @staticmethod
    def detect_duplicate_vendor_payments(days_window=7):
        """
        Find payments to same vendor with same amount within a short window.
        """
        from trueAlign.models import BankPayment
        from django.db import connection
        
        # Complex query, easier with raw SQL or window functions
        # Using self-join logic via ORM
        
        duplicates = []
        payments = BankPayment.objects.filter(status='executed').order_by('party_name', 'amount', 'payment_date')
        
        # Naive iteration for simplicity (O(N) since sorted)
        # For production with millions of rows, use Window functions
        
        prev = None
        for p in payments:
            if prev and p.party_name == prev.party_name and p.amount == prev.amount:
                delta = p.payment_date - prev.payment_date
                if delta.days <= days_window:
                    duplicates.append({
                        'vendor': p.party_name,
                        'amount': p.amount,
                        'payment1': {'id': prev.payment_id, 'date': prev.payment_date},
                        'payment2': {'id': p.payment_id, 'date': p.payment_date}
                    })
            prev = p
            
        return duplicates