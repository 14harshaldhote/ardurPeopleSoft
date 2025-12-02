"""
Finance Module - Business Rules Engine
Configurable rule-based automation using business-rules library
"""

from business_rules.engine import run_all
from business_rules.variables import BaseVariables, numeric_rule_variable, string_rule_variable, boolean_rule_variable
from business_rules.actions import BaseActions, rule_action
from business_rules.fields import FIELD_NUMERIC, FIELD_TEXT, FIELD_SELECT
from decimal import Decimal
import logging

logger = logging.getLogger('finance')


# ============================================
# EXPENSE VARIABLES (for rule conditions)
# ============================================

class ExpenseVariables(BaseVariables):
    """Variables available for expense rules"""
    
    def __init__(self, expense):
        self.expense = expense
    
    @numeric_rule_variable(label='Amount')
    def amount(self):
        """Expense amount"""
        return float(self.expense.get('amount', 0))
    
    @string_rule_variable(label='Category')
    def category(self):
        """Expense category"""
        return self.expense.get('category', '')
    
    @string_rule_variable(label='Department')
    def department(self):
        """Department name"""
        return self.expense.get('department', '')
    
    @string_rule_variable(label='Description')
    def description(self):
        """Expense description"""
        return self.expense.get('description', '')
    
    @string_rule_variable(label='Vendor')
    def vendor(self):
        """Vendor name"""
        return self.expense.get('vendor', '')
    
    @boolean_rule_variable(label='Has Attachment')
    def has_attachment(self):
        """Whether expense has attachment"""
        return bool(self.expense.get('attachments'))


# ============================================
# EXPENSE ACTIONS (outcomes of rules)
# ============================================

class ExpenseActions(BaseActions):
    """Actions that can be performed on expenses"""
    
    def __init__(self, expense):
        self.expense = expense
        self.actions_taken = []
    
    @rule_action(params={'status': FIELD_SELECT})
    def set_status(self, status):
        """Set expense status"""
        self.expense['auto_status'] = status
        self.actions_taken.append(f"Set status to {status}")
        logger.info(f"Rule action: Set status to {status}")
    
    @rule_action(params={'category': FIELD_TEXT})
    def set_category(self, category):
        """Auto-categorize expense"""
        self.expense['auto_category'] = category
        self.actions_taken.append(f"Categorized as {category}")
        logger.info(f"Rule action: Set category to {category}")
    
    @rule_action(params={'flag': FIELD_TEXT})
    def flag_for_review(self, flag):
        """Flag expense for manual review"""
        self.expense['flagged'] = True
        self.expense['flag_reason'] = flag
        self.actions_taken.append(f"Flagged: {flag}")
        logger.info(f"Rule action: Flagged - {flag}")
    
    @rule_action()
    def auto_approve(self):
        """Auto-approve expense"""
        self.expense['auto_approved'] = True
        self.actions_taken.append("Auto-approved")
        logger.info("Rule action: Auto-approved")
    
    @rule_action()
    def require_manager_approval(self):
        """Require manager approval"""
        self.expense['requires_manager_approval'] = True
        self.actions_taken.append("Requires manager approval")
        logger.info("Rule action: Requires manager approval")
    
    @rule_action(params={'priority': FIELD_SELECT})
    def set_priority(self, priority):
        """Set processing priority"""
        self.expense['priority'] = priority
        self.actions_taken.append(f"Priority: {priority}")
        logger.info(f"Rule action: Set priority to {priority}")


# ============================================
# PREDEFINED RULES
# ============================================

class FinanceRules:
    """Predefined business rules for finance automation"""
    
    # Auto-approval rules
    AUTO_APPROVE_SMALL_EXPENSES = {
        'name': 'Auto-approve small expenses',
        'conditions': {
            'all': [
                {'name': 'amount', 'operator': 'less_than', 'value': 5000},
                {'name': 'has_attachment', 'operator': 'is_true', 'value': None},
            ]
        },
        'actions': [
            {'name': 'auto_approve', 'params': {}},
            {'name': 'set_priority', 'params': {'priority': 'low'}},
        ]
    }
    
    # Flag high-value expenses
    FLAG_HIGH_VALUE = {
        'name': 'Flag high-value expenses',
        'conditions': {
            'all': [
                {'name': 'amount', 'operator': 'greater_than', 'value': 50000},
            ]
        },
        'actions': [
            {'name': 'flag_for_review', 'params': {'flag': 'High value - requires approval'}},
            {'name': 'require_manager_approval', 'params': {}},
            {'name': 'set_priority', 'params': {'priority': 'high'}},
        ]
    }
    
    # Auto-categorize common expenses
    CATEGORIZE_RENT = {
        'name': 'Auto-categorize rent',
        'conditions': {
            'any': [
                {'name': 'description', 'operator': 'contains', 'value': 'rent'},
                {'name': 'description', 'operator': 'contains', 'value': 'lease'},
                {'name': 'vendor', 'operator': 'contains', 'value': 'property'},
            ]
        },
        'actions': [
            {'name': 'set_category', 'params': {'category': 'rent'}},
        ]
    }
    
    CATEGORIZE_SALARY = {
        'name': 'Auto-categorize salary',
        'conditions': {
            'any': [
                {'name': 'description', 'operator': 'contains', 'value': 'salary'},
                {'name': 'description', 'operator': 'contains', 'value': 'payroll'},
                {'name': 'category', 'operator': 'equal_to', 'value': 'sal'},
            ]
        },
        'actions': [
            {'name': 'set_category', 'params': {'category': 'salary'}},
            {'name': 'set_priority', 'params': {'priority': 'high'}},
        ]
    }
    
    CATEGORIZE_UTILITIES = {
        'name': 'Auto-categorize utilities',
        'conditions': {
            'any': [
                {'name': 'description', 'operator': 'contains', 'value': 'electricity'},
                {'name': 'description', 'operator': 'contains', 'value': 'internet'},
                {'name': 'description', 'operator': 'contains', 'value': 'water'},
                {'name': 'description', 'operator': 'contains', 'value': 'bill'},
            ]
        },
        'actions': [
            {'name': 'set_category', 'params': {'category': 'utilities'}},
        ]
    }
    
    # Department-specific rules
    TECH_DEPT_SOFTWARE = {
        'name': 'Tech department software expenses',
        'conditions': {
            'all': [
                {'name': 'department', 'operator': 'equal_to', 'value': 'Technology'},
                {'name': 'description', 'operator': 'contains', 'value': 'license'},
            ]
        },
        'actions': [
            {'name': 'set_category', 'params': {'category': 'software'}},
        ]
    }
    
    @classmethod
    def get_all_rules(cls):
        """Get all predefined rules"""
        return [
            cls.AUTO_APPROVE_SMALL_EXPENSES,
            cls.FLAG_HIGH_VALUE,
            cls.CATEGORIZE_RENT,
            cls.CATEGORIZE_SALARY,
            cls.CATEGORIZE_UTILITIES,
            cls.TECH_DEPT_SOFTWARE,
        ]


# ============================================
# RULE ENGINE
# ============================================

class ExpenseRuleEngine:
    """
    Main rule engine for processing expenses
    """
    
    def __init__(self, rules=None):
        """
        Initialize engine with rules
        
        Args:
            rules: List of rule dicts (default: use predefined)
        """
        self.rules = rules or FinanceRules.get_all_rules()
    
    def process_expense(self, expense_dict):
        """
        Process expense through all rules
        
        Args:
            expense_dict: Dict with expense data
            
        Returns:
            dict: Updated expense with auto-applied fields
        """
        # Create working copy
        expense = expense_dict.copy()
        
        # Track all actions
        all_actions = []
        
        # Apply each rule
        for rule in self.rules:
            try:
                # Create variables and actions
                variables = ExpenseVariables(expense)
                actions = ExpenseActions(expense)
                
                # Run rule engine
                result = run_all(
                    rule_list=[rule],
                    defined_variables=variables,
                    defined_actions=actions,
                    stop_on_first_trigger=False
                )
                
                # Collect actions
                if actions.actions_taken:
                    all_actions.extend(actions.actions_taken)
                    logger.info(f"Rule '{rule['name']}' triggered: {actions.actions_taken}")
                
            except Exception as e:
                logger.error(f"Error processing rule '{rule.get('name')}': {e}", exc_info=True)
                continue
        
        # Add summary
        expense['rules_applied'] = all_actions
        expense['rules_processed'] = True
        
        return expense
    
    def batch_process(self, expenses):
        """
        Process multiple expenses
        
        Args:
            expenses: List of expense dicts
            
        Returns:
            list: Processed expenses
        """
        return [self.process_expense(exp) for exp in expenses]


# ============================================
# CUSTOM RULE BUILDER
# ============================================

class RuleBuilder:
    """Helper to build custom rules"""
    
    @staticmethod
    def create_amount_threshold_rule(amount, action='flag'):
        """
        Create rule for amount threshold
        
        Args:
            amount: Threshold amount
            action: 'flag' or 'approve' or 'reject'
            
        Returns:
            dict: Rule definition
        """
        if action == 'flag':
            actions = [
                {'name': 'flag_for_review', 'params': {'flag': f'Exceeds threshold of {amount}'}},
            ]
        elif action == 'approve':
            actions = [
                {'name': 'auto_approve', 'params': {}},
            ]
        else:
            actions = []
        
        return {
            'name': f'Amount threshold {amount}',
            'conditions': {
                'all': [
                    {'name': 'amount', 'operator': 'greater_than', 'value': float(amount)},
                ]
            },
            'actions': actions,
        }
    
    @staticmethod
    def create_keyword_category_rule(keywords, category):
        """
        Create rule to categorize based on keywords
        
        Args:
            keywords: List of keywords
            category: Category to assign
            
        Returns:
            dict: Rule definition
        """
        conditions = [
            {'name': 'description', 'operator': 'contains', 'value': kw}
            for kw in keywords
        ]
        
        return {
            'name': f'Categorize as {category}',
            'conditions': {'any': conditions},
            'actions': [
                {'name': 'set_category', 'params': {'category': category}},
            ]
        }


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    # Example expense
    expense = {
        'amount': Decimal('3000'),
        'category': 'misc',
        'department': 'Operations',
        'description': 'Office rent payment for December',
        'vendor': 'Property Management Co',
        'attachments': True,
    }
    
    # Process with rules
    engine = ExpenseRuleEngine()
    processed = engine.process_expense(expense)
    
    print("Original:", expense)
    print("\nProcessed:", processed)
    print("\nActions taken:", processed.get('rules_applied'))
    
    # Example: Custom rule
    custom_rule = RuleBuilder.create_amount_threshold_rule(10000, action='flag')
    custom_engine = ExpenseRuleEngine(rules=[custom_rule])
    
    high_value_expense = {'amount': 15000, 'description': 'Large purchase'}
    result = custom_engine.process_expense(high_value_expense)
    print("\nCustom rule result:", result.get('rules_applied'))
