"""
Finance Module - Validation Utilities
Comprehensive validators for financial data including PAN, GSTIN, IBAN, amounts, dates
Uses python-stdnum for compliance-grade validation
"""

from decimal import Decimal
from datetime import date, datetime
from django.core.exceptions import ValidationError
from django.utils import timezone

# Import stdnum validators (install: pip install python-stdnum)
try:
    from stdnum.in_ import pan, aadhaar, gstin
    from stdnum import iban
    from stdnum.iso9362 import is_valid as is_valid_swift_bic
    STDNUM_AVAILABLE = True
except ImportError:
    STDNUM_AVAILABLE = False
    print("WARNING: python-stdnum not installed. Install with: pip install python-stdnum")


# ============================================
# INDIAN COMPLIANCE VALIDATORS
# ============================================

def validate_pan(value):
    """
    Validate Indian PAN (Permanent Account Number)
    
    Format: ABCDE1234F
    - First 5 chars: Alphabets
    - Next 4 chars: Numbers
    - Last char: Alphabet
    
    Args:
        value: PAN string
        
    Returns:
        Standardized PAN (uppercase, no spaces)
        
    Raises:
        ValidationError if invalid
    """
    if not STDNUM_AVAILABLE:
        raise ValidationError("python-stdnum library not installed")
    
    if not value:
        raise ValidationError("PAN number is required")
    
    # Clean and standardize
    cleaned = value.strip().upper()
    
    if not pan.is_valid(cleaned):
        raise ValidationError(
            f"'{value}' is not a valid PAN number. "
            "Format should be: ABCDE1234F (5 letters, 4 digits, 1 letter)"
        )
    
    return pan.compact(cleaned)


def validate_gstin(value):
    """
    Validate Indian GSTIN (Goods and Services Tax Identification Number)
    
    Format: 15 characters
    - First 2: State code
    - Next 10: PAN
    - 13th: Entity number
    - 14th: Z (default)
    - 15th: Check digit
    
    Args:
        value: GSTIN string
        
    Returns:
        Standardized GSTIN (uppercase, no spaces)
        
    Raises:
        ValidationError if invalid
    """
    if not STDNUM_AVAILABLE:
        raise ValidationError("python-stdnum library not installed")
    
    if not value:
        return value  # GSTIN is optional for many entities
    
    cleaned = value.strip().upper()
    
    if not gstin.is_valid(cleaned):
        raise ValidationError(
            f"'{value}' is not a valid GSTIN. "
            "GSTIN must be 15 characters (2-digit state code + 10-char PAN + 3 additional chars)"
        )
    
    return gstin.compact(cleaned)


def validate_aadhaar(value):
    """
    Validate Indian Aadhaar number
    
    Format: 12 digits
    
    Args:
        value: Aadhaar string
        
    Returns:
        Standardized Aadhaar
        
    Raises:
        ValidationError if invalid
    """
    if not STDNUM_AVAILABLE:
        raise ValidationError("python-stdnum library not installed")
    
    if not value:
        return value  # Optional
    
    cleaned = value.strip().replace(' ', '').replace('-', '')
    
    if not aadhaar.is_valid(cleaned):
        raise ValidationError(
            f"'{value}' is not a valid Aadhaar number. "
            "Aadhaar must be 12 digits"
        )
    
    return aadhaar.compact(cleaned)


# ============================================
# INTERNATIONAL VALIDATORS
# ============================================

def validate_iban_number(value):
    """
    Validate IBAN (International Bank Account Number)
    
    Supports all countries with IBAN system
    
    Args:
        value: IBAN string
        
    Returns:
        Standardized IBAN (uppercase, no spaces)
        
    Raises:
        ValidationError if invalid
    """
    if not STDNUM_AVAILABLE:
        raise ValidationError("python-stdnum library not installed")
    
    if not value:
        return value  # Optional
    
    cleaned = value.strip().upper().replace(' ', '')
    
    if not iban.is_valid(cleaned):
        raise ValidationError(
            f"'{value}' is not a valid IBAN. "
            "IBAN format varies by country (e.g., GB29NWBK60161331926819)"
        )
    
    return iban.compact(cleaned)


def validate_swift_bic(value):
    """
    Validate SWIFT/BIC code
    
    Format: 8 or 11 characters
    - First 4: Bank code
    - Next 2: Country code
    - Next 2: Location code
    - Last 3: Branch code (optional)
    
    Args:
        value: BIC string
        
    Returns:
        Standardized BIC (uppercase)
        
    Raises:
        ValidationError if invalid
    """
    if not STDNUM_AVAILABLE:
        raise ValidationError("python-stdnum library not installed")
    
    if not value:
        return value  # Optional
    
    cleaned = value.strip().upper()
    
    if not is_valid_swift_bic(cleaned):
        raise ValidationError(
            f"'{value}' is not a valid SWIFT/BIC code. "
            "BIC must be 8 or 11 characters (e.g., DEUTDEFF or DEUTDEFF500)"
        )
    
    return cleaned


# ============================================
# FINANCIAL AMOUNT VALIDATORS
# ============================================

def validate_positive_amount(value):
    """
    Validate that amount is positive
    
    Args:
        value: Decimal or float
        
    Returns:
        Decimal value
        
    Raises:
        ValidationError if <= 0
    """
    if value is None:
        raise ValidationError("Amount is required")
    
    amount = Decimal(str(value))
    
    if amount <= Decimal('0'):
        raise ValidationError("Amount must be greater than zero")
    
    return amount


def validate_non_negative_amount(value):
    """
    Validate that amount is non-negative (>= 0)
    
    Args:
        value: Decimal or float
        
    Returns:
        Decimal value
        
    Raises:
        ValidationError if < 0
    """
    if value is None:
        raise ValidationError("Amount is required")
    
    amount = Decimal(str(value))
    
    if amount < Decimal('0'):
        raise ValidationError("Amount cannot be negative")
    
    return amount


def validate_decimal_precision(value, max_decimals=2):
    """
    Validate decimal precision (max 2 decimal places for currency)
    
    Args:
        value: Decimal or float
        max_decimals: Maximum allowed decimal places (default: 2)
        
    Returns:
        Decimal value
        
    Raises:
        ValidationError if too many decimal places
    """
    amount = Decimal(str(value))
    
    # Get decimal places
    exponent = amount.as_tuple().exponent
    decimal_places = abs(exponent) if exponent < 0 else 0
    
    if decimal_places > max_decimals:
        raise ValidationError(
            f"Amount cannot have more than {max_decimals} decimal places. "
            f"Got {decimal_places} decimal places."
        )
    
    return amount


def validate_amount_range(value, min_amount=None, max_amount=None):
    """
    Validate amount is within specified range
    
    Args:
        value: Decimal or float
        min_amount: Minimum allowed amount (optional)
        max_amount: Maximum allowed amount (optional)
        
    Returns:
        Decimal value
        
    Raises:
        ValidationError if out of range
    """
    amount = Decimal(str(value))
    
    if min_amount is not None and amount < Decimal(str(min_amount)):
        raise ValidationError(f"Amount must be at least {min_amount}")
    
    if max_amount is not None and amount > Decimal(str(max_amount)):
        raise ValidationError(f"Amount cannot exceed {max_amount}")
    
    return amount


# ============================================
# DATE VALIDATORS
# ============================================

def validate_not_future_date(value):
    """
    Validate that date is not in the future
    
    Args:
        value: date or datetime
        
    Returns:
        date object
        
    Raises:
        ValidationError if future date
    """
    if value is None:
        raise ValidationError("Date is required")
    
    if isinstance(value, datetime):
        value = value.date()
    
    today = timezone.now().date()
    
    if value > today:
        raise ValidationError(
            f"Date cannot be in the future. Maximum allowed date is {today}"
        )
    
    return value


def validate_date_range(value, min_date=None, max_date=None):
    """
    Validate date is within specified range
    
    Args:
        value: date or datetime
        min_date: Minimum allowed date (optional)
        max_date: Maximum allowed date (optional)
        
    Returns:
        date object
        
    Raises:
        ValidationError if out of range
    """
    if isinstance(value, datetime):
        value = value.date()
    
    if min_date and value < min_date:
        raise ValidationError(f"Date must be on or after {min_date}")
    
    if max_date and value > max_date:
        raise ValidationError(f"Date must be on or before {max_date}")
    
    return value


def validate_financial_year_date(value, financial_year_start_month=4):
    """
    Validate date is within current/recent financial year
    
    Args:
        value: date or datetime
        financial_year_start_month: Month when FY starts (default: 4 for April in India)
        
    Returns:
        date object
        
    Raises:
        ValidationError if too old (more than 2 FY ago)
    """
    if isinstance(value, datetime):
        value = value.date()
    
    today = timezone.now().date()
    
    # Calculate start of current FY
    if today.month >= financial_year_start_month:
        fy_start = date(today.year, financial_year_start_month, 1)
    else:
        fy_start = date(today.year - 1, financial_year_start_month, 1)
    
    # Allow up to 2 FY back
    min_allowed = date(fy_start.year - 2, financial_year_start_month, 1)
    
    if value < min_allowed:
        raise ValidationError(
            f"Date is too old. Transactions older than {min_allowed} "
            f"(more than 2 financial years) are not allowed"
        )
    
    return value


# ============================================
# BUSINESS RULE VALIDATORS
# ============================================

def validate_expense_limit(amount, category, department=None):
    """
    Validate expense against category/department limits
    
    Define limits in settings or database
    
    Args:
        amount: Decimal amount
        category: Expense category
        department: Department (optional)
        
    Returns:
        True if valid
        
    Raises:
        ValidationError if exceeds limit
    """
    # Define limits (these should come from database/settings in production)
    CATEGORY_LIMITS = {
        'travel': Decimal('50000'),
        'food': Decimal('5000'),
        'office_supplies': Decimal('10000'),
        'software': Decimal('100000'),
        'consulting': Decimal('500000'),
    }
    
    limit = CATEGORY_LIMITS.get(category.lower())
    
    if limit and amount > limit:
        raise ValidationError(
            f"Amount {amount} exceeds limit for category '{category}' (limit: {limit}). "
            f"Requires special approval."
        )
    
    return True


# ============================================
# COMBINED VALIDATORS
# ============================================

def validate_complete_amount(value, allow_zero=False, max_decimals=2, 
                            min_amount=None, max_amount=None):
    """
    Complete amount validation (combines multiple checks)
    
    Args:
        value: Amount to validate
        allow_zero: Whether to allow zero (default: False)
        max_decimals: Maximum decimal places (default: 2)
        min_amount: Minimum allowed (optional)
        max_amount: Maximum allowed (optional)
        
    Returns:
        Validated Decimal
        
    Raises:
        ValidationError if any check fails
    """
    # Convert to Decimal
    amount = Decimal(str(value))
    
    # Check positivity
    if allow_zero:
        validate_non_negative_amount(amount)
    else:
        validate_positive_amount(amount)
    
    # Check precision
    validate_decimal_precision(amount, max_decimals)
    
    # Check range
    if min_amount or max_amount:
        validate_amount_range(amount, min_amount, max_amount)
    
    return amount


# ============================================
# USAGE EXAMPLES (for documentation)
# ============================================

if __name__ == '__main__':
    # Example usage
    
    # PAN validation
    try:
        pan_num = validate_pan("ABCDE1234F")
        print(f"Valid PAN: {pan_num}")
    except ValidationError as e:
        print(f"Invalid PAN: {e}")
    
    # GSTIN validation
    try:
        gstin_num = validate_gstin("29ABCDE1234F1Z5")
        print(f"Valid GSTIN: {gstin_num}")
    except ValidationError as e:
        print(f"Invalid GSTIN: {e}")
    
    # Amount validation
    try:
        amount = validate_complete_amount("1000.50", max_amount=50000)
        print(f"Valid amount: {amount}")
    except ValidationError as e:
        print(f"Invalid amount: {e}")
