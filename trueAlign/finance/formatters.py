"""
Finance Module - Currency Formatters
Format monetary amounts for different locales using Babel
"""

from decimal import Decimal
from babel.numbers import format_currency, format_decimal, get_currency_symbol
from babel.dates import format_date, format_datetime
from django.utils import timezone
import logging

logger = logging.getLogger('finance')

# Import django-money if available
try:
    from djmoney.money import Money
    MONEY_AVAILABLE = True
except ImportError:
    MONEY_AVAILABLE = False


class MoneyFormatter:
    """
    Format monetary amounts with locale support using Babel
    """
    
    # Common locales
    LOCALES = {
        'india': 'en_IN',
        'us': 'en_US',
        'uk': 'en_GB',
        'europe': 'de_DE',
        'france': 'fr_FR',
        'japan': 'ja_JP',
        'china': 'zh_CN',
    }
    
    @staticmethod
    def format_money(amount, currency='INR', locale='en_IN'):
        """
        Format money amount with currency symbol and locale-specific formatting
        
        Args:
            amount: Decimal or Money object
            currency: Currency code (default: INR)
            locale: Locale code (default: en_IN for India)
            
        Returns:
            str: Formatted money string
            
        Examples:
            >>> MoneyFormatter.format_money(50000, 'INR', 'en_IN')
            '₹50,000.00'
            
            >>> MoneyFormatter.format_money(1200.50, 'USD', 'en_US')
            '$1,200.50'
            
            >>> MoneyFormatter.format_money(999.99, 'EUR', 'de_DE')
            '999,99 €'
        """
        # Handle Money objects
        if MONEY_AVAILABLE and isinstance(amount, Money):
            amount_value = amount.amount
            currency = amount.currency.code
        else:
            amount_value = Decimal(str(amount))
        
        try:
            formatted = format_currency(
                amount_value,
                currency,
                locale=locale
            )
            return formatted
        except Exception as e:
            logger.error(f"Error formatting money: {e}")
            # Fallback to simple format
            return f"{currency} {amount_value:,.2f}"
    
    @staticmethod
    def format_money_indian_style(amount, currency='INR'):
        """
        Format money in Indian numbering system (lakhs, crores)
        
        Args:
            amount: Decimal or Money object
            currency: Currency code (default: INR)
            
        Returns:
            str: Formatted string
            
        Examples:
            >>> MoneyFormatter.format_money_indian_style(150000)
            '₹1,50,000.00'
            
            >>> MoneyFormatter.format_money_indian_style(10000000)
            '₹1,00,00,000.00'
        """
        if MONEY_AVAILABLE and isinstance(amount, Money):
            amount_value = float(amount.amount)
            currency = amount.currency.code
        else:
            amount_value = float(amount)
        
        # Get currency symbol
        symbol = get_currency_symbol(currency, locale='en_IN')
        
        # Indian number formatting
        amount_str = f"{amount_value:.2f}"
        integer_part, decimal_part = amount_str.split('.')
        
        # Reverse for easier processing
        reversed_int = integer_part[::-1]
        
        # First group of 3, then groups of 2
        groups = []
        groups.append(reversed_int[:3])
        remaining = reversed_int[3:]
        
        while remaining:
            groups.append(remaining[:2])
            remaining = remaining[2:]
        
        # Join and reverse back
        formatted_int = ','.join(groups)[::-1]
        
        return f"{symbol}{formatted_int}.{decimal_part}"
    
    @staticmethod
    def format_money_compact(amount, currency='INR', locale='en_IN'):
        """
        Format money in compact form (K, M, B)
        
        Args:
            amount: Decimal or Money object
            currency: Currency code
            locale: Locale code
            
        Returns:
            str: Compact formatted string
            
        Examples:
            >>> MoneyFormatter.format_money_compact(1500)
            '₹1.5K'
            
            >>> MoneyFormatter.format_money_compact(1500000)
            '₹1.5M'
            
            >>> MoneyFormatter.format_money_compact(1500000000)
            '₹1.5B'
        """
        if MONEY_AVAILABLE and isinstance(amount, Money):
            amount_value = float(amount.amount)
            currency = amount.currency.code
        else:
            amount_value = float(amount)
        
        symbol = get_currency_symbol(currency, locale=locale)
        
        # Determine scale
        if amount_value >= 1_000_000_000:  # Billions
            scaled = amount_value / 1_000_000_000
            suffix = 'B'
        elif amount_value >= 1_000_000:  # Millions
            scaled = amount_value / 1_000_000
            suffix = 'M'
        elif amount_value >= 1_000:  # Thousands
            scaled = amount_value / 1_000
            suffix = 'K'
        else:
            scaled = amount_value
            suffix = ''
        
        if suffix:
            return f"{symbol}{scaled:.1f}{suffix}"
        else:
            return f"{symbol}{scaled:,.2f}"
    
    @staticmethod
    def format_money_words(amount, currency='INR', locale='en_IN'):
        """
        Format money in words (Indian style for INR)
        
        Args:
            amount: Decimal or Money object
            currency: Currency code
            locale: Locale code
            
        Returns:
            str: Amount in words
            
        Examples:
            >>> MoneyFormatter.format_money_words(5000)
            'Five Thousand Rupees'
            
            >>> MoneyFormatter.format_money_words(150000)
            'One Lakh Fifty Thousand Rupees'
        """
        if MONEY_AVAILABLE and isinstance(amount, Money):
            amount_value = int(amount.amount)
            currency = amount.currency.code
        else:
            amount_value = int(amount)
        
        if currency == 'INR':
            return MoneyFormatter._amount_to_words_indian(amount_value)
        else:
            return MoneyFormatter._amount_to_words_international(amount_value, currency)
    
    @staticmethod
    def _amount_to_words_indian(amount):
        """Convert amount to words (Indian system: lakhs, crores)"""
        # This is a simplified version - for production, use a library like num2words
        
        if amount == 0:
            return "Zero Rupees"
        
        # Basic number names
        ones = ['', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine']
        tens = ['', '', 'Twenty', 'Thirty', 'Forty', 'Fifty', 'Sixty', 'Seventy', 'Eighty', 'Ninety']
        teens = ['Ten', 'Eleven', 'Twelve', 'Thirteen', 'Fourteen', 'Fifteen', 
                 'Sixteen', 'Seventeen', 'Eighteen', 'Nineteen']
        
        def convert_below_thousand(n):
            if n == 0:
                return ''
            elif n < 10:
                return ones[n]
            elif n < 20:
                return teens[n - 10]
            elif n < 100:
                return tens[n // 10] + (' ' + ones[n % 10] if n % 10 != 0 else '')
            else:
                return ones[n // 100] + ' Hundred' + (' ' + convert_below_thousand(n % 100) if n % 100 != 0 else '')
        
        # Split into crores, lakhs, thousands, hundreds
        crores = amount // 10000000
        lakhs = (amount % 10000000) // 100000
        thousands = (amount % 100000) // 1000
        remainder = amount % 1000
        
        result = []
        
        if crores > 0:
            result.append(convert_below_thousand(crores) + ' Crore')
        if lakhs > 0:
            result.append(convert_below_thousand(lakhs) + ' Lakh')
        if thousands > 0:
            result.append(convert_below_thousand(thousands) + ' Thousand')
        if remainder > 0:
            result.append(convert_below_thousand(remainder))
        
        return ' '.join(result) + ' Rupees'
    
    @staticmethod
    def _amount_to_words_international(amount, currency):
        """Convert amount to words (international system)"""
        # Simplified - use num2words library for production
        return f"{currency} {amount:,}"
    
    @staticmethod
    def format_date_indian(date_obj):
        """
        Format date in Indian style
        
        Args:
            date_obj: date or datetime object
            
        Returns:
            str: Formatted date
            
        Example:
            >>> MoneyFormatter.format_date_indian(date(2024, 12, 2))
            '02-Dec-2024'
        """
        try:
            formatted = format_date(date_obj, format='dd-MMM-yyyy', locale='en_IN')
            return formatted
        except Exception as e:
            logger.error(f"Error formatting date: {e}")
            return str(date_obj)


class InvoiceFormatter:
    """Specialized formatter for invoices"""
    
    @staticmethod
    def format_invoice_amount(amount, currency='INR'):
        """
        Format invoice amount with words
        
        Args:
            amount: Decimal or Money object
            currency: Currency code
            
        Returns:
            dict: {formatted, words, currency_symbol}
        """
        formatted = MoneyFormatter.format_money(amount, currency, 'en_IN')
        words = MoneyFormatter.format_money_words(amount, currency)
        symbol = get_currency_symbol(currency, 'en_IN')
        
        return {
            'formatted': formatted,
            'words': words,
            'symbol': symbol,
            'amount': float(amount) if not isinstance(amount, Money) else float(amount.amount)
        }
    
    @staticmethod
    def format_invoice_number(invoice_id, prefix='INV', financial_year=None):
        """
        Format invoice number
        
        Args:
            invoice_id: Numeric ID
            prefix: Prefix (default: INV)
            financial_year: FY string (e.g., '2024-25')
            
        Returns:
            str: Formatted invoice number
            
        Example:
            >>> InvoiceFormatter.format_invoice_number(123, 'INV', '2024-25')
            'INV/2024-25/0123'
        """
        if financial_year:
            return f"{prefix}/{financial_year}/{invoice_id:04d}"
        else:
            return f"{prefix}/{invoice_id:04d}"


# ============================================
# DJANGO TEMPLATE FILTERS (optional)
# ============================================

from django import template

register = template.Library()

@register.filter(name='format_money_indian')
def format_money_indian_filter(amount, currency='INR'):
    """Template filter for Indian money formatting"""
    return MoneyFormatter.format_money_indian_style(amount, currency)

@register.filter(name='format_money_compact')
def format_money_compact_filter(amount, currency='INR'):
    """Template filter for compact money formatting"""
    return MoneyFormatter.format_money_compact(amount, currency)

@register.filter(name='format_money_words')
def format_money_words_filter(amount, currency='INR'):
    """Template filter for money in words"""
    return MoneyFormatter.format_money_words(amount, currency)


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    from datetime import date
    
    # Example 1: Basic formatting
    amount = Decimal('50000.50')
    print(MoneyFormatter.format_money(amount, 'INR', 'en_IN'))
    # Output: ₹50,000.50
    
    # Example 2: Indian style
    print(MoneyFormatter.format_money_indian_style(150000))
    # Output: ₹1,50,000.00
    
    # Example 3: Compact format
    print(MoneyFormatter.format_money_compact(1500000))
    # Output: ₹1.5M
    
    # Example 4: Amount in words
    print(MoneyFormatter.format_money_words(150000))
    # Output: One Lakh Fifty Thousand Rupees
    
    # Example 5: Invoice formatting
    invoice_data = InvoiceFormatter.format_invoice_amount(50000, 'INR')
    print(invoice_data)
    # Output: {'formatted': '₹50,000.00', 'words': 'Fifty Thousand Rupees', ...}
    
    # Example 6: Date formatting
    today = date.today()
    print(MoneyFormatter.format_date_indian(today))
    # Output: 02-Dec-2024
