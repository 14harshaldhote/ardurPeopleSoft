"""
Finance Module - Currency Converter
Real-time FX conversion using forex-python with caching
Compatible with Django's cache backends (database/file cache for cPanel)
"""

from decimal import Decimal
from django.core.cache import cache
from datetime import datetime, timedelta
import logging

logger = logging.getLogger('finance')

# Import forex-python (install: pip install forex-python)
try:
    from forex_python.converter import CurrencyRates, RatesNotAvailableError
    from forex_python.bitcoin import BtcConverter
    FOREX_AVAILABLE = True
except ImportError:
    FOREX_AVAILABLE = False
    print("WARNING: forex-python not installed. Install with: pip install forex-python")

# Import django-money if available
try:
    from djmoney.money import Money
    MONEY_AVAILABLE = True
except ImportError:
    MONEY_AVAILABLE = False


class FXConverter:
    """
    Currency converter with caching for performance
    Uses forex-python for real-time rates
    
    Cache Backend Support:
    - Database cache (for cPanel): python manage.py createcachetable finance_cache
    - File cache (for cPanel): Built-in, no setup needed
    - Redis cache (for VPS/Cloud): Requires redis-server
    - Dummy cache (dev): No caching
    """
    
    # Cache TTL (1 hour - rates don't change that frequently)
    CACHE_TTL = 3600
    
    def __init__(self):
        if not FOREX_AVAILABLE:
            raise ImportError("forex-python not installed. Run: pip install forex-python")
        
        self.c = CurrencyRates()
    
    def get_rate(self, from_currency, to_currency='INR'):
        """
        Get exchange rate from one currency to another
        
        Args:
            from_currency: Source currency code (e.g., 'USD')
            to_currency: Target currency code (default: 'INR')
            
        Returns:
            Decimal: Exchange rate
            
        Example:
            >>> converter = FXConverter()
            >>> rate = converter.get_rate('USD', 'INR')
            >>> print(rate)  # 83.25
            
        Note:
            Uses Django's cache backend (database/file/Redis)
            Works on cPanel with database or file cache
        """
        if from_currency == to_currency:
            return Decimal('1.0')
        
        # Check cache first (works with any Django cache backend)
        cache_key = f'fx_rate_{from_currency}_{to_currency}'
        cached_rate = cache.get(cache_key)
        
        if cached_rate:
            logger.debug(f"FX rate cache hit: {from_currency}/{to_currency} = {cached_rate}")
            return Decimal(str(cached_rate))
        
        # Fetch from API
        try:
            rate = self.c.get_rate(from_currency, to_currency)
            rate_decimal = Decimal(str(rate))
            
            # Cache the rate
            cache.set(cache_key, float(rate_decimal), self.CACHE_TTL)
            
            logger.info(
                f"Fetched FX rate: {from_currency}/{to_currency} = {rate_decimal}",
                extra={'from_currency': from_currency, 'to_currency': to_currency, 'rate': float(rate_decimal)}
            )
            
            return rate_decimal
            
        except RatesNotAvailableError as e:
            logger.error(f"FX rates not available: {e}")
            raise ValueError(f"Unable to fetch exchange rate for {from_currency}/{to_currency}")
    
    def convert_amount(self, amount, from_currency, to_currency='INR'):
        """
        Convert amount from one currency to another
        
        Args:
            amount: Amount to convert (Decimal or float)
            from_currency: Source currency
            to_currency: Target currency (default: INR)
            
        Returns:
            Decimal: Converted amount
            
        Example:
            >>> converter = FXConverter()
            >>> inr_amount = converter.convert_amount(100, 'USD', 'INR')
            >>> print(inr_amount)  # 8325.00
        """
        if from_currency == to_currency:
            return Decimal(str(amount))
        
        rate = self.get_rate(from_currency, to_currency)
        amount_decimal = Decimal(str(amount))
        converted = amount_decimal * rate
        
        # Round to 2 decimal places for currency
        return converted.quantize(Decimal('0.01'))
    
    def convert_money(self, money_obj, to_currency='INR'):
        """
        Convert Money object to target currency (requires django-money)
        
        Args:
            money_obj: Money instance
            to_currency: Target currency code
            
        Returns:
            Money: Converted Money object
            
        Example:
            >>> from djmoney.money import Money
            >>> converter = FXConverter()
            >>> usd_amount = Money(100, 'USD')
            >>> inr_amount = converter.convert_money(usd_amount, 'INR')
            >>> print(inr_amount)  # ₹8,325.00 INR
        """
        if not MONEY_AVAILABLE:
            raise ImportError("django-money not installed. Run: pip install django-money")
        
        if not isinstance(money_obj, Money):
            raise TypeError("Expected Money object")
        
        if money_obj.currency.code == to_currency:
            return money_obj
        
        converted_amount = self.convert_amount(
            money_obj.amount,
            money_obj.currency.code,
            to_currency
        )
        
        return Money(converted_amount, to_currency)
    
    def get_all_rates(self, base_currency='INR'):
        """
        Get rates for all major currencies
        
        Args:
            base_currency: Base currency (default: INR)
            
        Returns:
            dict: Currency code -> rate
            
        Example:
            >>> converter = FXConverter()
            >>> rates = converter.get_all_rates('INR')
            >>> print(rates)  # {'USD': 0.012, 'EUR': 0.011, ...}
        """
        cache_key = f'fx_rates_all_{base_currency}'
        cached = cache.get(cache_key)
        
        if cached:
            return cached
        
        try:
            rates = self.c.get_rates(base_currency)
            
            # Convert to Decimal
            rates_decimal = {k: float(Decimal(str(v))) for k, v in rates.items()}
            
            # Cache for 1 hour
            cache.set(cache_key, rates_decimal, self.CACHE_TTL)
            
            return rates_decimal
            
        except RatesNotAvailableError as e:
            logger.error(f"Unable to fetch rates: {e}")
            return {}
    
    @staticmethod
    def get_supported_currencies():
        """
        Get list of supported currency codes
        
        Returns:
            list: Currency codes
        """
        # Major currencies
        return [
            'INR',  # Indian Rupee
            'USD',  # US Dollar
            'EUR',  # Euro
            'GBP',  # British Pound
            'JPY',  # Japanese Yen
            'CNY',  # Chinese Yuan
            'AUD',  # Australian Dollar
            'CAD',  # Canadian Dollar
            'CHF',  # Swiss Franc
            'SGD',  # Singapore Dollar
            'AED',  # UAE Dirham
            'SAR',  # Saudi Riyal
        ]


class CurrencyCache:
    """Manage currency rate cache"""
    
    @staticmethod
    def clear_cache(from_currency=None, to_currency=None):
        """
        Clear FX rate cache
        
        Args:
            from_currency: Specific from currency (optional)
            to_currency: Specific to currency (optional)
        """
        if from_currency and to_currency:
            cache_key = f'fx_rate_{from_currency}_{to_currency}'
            cache.delete(cache_key)
            logger.info(f"Cleared FX cache for {from_currency}/{to_currency}")
        else:
            # Clear all FX caches (pattern matching)
            # Note: This requires Redis backend for pattern-based deletion
            logger.info("Clearing all FX rate caches")
            cache.delete_pattern('fx_rate_*')
            cache.delete_pattern('fx_rates_all_*')
    
    @staticmethod
    def  warmup_cache(base_currency='INR', target_currencies=None):
        """
        Pre-populate cache with common currency pairs
        
        Args:
            base_currency: Base currency
            target_currencies: List of target currencies (optional)
        """
        if target_currencies is None:
            target_currencies = ['USD', 'EUR', 'GBP', 'AED']
        
        converter = FXConverter()
        
        for target in target_currencies:
            try:
                converter.get_rate(base_currency, target)
                logger.info(f"Warmed up cache for {base_currency}/{target}")
            except Exception as e:
                logger.warning(f"Failed to warm up {base_currency}/{target}: {e}")


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    converter = FXConverter()
    
    # Example 1: Get exchange rate
    rate = converter.get_rate('USD', 'INR')
    print(f"1 USD = {rate} INR")
    
    # Example 2: Convert amount
    inr_amount = converter.convert_amount(100, 'USD', 'INR')
    print(f"100 USD = {inr_amount} INR")
    
    # Example 3: Get all rates
    rates = converter.get_all_rates('INR')
    print(f"All rates from INR: {rates}")
    
    # Example 4: Convert Money object (if django-money installed)
    if MONEY_AVAILABLE:
        usd_money = Money(1000, 'USD')
        inr_money = converter.convert_money(usd_money, 'INR')
        print(f"{usd_money} = {inr_money}")
