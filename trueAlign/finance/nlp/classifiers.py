"""
Rule-Based Classifiers
"""
from .constants import *
from .cleaners import normalize_text

class TransactionClassifier:
    
    @staticmethod
    def classify_type(description):
        """
        Determine transaction type based on description keywords.
        """
        text = normalize_text(description)
        
        # Check Salary
        if any(kw in text for kw in KEYWORDS_SALARY):
            return TYPE_SALARY
            
        # Check Tax
        if any(kw in text for kw in KEYWORDS_TAX):
            return TYPE_TAX
            
        # Check Bank Charges
        if any(kw in text for kw in KEYWORDS_BANK_CHARGE):
            return TYPE_BANK_CHARGE
            
        # Check ATM
        if any(kw in text for kw in KEYWORDS_ATM):
            return TYPE_ATM
            
        # Check UPI
        if any(kw in text for kw in KEYWORDS_UPI):
            return TYPE_UPI
            
        return TYPE_UNKNOWN

    @staticmethod
    def detect_mode(description):
        """
        Detect payment mode (UPI, NEFT, etc.)
        """
        text = normalize_text(description)
        
        if 'upi' in text or 'gpay' in text or 'phonepe' in text:
            return MODE_UPI
        if 'neft' in text:
            return MODE_NEFT
        if 'rtgs' in text:
            return MODE_RTGS
        if 'imps' in text:
            return MODE_IMPS
        if 'atm' in text or 'cash' in text:
            return MODE_CASH # Broadly cash/atm
        if 'pos' in text or 'card' in text:
            return MODE_POS
            
        return None

    @staticmethod
    def predict_category(description):
        """
        Predict expense category based on keywords.
        """
        text = normalize_text(description)
        
        for category, keywords in CATEGORY_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return category
                
        return None
