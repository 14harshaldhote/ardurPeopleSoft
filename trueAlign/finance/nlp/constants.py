"""
NLP Constants and Dictionaries
"""

# Transaction Types
TYPE_SALARY = 'SALARY'
TYPE_VENDOR = 'VENDOR'
TYPE_TAX = 'TAX'
TYPE_BANK_CHARGE = 'BANK_CHARGE'
TYPE_ATM = 'ATM'
TYPE_UPI = 'UPI'
TYPE_TRANSFER = 'TRANSFER'
TYPE_UNKNOWN = 'UNKNOWN'

# Modes
MODE_UPI = 'UPI'
MODE_NEFT = 'NEFT'
MODE_RTGS = 'RTGS'
MODE_IMPS = 'IMPS'
MODE_ATM = 'ATM'
MODE_POS = 'POS'
MODE_CARD = 'CARD'
MODE_CASH = 'CASH'
MODE_CHEQUE = 'CHEQUE'

# Keywords for Classification
KEYWORDS_SALARY = ['salary', 'sal', 'payroll', 'stipend', 'bonus', 'incentive']
KEYWORDS_TAX = ['tds', 'gst', 'igst', 'cgst', 'sgst', 'pf', 'esic', 'pt', 'income tax']
KEYWORDS_BANK_CHARGE = ['charge', 'fee', 'penalty', 'interest', 'min bal']
KEYWORDS_ATM = ['atm', 'wdl', 'withdrawal', 'cash wdl']
KEYWORDS_UPI = ['upi', 'gpay', 'paytm', 'phonepe', 'bharatpe', 'razorpay']

# Expense Categories Mapping
CATEGORY_KEYWORDS = {
    'FOOD': ['swiggy', 'zomato', 'lunch', 'dinner', 'snacks', 'tea', 'coffee', 'cafe', 'restaurant'],
    'TRAVEL': ['ola', 'uber', 'auto', 'cab', 'taxi', 'bus', 'train', 'flight', 'air', 'fuel', 'petrol', 'diesel'],
    'SOFTWARE': ['zoom', 'aws', 'google', 'microsoft', 'adobe', 'github', 'digitalocean', 'godaddy', 'domain', 'hosting'],
    'OFFICE': ['stationary', 'xerox', 'print', 'courier', 'cleaning', 'maintenance', 'repair', 'internet', 'wifi', 'broadband'],
    'UTILITY': ['electricity', 'water', 'bill', 'mobile', 'recharge'],
}

# Risk Keywords
RISK_VAGUE = ['misc', 'general', 'adjustment', 'cash', 'other', 'staff welfare', 'sundry']
RISK_SUSPICIOUS = ['lost', 'urgent', 'forgot', 'personal', 'loan', 'advance']
