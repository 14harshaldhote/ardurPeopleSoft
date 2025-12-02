"""
Regex Patterns for NLP Extraction
"""
import re

# UTR / Reference Numbers
PATTERN_UTR = re.compile(r'[A-Z]{4}\d{7,}')  # Generic UTR-like pattern
PATTERN_UPI_REF = re.compile(r'UPI/\d+/')
PATTERN_CHEQUE = re.compile(r'\b\d{6}\b')  # 6 digit cheque number

# Invoice Numbers (Generic)
PATTERN_INVOICE = re.compile(r'\b(INV|BILL|REF)[-\s]?\d+\b', re.IGNORECASE)

# Amounts (for extraction from text if needed)
PATTERN_AMOUNT = re.compile(r'[\d,]+\.\d{2}')

# Tax Percentages
PATTERN_TAX_PERCENT = re.compile(r'(\d+)%')

# Dates (Simple formats)
PATTERN_DATE_ISO = re.compile(r'\d{4}-\d{2}-\d{2}')
PATTERN_DATE_DMY = re.compile(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}')
