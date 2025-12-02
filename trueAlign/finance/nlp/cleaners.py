"""
Text Cleaning and Normalization
"""
import re

def normalize_text(text):
    """
    Normalize text for analysis:
    1. Convert to lowercase
    2. Remove special characters (keep alphanumeric and spaces)
    3. Remove extra whitespace
    """
    if not text:
        return ""
    
    # Lowercase
    text = text.lower()
    
    # Remove special chars (keep basic punctuation for context if needed, but mostly clean)
    # Keeping alphanumeric, spaces, and basic punctuation .-
    text = re.sub(r'[^a-z0-9\s\.\-]', ' ', text)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def extract_amount(text):
    """
    Try to extract a monetary amount from text.
    Returns float or None.
    """
    # Simple regex for now
    match = re.search(r'(\d+(?:,\d{3})*(?:\.\d{2})?)', text)
    if match:
        try:
            return float(match.group(1).replace(',', ''))
        except ValueError:
            return None
    return None
