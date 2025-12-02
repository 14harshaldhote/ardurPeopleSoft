"""
Finance Module - PDF Parsers
Parse bank statements and financial documents using pdfplumber
Works on cPanel (no Java required)
"""

import pdfplumber
import re
from decimal import Decimal
from datetime import datetime
from dateparser import parse as dateparse
import logging

logger = logging.getLogger('finance')


class BankStatementParser:
    """
    Parse bank statements from PDF files
    Supports multiple bank formats
    """
    
    # Common patterns for bank statements
    PATTERNS = {
        'date': [
            r'\b(\d{2}[-/]\d{2}[-/]\d{4})\b',  # DD-MM-YYYY or DD/MM/YYYY
            r'\b(\d{2}[-/]\d{2}[-/]\d{2})\b',  # DD-MM-YY or DD/MM/YY
            r'\b(\d{4}[-/]\d{2}[-/]\d{2})\b',  # YYYY-MM-DD
        ],
        'amount': [
            r'(?:Rs\.?|INR|₹)\s*([\d,]+\.?\d*)',  # Rs. 1,000.00
            r'([\d,]+\.\d{2})\s*(?:Dr|Cr)',  # 1,000.00 Dr
            r'\b(\d{1,3}(?:,\d{3})*\.\d{2})\b',  # 1,000.00
        ],
        'transaction_id': [
            r'(?:UTR|Ref|Reference)[\s:]+([\w\d]+)',
            r'\b([A-Z0-9]{12,})\b',  # Generic alphanumeric
        ],
    }
    
    def __init__(self, pdf_path):
        """
        Initialize parser with PDF path
        
        Args:
            pdf_path: Path to PDF file
        """
        self.pdf_path = pdf_path
        self.transactions = []
    
    def parse(self):
        """
        Parse PDF and extract transactions
        
        Returns:
            list: List of transaction dictionaries
        """
        try:
            with pdfplumber.open(self.pdf_path) as pdf:
                logger.info(f"Parsing PDF: {self.pdf_path}, Pages: {len(pdf.pages)}")
                
                for page_num, page in enumerate(pdf.pages, 1):
                    # Extract text
                    text = page.extract_text()
                    
                    if not text:
                        logger.warning(f"No text found on page {page_num}")
                        continue
                    
                    # Try table extraction first (more structured)
                    tables = page.extract_tables()
                    
                    if tables:
                        transactions = self._parse_tables(tables, page_num)
                        self.transactions.extend(transactions)
                    else:
                        # Fallback to text parsing
                        transactions = self._parse_text(text, page_num)
                        self.transactions.extend(transactions)
                
                logger.info(f"Extracted {len(self.transactions)} transactions")
                return self.transactions
                
        except Exception as e:
            logger.error(f"Error parsing PDF: {e}", exc_info=True)
            raise
    
    def _parse_tables(self, tables, page_num):
        """
        Parse structured tables from PDF
        
        Args:
            tables: List of tables extracted by pdfplumber
            page_num: Page number
            
        Returns:
            list: Parsed transactions
        """
        transactions = []
        
        for table_idx, table in enumerate(tables):
            if not table or len(table) < 2:
                continue
            
            # Try to identify header row
            header = table[0]
            
            # Find date, description, amount columns
            date_col = self._find_column(header, ['date', 'txn date', 'transaction date'])
            desc_col = self._find_column(header, ['description', 'particulars', 'narration', 'details'])
            debit_col = self._find_column(header, ['debit', 'withdrawal', 'dr'])
            credit_col = self._find_column(header, ['credit', 'deposit', 'cr'])
            balance_col = self._find_column(header, ['balance', 'closing balance'])
            
            # Parse rows
            for row_idx, row in enumerate(table[1:], 1):
                if not row or len(row) == 0:
                    continue
                
                try:
                    transaction = self._extract_transaction_from_row(
                        row, date_col, desc_col, debit_col, credit_col, balance_col
                    )
                    
                    if transaction:
                        transaction['page'] = page_num
                        transaction['table'] = table_idx
                        transaction['row'] = row_idx
                        transactions.append(transaction)
                        
                except Exception as e:
                    logger.warning(f"Error parsing row {row_idx}: {e}")
                    continue
        
        return transactions
    
    def _parse_text(self, text, page_num):
        """
        Parse unstructured text when tables not available
        
        Args:
            text: Extracted text
            page_num: Page number
            
        Returns:
            list: Parsed transactions
        """
        transactions = []
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Look for lines with dates and amounts
            date_match = None
            for pattern in self.PATTERNS['date']:
                match = re.search(pattern, line)
                if match:
                    date_match = match.group(1)
                    break
            
            if not date_match:
                continue
            
            # Extract amount
            amount_match = None
            for pattern in self.PATTERNS['amount']:
                match = re.search(pattern, line)
                if match:
                    amount_match = match.group(1)
                    break
            
            if amount_match:
                try:
                    transaction = {
                        'date': self._parse_date(date_match),
                        'description': self._clean_description(line),
                        'amount': self._parse_amount(amount_match),
                        'type': self._guess_transaction_type(line),
                        'page': page_num,
                        'line': line_num,
                        'raw': line,
                    }
                    transactions.append(transaction)
                except Exception as e:
                    logger.warning(f"Error parsing line {line_num}: {e}")
        
        return transactions
    
    def _find_column(self, header, keywords):
        """Find column index by keywords"""
        if not header:
            return None
        
        for idx, cell in enumerate(header):
            if not cell:
                continue
            cell_lower = str(cell).lower()
            for keyword in keywords:
                if keyword in cell_lower:
                    return idx
        return None
    
    def _extract_transaction_from_row(self, row, date_col, desc_col, debit_col, credit_col, balance_col):
        """Extract transaction from table row"""
        if date_col is None or date_col >= len(row):
            return None
        
        date_str = row[date_col] if date_col < len(row) else None
        if not date_str:
            return None
        
        description = row[desc_col] if desc_col and desc_col < len(row) else ''
        debit = row[debit_col] if debit_col and debit_col < len(row) else None
        credit = row[credit_col] if credit_col and credit_col < len(row) else None
        balance = row[balance_col] if balance_col and balance_col < len(row) else None
        
        # Determine amount and type
        if debit and self._is_numeric(debit):
            amount = self._parse_amount(debit)
            txn_type = 'debit'
        elif credit and self._is_numeric(credit):
            amount = self._parse_amount(credit)
            txn_type = 'credit'
        else:
            return None
        
        return {
            'date': self._parse_date(date_str),
            'description': self._clean_description(description),
            'amount': amount,
            'type': txn_type,
            'balance': self._parse_amount(balance) if balance else None,
        }
    
    def _parse_date(self, date_str):
        """Parse date string to datetime"""
        if not date_str:
            return None
        
        try:
            # Try dateparser first (handles many formats)
            parsed = dateparse(str(date_str))
            return parsed.date() if parsed else None
        except:
            return None
    
    def _parse_amount(self, amount_str):
        """Parse amount string to Decimal"""
        if not amount_str:
            return None
        
        try:
            # Remove currency symbols and commas
            cleaned = str(amount_str).replace('Rs.', '').replace('INR', '').replace('₹', '')
            cleaned = cleaned.replace(',', '').replace('Dr', '').replace('Cr', '').strip()
            
            return Decimal(cleaned)
        except:
            return None
    
    def _clean_description(self, desc):
        """Clean transaction description"""
        if not desc:
            return ''
        
        # Remove extra whitespace
        cleaned = ' '.join(str(desc).split())
        return cleaned[:200]  # Limit length
    
    def _guess_transaction_type(self, line):
        """Guess transaction type from line"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['debit', 'withdrawal', 'dr', 'payment']):
            return 'debit'
        elif any(word in line_lower for word in ['credit', 'deposit', 'cr', 'received']):
            return 'credit'
        else:
            return 'unknown'
    
    def _is_numeric(self, value):
        """Check if value can be parsed as number"""
        if not value:
            return False
        try:
            float(str(value).replace(',', '').replace('Rs.', '').replace('₹', ''))
            return True
        except:
            return False
    
    def export_to_dict_list(self):
        """Export transactions as list of dicts for Django"""
        return self.transactions


class InvoiceParser:
    """Parse invoice PDFs to extract key information"""
    
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
    
    def parse(self):
        """
        Extract invoice details
        
        Returns:
            dict: Invoice data
        """
        try:
            with pdfplumber.open(self.pdf_path) as pdf:
                text = ''
                for page in pdf.pages:
                    text += page.extract_text() or ''
                
                return {
                    'invoice_number': self._extract_invoice_number(text),
                    'date': self._extract_date(text),
                    'total_amount': self._extract_total(text),
                    'vendor_name': self._extract_vendor(text),
                    'items': self._extract_line_items(pdf),
                }
        except Exception as e:
            logger.error(f"Error parsing invoice: {e}")
            return {}
    
    def _extract_invoice_number(self, text):
        """Extract invoice number"""
        patterns = [
            r'Invoice\s*(?:No|Number|#)[\s:]+([A-Z0-9-]+)',
            r'Bill\s*(?:No|Number|#)[\s:]+([A-Z0-9-]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_date(self, text):
        """Extract invoice date"""
        patterns = [
            r'(?:Invoice|Bill)\s*Date[\s:]+(\d{2}[-/]\d{2}[-/]\d{4})',
            r'Date[\s:]+(\d{2}[-/]\d{2}[-/]\d{4})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return dateparse(match.group(1))
        return None
    
    def _extract_total(self, text):
        """Extract total amount"""
        patterns = [
            r'(?:Total|Grand\s*Total|Amount\s*Payable)[\s:]+(?:Rs\.?|INR|₹)\s*([\d,]+\.?\d*)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                amount_str = match.group(1).replace(',', '')
                return Decimal(amount_str)
        return None
    
    def _extract_vendor(self, text):
        """Extract vendor name (basic)"""
        lines = text.split('\n')
        # Assume vendor is in first few lines
        for line in lines[:5]:
            if len(line.strip()) > 3:
                return line.strip()[:100]
        return None
    
    def _extract_line_items(self, pdf):
        """Extract line items from tables"""
        items = []
        
        for page in pdf.pages:
            tables = page.extract_tables()
            for table in tables:
                if not table or len(table) < 2:
                    continue
                
                # Skip header, parse rows
                for row in table[1:]:
                    if row and len(row) >= 2:
                        items.append({
                            'description': row[0],
                            'amount': row[-1]  # Assume amount is last column
                        })
        
        return items[:10]  # Limit to first 10 items


# Usage examples
if __name__ == '__main__':
    # Example: Parse bank statement
    parser = BankStatementParser('path/to/statement.pdf')
    transactions = parser.parse()
    
    for txn in transactions:
        print(f"{txn['date']}: {txn['description']} - {txn['amount']}")
