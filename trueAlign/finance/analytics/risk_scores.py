"""
Risk Scoring Module
Employee and vendor risk assessment with rule-based scoring
"""

from typing import Dict, List, Optional, Tuple
from datetime import date, timedelta
from decimal import Decimal
import pandas as pd
import numpy as np


class RiskScorer:
    """
    Calculate risk scores for employees, vendors, and transactions
    Combines multiple factors for comprehensive risk assessment
    """
    
    # Risk score thresholds
    RISK_LOW = 30
    RISK_MEDIUM = 60
    RISK_HIGH = 80
    
    def __init__(self, transactions_df: pd.DataFrame):
        """
        Initialize risk scorer
        
        Args:
            transactions_df: DataFrame with transaction data
        """
        self.df = transactions_df.copy()
    
    # ============================================
    # Employee Risk Scoring
    # ============================================
    
    def score_employee_risk(self, employee_id: int) -> Dict:
        """
        Calculate comprehensive risk score for employee
        
        Factors:
        - High-value transactions (10 points per >50K expense)
        - Frequent expenses (5 points if >20 expenses/month)
        - Missing receipts/documentation (15 points each)
        - Late submissions (5 points each)
        - Policy violations (20 points each)
        - Unusual patterns (10-30 points)
        
        Args:
            employee_id: Employee ID to score
            
        Returns:
            dict: Risk score and breakdown
        """
        emp_txns = self.df[self.df['paid_by_id'] == employee_id]
        
        if emp_txns.empty:
            return {
                'employee_id': employee_id,
                'risk_score': 0,
                'risk_level': 'unknown',
                'factors': [],
            }
        
        risk_factors = []
        total_score = 0
        
        # Factor 1: High-value transactions
        high_value = emp_txns[emp_txns['amount'] > 50000]
        if len(high_value) > 0:
            points = min(len(high_value) * 10, 50)
            total_score += points
            risk_factors.append({
                'factor': 'High-value transactions',
                'count': len(high_value),
                'points': points,
                'description': f'{len(high_value)} transactions >₹50,000'
            })
        
        # Factor 2: Transaction frequency
        months_active = (emp_txns['date'].max() - emp_txns['date'].min()).days / 30
        if months_active > 0:
            txns_per_month = len(emp_txns) / months_active
            if txns_per_month > 20:
                points = 15
                total_score += points
                risk_factors.append({
                    'factor': 'High transaction frequency',
                    'value': round(txns_per_month, 1),
                    'points': points,
                    'description': f'{txns_per_month:.1f} transactions/month'
                })
        
        # Factor 3: Missing documentation (if has_attachment field)
        if 'has_attachment' in emp_txns.columns:
            missing_docs = emp_txns[emp_txns['has_attachment'] == False]
            if len(missing_docs) > 0:
                points = min(len(missing_docs) * 5, 40)
                total_score += points
                risk_factors.append({
                    'factor': 'Missing documentation',
                    'count': len(missing_docs),
                    'points': points,
                    'description': f'{len(missing_docs)} expenses without receipts'
                })
        
        # Factor 4: Weekend/holiday expenses (unusual pattern)
        if 'date' in emp_txns.columns:
            emp_txns['dayofweek'] = pd.to_datetime(emp_txns['date']).dt.dayofweek
            weekend_txns = emp_txns[emp_txns['dayofweek'].isin([5, 6])]  # Sat, Sun
            if len(weekend_txns) > 0 and len(weekend_txns) / len(emp_txns) > 0.3:
                points = 15
                total_score += points
                risk_factors.append({
                    'factor': 'Unusual timing pattern',
                    'percentage': round(len(weekend_txns) / len(emp_txns) * 100, 1),
                    'points': points,
                    'description': f'{len(weekend_txns)} weekend transactions'
                })
        
        # Factor 5: Duplicate or near-duplicate expenses
        duplicates = self._find_employee_duplicates(emp_txns)
        if len(duplicates) > 0:
            points = min(len(duplicates) * 10, 30)
            total_score += points
            risk_factors.append({
                'factor': 'Potential duplicate expenses',
                'count': len(duplicates),
                'points': points,
                'description': f'{len(duplicates)} possible duplicate claims'
            })
        
        # Factor 6: Category diversity (lack of focus might indicate misuse)
        if 'category' in emp_txns.columns:
            unique_categories = emp_txns['category'].nunique()
            if unique_categories > 8:  # More than 8 different categories
                points = 10
                total_score += points
                risk_factors.append({
                    'factor': 'High category diversity',
                    'count': unique_categories,
                    'points': points,
                    'description': f'Expenses across {unique_categories} categories'
                })
        
        # Determine risk level
        risk_level = self._get_risk_level(total_score)
        
        return {
            'employee_id': employee_id,
            'risk_score': total_score,
            'risk_level': risk_level,
            'total_transactions': len(emp_txns),
            'total_amount': float(emp_txns['amount'].sum()),
            'factors': risk_factors,
            'factor_count': len(risk_factors),
        }
    
    def _find_employee_duplicates(self, emp_txns: pd.DataFrame) -> List[Dict]:
        """Find potential duplicate expenses for employee"""
        duplicates = []
        
        # Group by date and amount
        grouped = emp_txns.groupby(['date', 'amount'])
        for (date_val, amount_val), group in grouped:
            if len(group) > 1:
                duplicates.append({
                    'date': date_val,
                    'amount': float(amount_val),
                    'count': len(group)
                })
        
        return duplicates
    
    # ============================================
    # Vendor Risk Scoring
    # ============================================
    
    def score_vendor_risk(self, vendor: str) -> Dict:
        """
        Calculate risk score for vendor
        
        Factors:
        - New vendor (20 points if <3 months)
        - High transaction amounts (10 points per >100K)
        - Irregular patterns (10-20 points)
        - Single-employee usage (15 points)
        - Unusual frequency spikes (10 points)
        
        Args:
            vendor: Vendor name
            
        Returns:
            dict: Risk score and breakdown
        """
        vendor_txns = self.df[self.df['vendor'].str.contains(vendor, case=False, na=False)]
        
        if vendor_txns.empty:
            return {
                'vendor': vendor,
                'risk_score': 0,
                'risk_level': 'unknown',
                'factors': [],
            }
        
        risk_factors = []
        total_score = 0
        
        # Factor 1: New vendor
        first_txn = vendor_txns['date'].min()
        days_active = (date.today() - pd.to_datetime(first_txn).date()).days
        if days_active < 90:  # Less than 3 months
            points = 20
            total_score += points
            risk_factors.append({
                'factor': 'New vendor',
                'days_active': days_active,
                'points': points,
                'description': f'Only {days_active} days of history'
            })
        
        # Factor 2: High-value transactions
        high_value = vendor_txns[vendor_txns['amount'] > 100000]
        if len(high_value) > 0:
            points = min(len(high_value) * 10, 40)
            total_score += points
            risk_factors.append({
                'factor': 'High-value transactions',
                'count': len(high_value),
                'points': points,
                'description': f'{len(high_value)} transactions >₹1L'
            })
        
        # Factor 3: Single employee usage
        unique_employees = vendor_txns['paid_by_id'].nunique()
        if unique_employees == 1 and len(vendor_txns) > 5:
            points = 15
            total_score += points
            risk_factors.append({
                'factor': 'Single employee usage',
                'employee_count': unique_employees,
                'points': points,
                'description': 'All transactions by one employee'
            })
        
        # Factor 4: Transaction amount variance (inconsistent pricing)
        # Convert to float for pandas calculations
        amounts_float = vendor_txns['amount'].astype(float)
        amount_std = amounts_float.std()
        amount_mean = amounts_float.mean()
        if amount_mean > 0:
            cv = amount_std / amount_mean  # Coefficient of variation
            if cv > 1.5:  # High variance
                points = 15
                total_score += points
                risk_factors.append({
                    'factor': 'Inconsistent transaction amounts',
                    'variance': round(float(cv), 2),
                    'points': points,
                    'description': 'Wide variance in transaction amounts'
                })
        
        # Factor 5: Frequency spikes
        # Fix: Set date as datetime index for pd.Grouper
        try:
            vendor_txns_indexed = vendor_txns.copy()
            vendor_txns_indexed['date'] = pd.to_datetime(vendor_txns_indexed['date'])
            vendor_txns_indexed = vendor_txns_indexed.set_index('date')
            monthly_counts = vendor_txns_indexed.groupby(pd.Grouper(freq='M')).size()
            
            if len(monthly_counts) > 1:
                avg_monthly = monthly_counts.mean()
                max_monthly = monthly_counts.max()
                if max_monthly > avg_monthly * 3:  # 3x spike
                    points = 10
                    total_score += points
                    risk_factors.append({
                        'factor': 'Transaction frequency spike',
                        'max_monthly': int(max_monthly),
                        'avg_monthly': round(float(avg_monthly), 1),
                        'points': points,
                        'description': f'Spike of {int(max_monthly)} txns in one month'
                    })
        except Exception:
            # Skip frequency spike analysis if date handling fails
            pass
        
        risk_level = self._get_risk_level(total_score)
        
        return {
            'vendor': vendor,
            'risk_score': total_score,
            'risk_level': risk_level,
            'total_transactions': len(vendor_txns),
            'total_amount': float(vendor_txns['amount'].sum()),
            'unique_employees': unique_employees,
            'factors': risk_factors,
            'factor_count': len(risk_factors),
        }
    
    # ============================================
    # Transaction Risk Scoring
    # ============================================
    
    def score_transaction_risk(self, transaction: Dict) -> Dict:
        """
        Score individual transaction risk
        
        Args:
            transaction: Transaction dict with amount, category, etc.
            
        Returns:
            dict: Risk assessment
        """
        risk_factors = []
        total_score = 0
        
        amount = float(transaction.get('amount', 0))
        
        # High amount
        if amount > 50000:
            points = 20
            total_score += points
            risk_factors.append({
                'factor': 'High amount',
                'value': amount,
                'points': points
            })
        
        # Round number (might indicate estimation)
        if amount % 1000 == 0 and amount > 1000:
            points = 5
            total_score += points
            risk_factors.append({
                'factor': 'Round number',
                'points': points
            })
        
        # Missing documentation
        if not transaction.get('has_attachment', True):
            points = 15
            total_score += points
            risk_factors.append({
                'factor': 'Missing receipt',
                'points': points
            })
        
        # Uncategorized
        if not transaction.get('category'):
            points = 10
            total_score += points
            risk_factors.append({
                'factor': 'Uncategorized',
                'points': points
            })
        
        risk_level = self._get_risk_level(total_score)
        
        return {
            'transaction_id': transaction.get('id'),
            'risk_score': total_score,
            'risk_level': risk_level,
            'factors': risk_factors,
        }
    
    # ============================================
    # Aggregated Risk Reports
    # ============================================
    
    def generate_risk_heatmap_data(self) -> Dict:
        """
        Generate data for risk heatmap visualization
        
        Returns:
            dict: Heatmap data with employees, vendors, categories
        """
        # Employee risks
        employee_risks = []
        for emp_id in self.df['paid_by_id'].unique():
            if pd.notna(emp_id):
                score = self.score_employee_risk(int(emp_id))
                employee_risks.append(score)
        
        # Vendor risks
        vendor_risks = []
        top_vendors = self.df['vendor'].value_counts().head(20).index
        for vendor in top_vendors:
            if vendor:
                score = self.score_vendor_risk(vendor)
                vendor_risks.append(score)
        
        # Category risks (aggregated)
        category_risks = []
        for category in self.df['category'].unique():
            if pd.notna(category):
                cat_txns = self.df[self.df['category'] == category]
                avg_risk = self._calculate_category_avg_risk(cat_txns)
                category_risks.append({
                    'category': category,
                    'risk_score': avg_risk,
                    'risk_level': self._get_risk_level(avg_risk),
                    'transaction_count': len(cat_txns),
                })
        
        return {
            'employees': sorted(employee_risks, key=lambda x: x['risk_score'], reverse=True)[:20],
            'vendors': sorted(vendor_risks, key=lambda x: x['risk_score'], reverse=True)[:20],
            'categories': sorted(category_risks, key=lambda x: x['risk_score'], reverse=True),
        }
    
    def _calculate_category_avg_risk(self, cat_txns: pd.DataFrame) -> float:
        """Calculate average risk for category"""
        risk_sum = 0
        
        # Convert amounts to float
        amounts = cat_txns['amount'].astype(float)
        
        # High amounts
        high_value_pct = len(amounts[amounts > 50000]) / len(amounts) * 100
        risk_sum += high_value_pct * 0.3
        
        # Amount variance
        cv = amounts.std() / amounts.mean() if amounts.mean() > 0 else 0
        risk_sum += min(float(cv) * 10, 30)
        
        return min(risk_sum, 100)
    
    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score < self.RISK_LOW:
            return 'low'
        elif score < self.RISK_MEDIUM:
            return 'medium'
        elif score < self.RISK_HIGH:
            return 'high'
        else:
            return 'critical'


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    print("Risk Scorer - Usage Examples\n")
    
    print("1. Employee Risk:")
    print("   scorer = RiskScorer(transactions_df)")
    print("   risk = scorer.score_employee_risk(employee_id=123)")
    print()
    
    print("2. Vendor Risk:")
    print("   risk = scorer.score_vendor_risk('Google')")
    print()
    
    print("3. Transaction Risk:")
    print("   risk = scorer.score_transaction_risk(transaction_dict)")
    print()
    
    print("4. Risk Heatmap:")
    print("   heatmap = scorer.generate_risk_heatmap_data()")
