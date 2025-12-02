"""
Finance Module - Analytics & Forecasting
Financial analytics, forecasting, and anomaly detection using pandas
Interactive visualizations with plotly
"""

import pandas as pd
import numpy as np
from decimal import Decimal
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

logger = logging.getLogger('finance')

# Import plotly for visualizations
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logger.warning("Plotly not available")


class ExpenseAnalyzer:
    """
    Analyze expense patterns and trends
    """
    
    def __init__(self, expenses_data: List[dict]):
        """
        Initialize with expense data
        
        Args:
            expenses_data: List of dicts with keys:
                - date, amount, category, department, etc.
        """
        self.df = pd.DataFrame(expenses_data)
        
        if not self.df.empty:
            # Ensure date is datetime
            if 'date' in self.df.columns:
                self.df['date'] = pd.to_datetime(self.df['date'])
            
            # Ensure amount is numeric
            if 'amount' in self.df.columns:
                self.df['amount'] = pd.to_numeric(self.df['amount'], errors='coerce')
    
    def monthly_summary(self) -> pd.DataFrame:
        """
        Get monthly expense summary
        
        Returns:
            DataFrame with month, total, count, avg
        """
        if self.df.empty or 'date' not in self.df.columns:
            return pd.DataFrame()
        
        # Group by month
        monthly = self.df.groupby(self.df['date'].dt.to_period('M')).agg({
            'amount': ['sum', 'count', 'mean', 'median']
        }).round(2)
        
        monthly.columns = ['total', 'count', 'avg', 'median']
        monthly.index.name = 'month'
        
        return monthly
    
    def category_breakdown(self, period: str = 'all') -> pd.DataFrame:
        """
        Get expense breakdown by category
        
        Args:
            period: 'all', 'this_month', 'last_month', 'this_year'
            
        Returns:
            DataFrame with category totals
        """
        if self.df.empty or 'category' not in self.df.columns:
            return pd.DataFrame()
        
        # Filter by period
        filtered_df = self._filter_by_period(self.df, period)
        
        if filtered_df.empty:
            return pd.DataFrame()
        
        # Group by category
        category_summary = filtered_df.groupby('category').agg({
            'amount': ['sum', 'count', 'mean']
        }).round(2)
        
        category_summary.columns = ['total', 'count', 'avg']
        category_summary = category_summary.sort_values('total', ascending=False)
        
        return category_summary
    
    def department_breakdown(self, period: str = 'this_month') -> pd.DataFrame:
        """Get expense breakdown by department"""
        if self.df.empty or 'department' not in self.df.columns:
            return pd.DataFrame()
        
        filtered_df = self._filter_by_period(self.df, period)
        
        if filtered_df.empty:
            return pd.DataFrame()
        
        dept_summary = filtered_df.groupby('department').agg({
            'amount': ['sum', 'count']
        }).round(2)
        
        dept_summary.columns = ['total', 'count']
        dept_summary = dept_summary.sort_values('total', ascending=False)
        
        return dept_summary
    
    def detect_anomalies(self, threshold: float = 2.0) -> pd.DataFrame:
        """
        Detect anomalous expenses using statistical methods
        
        Args:
            threshold: Number of standard deviations for anomaly
            
        Returns:
            DataFrame of anomalous expenses
        """
        if self.df.empty or 'amount' not in self.df.columns:
            return pd.DataFrame()
        
        # Calculate z-scores
        mean_amount = self.df['amount'].mean()
        std_amount = self.df['amount'].std()
        
        if std_amount == 0:
            return pd.DataFrame()
        
        self.df['z_score'] = (self.df['amount'] - mean_amount) / std_amount
        
        # Find anomalies
        anomalies = self.df[abs(self.df['z_score']) > threshold].copy()
        anomalies = anomalies.sort_values('z_score', ascending= False)
        
        return anomalies[['date', 'amount', 'category', 'z_score']]
    
    def trend_analysis(self, periods: int = 12) -> Dict:
        """
        Analyze expense trends over time
        
        Args:
            periods: Number of months to analyze
            
        Returns:
            dict with trend statistics
        """
        if self.df.empty:
            return {}
        
        # Get last N months
        monthly = self.monthly_summary()
        
        if monthly.empty or len(monthly) < 2:
            return {}
        
        recent = monthly.tail(periods)
        
        # Calculate trend
        x = np.arange(len(recent))
        y = recent['total'].values
        
        # Linear regression
        if len(x) > 1:
            slope, intercept = np.polyfit(x, y, 1)
            
            return {
                'trend': 'increasing' if slope > 0 else 'decreasing',
                'monthly_change': float(slope),
                'avg_monthly': float(recent['total'].mean()),
                'total_period': float(recent['total'].sum()),
                'months_analyzed': len(recent),
            }
        
        return {}
    
    def _filter_by_period(self, df: pd.DataFrame, period: str) -> pd.DataFrame:
        """Filter DataFrame by time period"""
        if period == 'all':
            return df
        
        if 'date' not in df.columns:
            return df
        
        now = pd.Timestamp.now()
        
        if period == 'this_month':
            start = now.replace(day=1)
            return df[df['date'] >= start]
        
        elif period == 'last_month':
            last_month_end = now.replace(day=1) - timedelta(days=1)
            last_month_start = last_month_end.replace(day=1)
            return df[(df['date'] >= last_month_start) & (df['date'] <= last_month_end)]
        
        elif period == 'this_year':
            start = now.replace(month=1, day=1)
            return df[df['date'] >= start]
        
        return df
    
    def create_monthly_chart(self) -> Optional[str]:
        """
        Create interactive monthly expense chart
        
        Returns:
            HTML string for plotly chart or None
        """
        if not PLOTLY_AVAILABLE or self.df.empty:
            return None
        
        monthly = self.monthly_summary()
        
        if monthly.empty:
            return None
        
        fig = go.Figure()
        
        # Add total line
        fig.add_trace(go.Scatter(
            x=[str(m) for m in monthly.index],
            y=monthly['total'],
            mode='lines+markers',
            name='Total Expenses',
            line=dict(color='#FF6B6B', width=3),
            marker=dict(size=8),
        ))
        
        # Add average line
        fig.add_trace(go.Scatter(
            x=[str(m) for m in monthly.index],
            y=monthly['avg'],
            mode='lines',
            name='Average Expense',
            line=dict(color='#4ECDC4', width=2, dash='dash'),
        ))
        
        fig.update_layout(
            title='Monthly Expense Trends',
            xaxis_title='Month',
            yaxis_title='Amount (₹)',
            hovermode='x unified',
            template='plotly_white',
        )
        
        return fig.to_html(include_plotlyjs='cdn')
    
    def create_category_pie_chart(self, period: str = 'this_month') -> Optional[str]:
        """Create pie chart for category breakdown"""
        if not PLOTLY_AVAILABLE or self.df.empty:
            return None
        
        category_data = self.category_breakdown(period)
        
        if category_data.empty:
            return None
        
        fig = go.Figure(data=[go.Pie(
            labels=category_data.index,
            values=category_data['total'],
            hole=0.4,
            marker=dict(colors=px.colors.qualitative.Set3)
        )])
        
        fig.update_layout(
            title=f'Expenses by Category ({period})',
            template='plotly_white',
        )
        
        return fig.to_html(include_plotlyjs='cdn')


class CashFlowForecaster:
    """
    Forecast cash flow based on historical data
    Simple moving average and trend-based forecasting
    """
    
    def __init__(self, historical_data: List[dict]):
        """
        Initialize with historical cash flow data
        
        Args:
            historical_data: List of dicts with {date, inflow, outflow}
        """
        self.df = pd.DataFrame(historical_data)
        
        if not self.df.empty and 'date' in self.df.columns:
            self.df['date'] = pd.to_datetime(self.df['date'])
            self.df = self.df.sort_values('date')
            
            # Calculate net cash flow
            if 'inflow' in self.df.columns and 'outflow' in self.df.columns:
                self.df['net_flow'] = self.df['inflow'] - self.df['outflow']
    
    def forecast_next_month(self, method: str = 'moving_average') -> Dict:
        """
        Forecast next month's cash flow
        
        Args:
            method: 'moving_average' or 'trend'
            
        Returns:
            dict with forecasted values
        """
        if self.df.empty or len(self.df) < 3:
            return {}
        
        if method == 'moving_average':
            return self._moving_average_forecast()
        elif method == 'trend':
            return self._trend_forecast()
        else:
            return {}
    
    def _moving_average_forecast(self, window: int = 3) -> Dict:
        """Simple moving average forecast"""
        recent = self.df.tail(window)
        
        return {
            'forecasted_inflow': float(recent['inflow'].mean()),
            'forecasted_outflow': float(recent['outflow'].mean()),
            'forecasted_net': float(recent['net_flow'].mean()),
            'method': 'moving_average',
            'window': window,
        }
    
    def _trend_forecast(self) -> Dict:
        """Trend-based forecast using linear regression"""
        if len(self.df) < 2:
            return {}
        
        # Prepare data
        x = np.arange(len(self.df))
        
        # Forecast inflow
        inflow_slope, inflow_intercept = np.polyfit(x, self.df['inflow'].values, 1)
        forecasted_inflow = inflow_slope * len(self.df) + inflow_intercept
        
        # Forecast outflow
        outflow_slope, outflow_intercept = np.polyfit(x, self.df['outflow'].values, 1)
        forecasted_outflow = outflow_slope * len(self.df) + outflow_intercept
        
        return {
            'forecasted_inflow': float(max(0, forecasted_inflow)),
            'forecasted_outflow': float(max(0, forecasted_outflow)),
            'forecasted_net': float(forecasted_inflow - forecasted_outflow),
            'method': 'trend',
            'inflow_trend': 'increasing' if inflow_slope > 0 else 'decreasing',
            'outflow_trend': 'increasing' if outflow_slope > 0 else 'decreasing',
        }


class FinancialDashboard:
    """Create comprehensive financial dashboard"""
    
    def __init__(self, expenses_data: List[dict], revenue_data: List[dict] = None):
        """
        Initialize dashboard with data
        
        Args:
            expenses_data: Expense transactions
            revenue_data: Revenue transactions (optional)
        """
        self.expenses_df = pd.DataFrame(expenses_data)
        self.revenue_df = pd.DataFrame(revenue_data) if revenue_data else pd.DataFrame()
        
        # Ensure dates are datetime
        for df in [self.expenses_df, self.revenue_df]:
            if not df.empty and 'date' in df.columns:
                df['date'] = pd.to_datetime(df['date'])
    
    def create_comprehensive_dashboard(self) -> Optional[str]:
        """
        Create multi-panel dashboard
        
        Returns:
            HTML string with dashboard or None
        """
        if not PLOTLY_AVAILABLE:
            return None
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Monthly Trends', 'Category Breakdown', 
                          'Department Comparison', 'Expense vs Revenue'),
            specs=[[{'type': 'scatter'}, {'type': 'pie'}],
                   [{'type': 'bar'}, {'type': 'scatter'}]]
        )
        
        # Add traces (simplified for now)
        if not self.expenses_df.empty:
            # Monthly trend
            monthly = self.expenses_df.groupby(
                self.expenses_df['date'].dt.to_period('M')
            )['amount'].sum()
            
            fig.add_trace(
                go.Scatter(x=[str(m) for m in monthly.index], y=monthly.values,
                          mode='lines+markers', name='Expenses'),
                row=1, col=1
            )
        
        fig.update_layout(height=800, showlegend=True, title_text="Financial Dashboard")
        
        return fig.to_html(include_plotlyjs='cdn')


# Usage examples
if __name__ == '__main__':
    # Example data
    expenses = [
        {'date': '2024-11-01', 'amount': 5000, 'category': 'rent', 'department': 'operations'},
        {'date': '2024-11-05', 'amount': 15000, 'category': 'salary', 'department': 'tech'},
        {'date': '2024-11-10', 'amount': 2000, 'category': 'utilities', 'department': 'operations'},
        {'date': '2024-12-01', 'amount': 5000, 'category': 'rent', 'department': 'operations'},
    ]
    
    analyzer = ExpenseAnalyzer(expenses)
    
    # Monthly summary
    monthly = analyzer.monthly_summary()
    print("Monthly Summary:")
    print(monthly)
    
    # Category breakdown
    categories = analyzer.category_breakdown('this_year')
    print("\nCategory Breakdown:")
    print(categories)
    
    # Trend analysis
    trends = analyzer.trend_analysis()
    print("\nTrends:")
    print(trends)
