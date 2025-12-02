"""
Financial Forecasting Module
Salary burn projections, cash flow trends, expense predictions using statsmodels
"""

from typing import Dict, List, Optional, Tuple
from datetime import date, timedelta
from decimal import Decimal
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np

# Statistical models
try:
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    from statsmodels.tsa.arima.model import ARIMA
    from statsmodels.tsa.seasonal import seasonal_decompose
    from sklearn.linear_model import LinearRegression
    STATS_AVAILABLE = True
except ImportError:
    STATS_AVAILABLE = False
    print("WARNING: statsmodels/sklearn not installed. Install with: pip install statsmodels scikit-learn")


class FinanceForecaster:
    """
    Advanced forecasting for financial metrics
    Uses statsmodels for time series analysis and predictions
    """
    
    def __init__(self, historical_data: pd.DataFrame, date_column: str = 'date', amount_column: str = 'amount'):
        """
        Initialize forecaster with historical data
        
        Args:
            historical_data: DataFrame with historical financial data
            date_column: Name of date column
            amount_column: Name of amount column
        """
        if not STATS_AVAILABLE:
            raise ImportError("statsmodels and scikit-learn are required for forecasting")
        
        self.df = historical_data.copy()
        self.date_col = date_column
        self.amount_col = amount_column
        
        # Ensure date column is datetime
        if self.date_col in self.df.columns:
            self.df[self.date_col] = pd.to_datetime(self.df[self.date_col])
            self.df = self.df.sort_values(self.date_col)
    
    # ============================================
    # Salary Burn Projections
    # ============================================
    
    def forecast_salary_burn(self, months_ahead: int = 6, confidence_level: float = 0.95) -> Dict:
        """
        Forecast monthly salary burn for specified months ahead
        
        Args:
            months_ahead: Number of months to forecast
            confidence_level: Confidence interval level (default: 95%)
            
        Returns:
            dict: Forecast results with predictions and confidence intervals
        """
        # Filter salary-related expenses
        salary_df = self.df[self.df['category'].str.contains('salary|payroll', case=False, na=False)]
        
        if salary_df.empty or len(salary_df) < 3:
            return {
                'error': 'Insufficient salary data for forecasting (need at least 3 months)',
                'method': 'insufficient_data'
            }
        
        # Aggregate by month
        monthly = salary_df.groupby(pd.Grouper(key=self.date_col, freq='MS'))[self.amount_col].sum()
        
        if len(monthly) < 3:
            return {
                'error': 'Need at least 3 months of salary data',
                'method': 'insufficient_data'
            }
        
        # Use Exponential Smoothing for salary forecasting
        try:
            model = ExponentialSmoothing(
                monthly.values,
                seasonal_periods=min(12, len(monthly) // 2) if len(monthly) >= 12 else None,
                trend='add',
                seasonal='add' if len(monthly) >= 12 else None
            )
            fitted = model.fit()
            forecast = fitted.forecast(steps=months_ahead)
            
            # Calculate simple confidence intervals (±10% of forecast)
            ci_width = forecast * 0.1
            lower_ci = forecast - ci_width
            upper_ci = forecast + ci_width
            
            # Generate future dates
            last_date = monthly.index[-1]
            future_dates = pd.date_range(
                start=last_date + pd.DateOffset(months=1),
                periods=months_ahead,
                freq='MS'
            )
            
            results = []
            for i, (fdate, fvalue, lower, upper) in enumerate(zip(future_dates, forecast, lower_ci, upper_ci)):
                results.append({
                    'month': fdate.strftime('%b %Y'),
                    'date': fdate.date(),
                    'forecast': float(fvalue),
                    'lower_bound': float(max(0, lower)),
                    'upper_bound': float(upper),
                    'months_ahead': i + 1,
                })
            
            return {
                'forecasts': results,
                'method': 'exponential_smoothing',
                'historical_months': len(monthly),
                'avg_monthly': float(monthly.mean()),
                'last_actual': float(monthly.iloc[-1]),
                'total_forecast': float(forecast.sum()),
            }
            
        except Exception as e:
            # Fallback to simple moving average
            return self._simple_salary_forecast(monthly, months_ahead)
    
    def _simple_salary_forecast(self, monthly_series: pd.Series, months_ahead: int) -> Dict:
        """Fallback simple forecasting method"""
        avg = monthly_series.mean()
        trend = monthly_series.diff().mean()
        
        last_date = monthly_series.index[-1]
        future_dates = pd.date_range(
            start=last_date + pd.DateOffset(months=1),
            periods=months_ahead,
            freq='MS'
        )
        
        results = []
        for i, fdate in enumerate(future_dates):
            forecast_value = avg + (trend * (i + 1))
            results.append({
                'month': fdate.strftime('%b %Y'),
                'date': fdate.date(),
                'forecast': float(max(0, forecast_value)),
                'lower_bound': float(max(0, forecast_value * 0.9)),
                'upper_bound': float(forecast_value * 1.1),
                'months_ahead': i + 1,
            })
        
        return {
            'forecasts': results,
            'method': 'simple_moving_average',
            'historical_months': len(monthly_series),
            'avg_monthly': float(avg),
        }
    
    # ============================================
    # Cash Flow Projections
    # ============================================
    
    def forecast_cash_flow(self, months_ahead: int = 3) -> Dict:
        """
        Forecast cash flow trend (total expenses) for near term
        
        Args:
            months_ahead: Number of months to forecast
            
        Returns:
            dict: Cash flow forecast
        """
        # Aggregate all expenses by month
        monthly = self.df.groupby(pd.Grouper(key=self.date_col, freq='MS'))[self.amount_col].sum()
        
        if len(monthly) < 3:
            return {
                'error': 'Need at least 3 months of data',
                'method': 'insufficient_data'
            }
        
        try:
            # Use ARIMA for short-term cash flow forecasting
            # ARIMA(1,1,1) - simple autoregressive integrated moving average
            model = ARIMA(monthly.values, order=(1, 1, 1))
            fitted = model.fit()
            forecast = fitted.forecast(steps=months_ahead)
            
            # Get confidence intervals
            forecast_ci = fitted.get_forecast(steps=months_ahead).conf_int()
            
            # Generate future dates
            last_date = monthly.index[-1]
            future_dates = pd.date_range(
                start=last_date + pd.DateOffset(months=1),
                periods=months_ahead,
                freq='MS'
            )
            
            results = []
            for i, (fdate, fvalue) in enumerate(zip(future_dates, forecast)):
                results.append({
                    'month': fdate.strftime('%b %Y'),
                    'date': fdate.date(),
                    'forecast': float(max(0, fvalue)),
                    'lower_bound': float(max(0, forecast_ci[i, 0])),
                    'upper_bound': float(forecast_ci[i, 1]),
                    'months_ahead': i + 1,
                })
            
            return {
                'forecasts': results,
                'method': 'arima',
                'historical_months': len(monthly),
                'avg_monthly': float(monthly.mean()),
                'trend': self._calculate_trend(monthly.values),
            }
            
        except Exception as e:
            # Fallback to linear regression
            return self._linear_cash_flow_forecast(monthly, months_ahead)
    
    def _linear_cash_flow_forecast(self, monthly_series: pd.Series, months_ahead: int) -> Dict:
        """Linear regression fallback for cash flow"""
        X = np.arange(len(monthly_series)).reshape(-1, 1)
        y = monthly_series.values
        
        model = LinearRegression()
        model.fit(X, y)
        
        # Predict future
        future_X = np.arange(len(monthly_series), len(monthly_series) + months_ahead).reshape(-1, 1)
        forecast = model.predict(future_X)
        
        last_date = monthly_series.index[-1]
        future_dates = pd.date_range(
            start=last_date + pd.DateOffset(months=1),
            periods=months_ahead,
            freq='MS'
        )
        
        results = []
        for i, (fdate, fvalue) in enumerate(zip(future_dates, forecast)):
            # Simple ±15% confidence interval
            results.append({
                'month': fdate.strftime('%b %Y'),
                'date': fdate.date(),
                'forecast': float(max(0, fvalue)),
                'lower_bound': float(max(0, fvalue * 0.85)),
                'upper_bound': float(fvalue * 1.15),
                'months_ahead': i + 1,
            })
        
        return {
            'forecasts': results,
            'method': 'linear_regression',
            'historical_months': len(monthly_series),
            'avg_monthly': float(monthly_series.mean()),
            'trend': 'increasing' if model.coef_[0] > 0 else 'decreasing',
        }
    
    # ============================================
    # Category-specific Forecasts
    # ============================================
    
    def forecast_by_category(self, category: str, months_ahead: int = 3) -> Dict:
        """
        Forecast spending for specific category
        
        Args:
            category: Expense category
            months_ahead: Months to forecast
            
        Returns:
            dict: Category forecast
        """
        cat_df = self.df[self.df['category'] == category]
        
        if cat_df.empty or len(cat_df) < 3:
            return {
                'error': f'Insufficient data for category: {category}',
                'category': category
            }
        
        monthly = cat_df.groupby(pd.Grouper(key=self.date_col, freq='MS'))[self.amount_col].sum()
        
        # Simple moving average for category forecasting
        window = min(3, len(monthly))
        ma = monthly.rolling(window=window).mean().iloc[-1]
        
        last_date = monthly.index[-1]
        future_dates = pd.date_range(
            start=last_date + pd.DateOffset(months=1),
            periods=months_ahead,
            freq='MS'
        )
        
        results = []
        for i, fdate in enumerate(future_dates):
            results.append({
                'month': fdate.strftime('%b %Y'),
                'date': fdate.date(),
                'forecast': float(ma),
                'category': category,
            })
        
        return {
            'category': category,
            'forecasts': results,
            'method': 'moving_average',
            'historical_months': len(monthly),
            'avg_monthly': float(monthly.mean()),
        }
    
   # ============================================
    # Trend Analysis
    # ============================================
    
    def analyze_trend(self, months: int = 12) -> Dict:
        """
        Analyze spending trend over specified period
        
        Args:
            months: Number of months to analyze
            
        Returns:
            dict: Trend analysis results
        """
        cutoff = pd.Timestamp.now() - pd.DateOffset(months=months)
        recent = self.df[self.df[self.date_col] >= cutoff]
        
        monthly = recent.groupby(pd.Grouper(key=self.date_col, freq='MS'))[self.amount_col].sum()
        
        if len(monthly) < 3:
            return {'error': 'Need at least 3 months for trend analysis'}
        
        # Calculate trend metrics
        trend_direction = self._calculate_trend(monthly.values)
        volatility = float(monthly.std() / monthly.mean() * 100) if monthly.mean() > 0 else 0
        
        # Month-over-month growth
        mom_growth = monthly.pct_change().dropna()
        
        return {
            'period_months': len(monthly),
            'trend': trend_direction,
            'avg_monthly': float(monthly.mean()),
            'min_monthly': float(monthly.min()),
            'max_monthly': float(monthly.max()),
            'volatility_pct': round(volatility, 2),
            'avg_mom_growth': float(mom_growth.mean() * 100),
            'consistent_growth': float(mom_growth[mom_growth > 0].count() / len(mom_growth) * 100) if len(mom_growth) > 0 else 0,
        }
    
    def _calculate_trend(self, values: np.ndarray) -> str:
        """Calculate trend direction from time series"""
        if len(values) < 2:
            return 'stable'
        
        X = np.arange(len(values)).reshape(-1, 1)
        y = values
        
        model = LinearRegression()
        model.fit(X, y)
        
        slope = model.coef_[0]
        
        # Determine trend based on slope
        mean_val = float(np.mean(values))  # Convert to float for comparison
        if abs(slope) < (mean_val * 0.02):  # Less than 2% change per month
            return 'stable'
        elif slope > 0:
            return 'increasing'
        else:
            return 'decreasing'
    
    # ============================================
    # Seasonality Detection
    # ============================================
    
    def detect_seasonality(self) -> Dict:
        """
        Detect seasonal patterns in expense data
        
        Returns:
            dict: Seasonality analysis
        """
        monthly = self.df.groupby(pd.Grouper(key=self.date_col, freq='MS'))[self.amount_col].sum()
        
        if len(monthly) < 24:  # Need at least 2 years for good seasonality detection
            return {
                'seasonal': False,
                'reason': 'Need at least 24 months of data for reliable seasonality detection',
                'months_available': len(monthly)
            }
        
        try:
            # Decompose time series
            decomposition = seasonal_decompose(monthly.values, model='additive', period=12)
            
            # Calculate seasonality strength
            seasonal_var = np.var(decomposition.seasonal)
            total_var = np.var(monthly.values)
            seasonal_strength = seasonal_var / total_var if total_var > 0 else 0
            
            # Get monthly seasonal indices
            seasonal_indices = {}
            for i, month_name in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                           'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']):
                seasonal_indices[month_name] = float(decomposition.seasonal[i])
            
            return {
                'seasonal': seasonal_strength > 0.1,  # More than 10% of variance
                'strength': float(seasonal_strength),
                'monthly_indices': seasonal_indices,
                'peak_month': max(seasonal_indices, key=seasonal_indices.get),
                'low_month': min(seasonal_indices, key=seasonal_indices.get),
            }
            
        except Exception as e:
            return {
                'seasonal': False,
                'error': str(e),
            }


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    print("Finance Forecaster - Usage Examples\n")
    
    print("1. Salary Burn Forecast:")
    print("   df = pd.DataFrame({'date': dates, 'amount': amounts, 'category': categories})")
    print("   forecaster = FinanceForecaster(df)")
    print("   salary_forecast = forecaster.forecast_salary_burn(months_ahead=6)")
    print()
    
    print("2. Cash Flow Projection:")
    print("   cash_flow = forecaster.forecast_cash_flow(months_ahead=3)")
    print()
    
    print("3. Category Forecast:")
    print("   travel_forecast = forecaster.forecast_by_category('travel', months_ahead=3)")
    print()
    
    print("4. Trend Analysis:")
    print("   trend = forecaster.analyze_trend(months=12)")
    print()
    
    print("5. Seasonality Detection:")
    print("   seasonality = forecaster.detect_seasonality()")
