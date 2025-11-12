"""
Leave Management Analytics and Monitoring
"""
from django.db.models import Count, Sum, Avg, Q
from django.utils import timezone
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

from trueAlign.models import LeaveRequest, LeaveType, UserLeaveBalance, CompOffRequest

analytics_logger = logging.getLogger('leave_management.analytics')

class LeaveAnalytics:
    """Comprehensive analytics for leave management"""
    
    @staticmethod
    def get_leave_usage_stats(year: int = None) -> Dict[str, Any]:
        """Get comprehensive leave usage statistics"""
        if not year:
            year = timezone.now().year
        
        stats = {
            'total_requests': LeaveRequest.objects.filter(
                start_date__year=year
            ).count(),
            
            'approved_requests': LeaveRequest.objects.filter(
                start_date__year=year,
                status='Approved'
            ).count(),
            
            'pending_requests': LeaveRequest.objects.filter(
                start_date__year=year,
                status='Pending'
            ).count(),
            
            'rejected_requests': LeaveRequest.objects.filter(
                start_date__year=year,
                status='Rejected'
            ).count(),
            
            'total_leave_days': LeaveRequest.objects.filter(
                start_date__year=year,
                status='Approved'
            ).aggregate(total=Sum('leave_days'))['total'] or 0,
            
            'average_leave_days': LeaveRequest.objects.filter(
                start_date__year=year,
                status='Approved'
            ).aggregate(avg=Avg('leave_days'))['avg'] or 0,
        }
        
        # Leave type breakdown
        leave_type_stats = LeaveRequest.objects.filter(
            start_date__year=year,
            status='Approved'
        ).values('leave_type__name').annotate(
            count=Count('id'),
            total_days=Sum('leave_days')
        ).order_by('-total_days')
        
        stats['leave_type_breakdown'] = list(leave_type_stats)
        
        # Monthly trends
        monthly_stats = []
        for month in range(1, 13):
            month_data = LeaveRequest.objects.filter(
                start_date__year=year,
                start_date__month=month,
                status='Approved'
            ).aggregate(
                count=Count('id'),
                total_days=Sum('leave_days')
            )
            monthly_stats.append({
                'month': month,
                'requests': month_data['count'] or 0,
                'days': float(month_data['total_days'] or 0)
            })
        
        stats['monthly_trends'] = monthly_stats
        
        return stats
    
    @staticmethod
    def get_user_leave_patterns(user: User, year: int = None) -> Dict[str, Any]:
        """Analyze individual user leave patterns"""
        if not year:
            year = timezone.now().year
        
        user_requests = LeaveRequest.objects.filter(
            user=user,
            start_date__year=year
        )
        
        patterns = {
            'total_requests': user_requests.count(),
            'approved_days': user_requests.filter(
                status='Approved'
            ).aggregate(total=Sum('leave_days'))['total'] or 0,
            
            'pending_requests': user_requests.filter(
                status='Pending'
            ).count(),
            
            'average_request_size': user_requests.filter(
                status='Approved'
            ).aggregate(avg=Avg('leave_days'))['avg'] or 0,
            
            'leave_frequency': user_requests.filter(
                status='Approved'
            ).count(),
        }
        
        # Leave type preferences
        type_preferences = user_requests.filter(
            status='Approved'
        ).values('leave_type__name').annotate(
            count=Count('id'),
            total_days=Sum('leave_days')
        ).order_by('-total_days')
        
        patterns['leave_type_preferences'] = list(type_preferences)
        
        # Seasonal patterns (quarters)
        quarterly_usage = []
        for quarter in range(1, 5):
            start_month = (quarter - 1) * 3 + 1
            end_month = quarter * 3
            
            quarter_data = user_requests.filter(
                status='Approved',
                start_date__month__gte=start_month,
                start_date__month__lte=end_month
            ).aggregate(
                count=Count('id'),
                total_days=Sum('leave_days')
            )
            
            quarterly_usage.append({
                'quarter': quarter,
                'requests': quarter_data['count'] or 0,
                'days': float(quarter_data['total_days'] or 0)
            })
        
        patterns['quarterly_usage'] = quarterly_usage
        
        return patterns
    
    @staticmethod
    def detect_unusual_patterns() -> List[Dict[str, Any]]:
        """Detect unusual leave patterns that might need attention"""
        alerts = []
        current_date = timezone.now().date()
        
        # Users with excessive leave requests in short time
        recent_heavy_users = LeaveRequest.objects.filter(
            created_at__gte=current_date - timedelta(days=30)
        ).values('user').annotate(
            request_count=Count('id')
        ).filter(request_count__gte=5)
        
        for user_data in recent_heavy_users:
            user = User.objects.get(id=user_data['user'])
            alerts.append({
                'type': 'EXCESSIVE_REQUESTS',
                'user': user.username,
                'details': f"{user_data['request_count']} requests in last 30 days",
                'severity': 'MEDIUM'
            })
        
        # Users with high rejection rates
        users_with_rejections = LeaveRequest.objects.filter(
            created_at__gte=current_date - timedelta(days=90)
        ).values('user').annotate(
            total_requests=Count('id'),
            rejected_requests=Count('id', filter=Q(status='Rejected'))
        ).filter(total_requests__gte=3)
        
        for user_data in users_with_rejections:
            rejection_rate = user_data['rejected_requests'] / user_data['total_requests']
            if rejection_rate > 0.5:  # More than 50% rejection rate
                user = User.objects.get(id=user_data['user'])
                alerts.append({
                    'type': 'HIGH_REJECTION_RATE',
                    'user': user.username,
                    'details': f"{rejection_rate:.1%} rejection rate ({user_data['rejected_requests']}/{user_data['total_requests']})",
                    'severity': 'HIGH'
                })
        
        # Pending requests older than 7 days
        old_pending = LeaveRequest.objects.filter(
            status='Pending',
            created_at__lte=current_date - timedelta(days=7)
        ).select_related('user', 'leave_type')
        
        for request in old_pending:
            alerts.append({
                'type': 'STALE_PENDING_REQUEST',
                'user': request.user.username,
                'details': f"Request #{request.id} pending for {(current_date - request.created_at.date()).days} days",
                'severity': 'MEDIUM'
            })
        
        return alerts
    
    @staticmethod
    def get_team_analytics(manager_user: User) -> Dict[str, Any]:
        """Get analytics for a manager's team"""
        # For now, assume all employees report to managers
        # In real implementation, this would use proper reporting structure
        team_members = User.objects.filter(
            groups__name='Employee',
            is_active=True
        )
        
        current_year = timezone.now().year
        
        team_stats = {
            'team_size': team_members.count(),
            'total_team_requests': LeaveRequest.objects.filter(
                user__in=team_members,
                start_date__year=current_year
            ).count(),
            
            'pending_approvals': LeaveRequest.objects.filter(
                user__in=team_members,
                status='Pending'
            ).count(),
            
            'team_leave_days': LeaveRequest.objects.filter(
                user__in=team_members,
                start_date__year=current_year,
                status='Approved'
            ).aggregate(total=Sum('leave_days'))['total'] or 0,
        }
        
        # Individual team member stats
        member_stats = []
        for member in team_members:
            member_data = LeaveRequest.objects.filter(
                user=member,
                start_date__year=current_year
            ).aggregate(
                total_requests=Count('id'),
                approved_days=Sum('leave_days', filter=Q(status='Approved')),
                pending_requests=Count('id', filter=Q(status='Pending'))
            )
            
            member_stats.append({
                'user': member.username,
                'name': member.get_full_name(),
                'total_requests': member_data['total_requests'] or 0,
                'approved_days': float(member_data['approved_days'] or 0),
                'pending_requests': member_data['pending_requests'] or 0
            })
        
        team_stats['member_breakdown'] = member_stats
        
        return team_stats
    
    @staticmethod
    def generate_compliance_report(year: int = None) -> Dict[str, Any]:
        """Generate compliance and audit report"""
        if not year:
            year = timezone.now().year
        
        report = {
            'report_generated': timezone.now().isoformat(),
            'year': year,
            'total_employees': User.objects.filter(is_active=True).count(),
        }
        
        # Leave utilization rates
        all_users = User.objects.filter(is_active=True)
        utilization_data = []
        
        for user in all_users:
            balances = UserLeaveBalance.objects.filter(user=user, year=year)
            total_allocated = sum(float(b.allocated) for b in balances)
            total_used = sum(float(b.used) for b in balances)
            
            if total_allocated > 0:
                utilization_rate = (total_used / total_allocated) * 100
            else:
                utilization_rate = 0
            
            utilization_data.append({
                'user': user.username,
                'allocated': total_allocated,
                'used': total_used,
                'utilization_rate': round(utilization_rate, 2)
            })
        
        report['utilization_analysis'] = utilization_data
        
        # Policy compliance
        policy_violations = []
        
        # Check for requests exceeding policy limits
        excessive_requests = LeaveRequest.objects.filter(
            start_date__year=year,
            leave_days__gt=30  # Assuming 30 days is a reasonable limit
        ).select_related('user', 'leave_type')
        
        for request in excessive_requests:
            policy_violations.append({
                'type': 'EXCESSIVE_LEAVE_DAYS',
                'user': request.user.username,
                'request_id': request.id,
                'days': float(request.leave_days),
                'leave_type': request.leave_type.name
            })
        
        report['policy_violations'] = policy_violations
        
        return report
