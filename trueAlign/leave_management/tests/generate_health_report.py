#!/usr/bin/env python
"""
Leave Management System - Health Report Generator

This script generates a comprehensive health report for the Leave Management System,
checking database integrity, data consistency, and system configuration.
"""

import os
import sys
import django
import json
import datetime
from decimal import Decimal
from collections import defaultdict
import argparse
import logging

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ardurPeopleSoft.settings")
django.setup()

from django.contrib.auth.models import User, Group
from django.db import connection
from django.db.models import Sum, Count, Q
from django.utils import timezone
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, Attendance
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('leave_management_health.log')
    ]
)
logger = logging.getLogger(__name__)

class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Decimal objects"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

def get_database_stats():
    """Get database statistics for the Leave Management System"""
    stats = {
        'users': {
            'total': User.objects.count(),
            'active': User.objects.filter(is_active=True).count(),
            'inactive': User.objects.filter(is_active=False).count(),
        },
        'groups': {
            'total': Group.objects.count(),
            'distribution': {}
        },
        'leave_types': {
            'total': LeaveType.objects.count(),
            'active': LeaveType.objects.filter(is_active=True).count(),
            'paid': LeaveType.objects.filter(is_paid=True).count(),
            'half_day_allowed': LeaveType.objects.filter(can_be_half_day=True).count(),
        },
        'leave_policies': {
            'total': LeavePolicy.objects.count(),
            'active': LeavePolicy.objects.filter(is_active=True).count(),
        },
        'leave_allocations': {
            'total': LeaveAllocation.objects.count(),
        },
        'leave_balances': {
            'total': UserLeaveBalance.objects.count(),
            'current_year': UserLeaveBalance.objects.filter(year=timezone.now().year).count(),
        },
        'leave_requests': {
            'total': LeaveRequest.objects.count(),
            'pending': LeaveRequest.objects.filter(status='Pending').count(),
            'approved': LeaveRequest.objects.filter(status='Approved').count(),
            'rejected': LeaveRequest.objects.filter(status='Rejected').count(),
            'cancelled': LeaveRequest.objects.filter(status='Cancelled').count(),
            'current_year': LeaveRequest.objects.filter(
                start_date__year=timezone.now().year
            ).count(),
        }
    }

    # Add group distribution
    for group in Group.objects.all():
        stats['groups']['distribution'][group.name] = group.user_set.count()

    return stats

def check_data_integrity():
    """Check data integrity and identify potential issues"""
    issues = []

    # Check for orphaned records
    orphaned_allocations = LeaveAllocation.objects.filter(
        Q(policy__isnull=True) | Q(leave_type__isnull=True)
    ).count()
    if orphaned_allocations > 0:
        issues.append(f"Found {orphaned_allocations} orphaned leave allocations")

    orphaned_balances = UserLeaveBalance.objects.filter(
        Q(user__isnull=True) | Q(leave_type__isnull=True)
    ).count()
    if orphaned_balances > 0:
        issues.append(f"Found {orphaned_balances} orphaned user leave balances")

    orphaned_requests = LeaveRequest.objects.filter(
        Q(user__isnull=True) | Q(leave_type__isnull=True)
    ).count()
    if orphaned_requests > 0:
        issues.append(f"Found {orphaned_requests} orphaned leave requests")

    # Check for inconsistent balance calculations
    negative_balances = UserLeaveBalance.objects.filter(allocated__lt=0).count()
    if negative_balances > 0:
        issues.append(f"Found {negative_balances} negative allocated balances")

    # Check for users without leave balances for current year
    users_without_balance = User.objects.filter(
        is_active=True,
        groups__name='Employee'
    ).exclude(
        leave_balances__year=timezone.now().year
    ).distinct().count()
    if users_without_balance > 0:
        issues.append(f"Found {users_without_balance} active employees without current year leave balances")

    # Check for overlapping approved leaves
    overlapping_leaves = 0
    approved_leaves = LeaveRequest.objects.filter(status='Approved')

    # Simple O(n²) approach for a small number of leaves
    # In production, use a more efficient algorithm
    processed = set()
    for leave1 in approved_leaves:
        for leave2 in approved_leaves:
            if leave1.id == leave2.id or (leave1.id, leave2.id) in processed or (leave2.id, leave1.id) in processed:
                continue

            if (leave1.user_id == leave2.user_id and
                leave1.start_date <= leave2.end_date and
                leave2.start_date <= leave1.end_date):
                overlapping_leaves += 1
                processed.add((leave1.id, leave2.id))

    if overlapping_leaves > 0:
        issues.append(f"Found {overlapping_leaves} potentially overlapping approved leaves")

    # Return integrity report
    return {
        'issues_count': len(issues),
        'issues': issues,
        'integrity_score': 100 - (len(issues) * 10) if len(issues) <= 10 else 0
    }

def check_user_setup():
    """Check if users are properly set up with groups and policies"""
    group_counts = {
        'admin': Group.objects.filter(name='Admin').count(),
        'hr': Group.objects.filter(name='HR').count(),
        'manager': Group.objects.filter(name='Manager').count(),
        'employee': Group.objects.filter(name='Employee').count(),
        'finance': Group.objects.filter(name='Finance').count(),
    }

    users_without_groups = User.objects.filter(
        is_active=True,
        groups__isnull=True
    ).count()

    policy_coverage = {}
    for group in Group.objects.all():
        policy = LeavePolicy.objects.filter(group=group, is_active=True).exists()
        policy_coverage[group.name] = policy

    # Calculate user setup score
    setup_score = 100

    if users_without_groups > 0:
        setup_score -= min(20, users_without_groups * 2)

    for group_name, has_policy in policy_coverage.items():
        if not has_policy and group_name in ['Admin', 'HR', 'Manager', 'Employee']:
            setup_score -= 15

    # Check required groups
    for group, count in group_counts.items():
        if count == 0 and group in ['admin', 'hr', 'manager', 'employee']:
            setup_score -= 10

    return {
        'group_counts': group_counts,
        'users_without_groups': users_without_groups,
        'policy_coverage': policy_coverage,
        'setup_score': max(0, setup_score)
    }

def check_leave_metrics():
    """Calculate and check leave usage metrics"""
    current_year = timezone.now().year

    leave_usage_by_type = {}
    for leave_type in LeaveType.objects.all():
        balances = UserLeaveBalance.objects.filter(
            leave_type=leave_type,
            year=current_year
        )

        total_allocated = balances.aggregate(Sum('allocated'))['allocated__sum'] or 0
        total_used = balances.aggregate(Sum('used'))['used__sum'] or 0

        if total_allocated > 0:
            utilization_rate = (total_used / total_allocated) * 100
        else:
            utilization_rate = 0

        leave_usage_by_type[leave_type.name] = {
            'allocated': total_allocated,
            'used': total_used,
            'utilization_rate': round(utilization_rate, 2)
        }

    # Leave request metrics
    total_requests = LeaveRequest.objects.filter(
        start_date__year=current_year
    ).count()

    approval_rate = 0
    rejection_rate = 0

    if total_requests > 0:
        approved = LeaveRequest.objects.filter(
            start_date__year=current_year,
            status='Approved'
        ).count()

        rejected = LeaveRequest.objects.filter(
            start_date__year=current_year,
            status='Rejected'
        ).count()

        approval_rate = (approved / total_requests) * 100
        rejection_rate = (rejected / total_requests) * 100

    return {
        'leave_usage_by_type': leave_usage_by_type,
        'request_metrics': {
            'total_requests': total_requests,
            'approval_rate': round(approval_rate, 2),
            'rejection_rate': round(rejection_rate, 2),
        }
    }

def check_performance():
    """Run simple performance checks on key operations"""
    performance_metrics = {}

    # Measure leave request retrieval
    start_time = datetime.datetime.now()
    LeaveRequest.objects.all()[:100]
    end_time = datetime.datetime.now()
    performance_metrics['leave_request_query'] = (end_time - start_time).total_seconds() * 1000

    # Measure balance calculation
    start_time = datetime.datetime.now()
    for balance in UserLeaveBalance.objects.all()[:20]:
        _ = balance.allocated - balance.used
    end_time = datetime.datetime.now()
    performance_metrics['balance_calculation'] = (end_time - start_time).total_seconds() * 1000

    # Measure leave type retrieval
    start_time = datetime.datetime.now()
    list(LeaveType.objects.all())
    end_time = datetime.datetime.now()
    performance_metrics['leave_type_retrieval'] = (end_time - start_time).total_seconds() * 1000

    # Calculate performance score
    performance_score = 100

    for metric, value in performance_metrics.items():
        if value > 500:  # Extremely slow
            performance_score -= 30
        elif value > 200:  # Very slow
            performance_score -= 20
        elif value > 100:  # Slow
            performance_score -= 10
        elif value > 50:  # Moderate
            performance_score -= 5

    performance_metrics['performance_score'] = max(0, performance_score)

    return performance_metrics

def generate_health_report():
    """Generate a comprehensive health report for the Leave Management System"""
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'database_stats': get_database_stats(),
        'data_integrity': check_data_integrity(),
        'user_setup': check_user_setup(),
        'leave_metrics': check_leave_metrics(),
        'performance': check_performance(),
    }

    # Calculate overall health score
    integrity_score = report['data_integrity']['integrity_score']
    setup_score = report['user_setup']['setup_score']
    performance_score = report['performance']['performance_score']

    overall_score = (integrity_score * 0.4) + (setup_score * 0.3) + (performance_score * 0.3)

    report['overall_health'] = {
        'score': round(overall_score, 2),
        'rating': get_health_rating(overall_score),
        'issues_summary': summarize_issues(report)
    }

    return report

def get_health_rating(score):
    """Convert health score to a descriptive rating"""
    if score >= 90:
        return "Excellent"
    elif score >= 80:
        return "Good"
    elif score >= 70:
        return "Satisfactory"
    elif score >= 60:
        return "Fair"
    else:
        return "Poor"

def summarize_issues(report):
    """Summarize key issues identified in the health report"""
    issues = []

    # Data integrity issues
    if report['data_integrity']['issues_count'] > 0:
        issues.extend(report['data_integrity']['issues'])

    # User setup issues
    if report['user_setup']['users_without_groups'] > 0:
        issues.append(f"Found {report['user_setup']['users_without_groups']} users without group assignments")

    for group, has_policy in report['user_setup']['policy_coverage'].items():
        if not has_policy:
            issues.append(f"Group '{group}' has no active leave policy")

    # Performance issues
    for metric, value in report['performance'].items():
        if metric != 'performance_score' and value > 200:
            issues.append(f"Performance issue: {metric} took {value:.2f}ms")

    return issues

def save_report_to_file(report, format='json'):
    """Save the health report to a file"""
    filename = f"leave_management_health_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if format == 'json':
        with open(f"{filename}.json", 'w') as f:
            json.dump(report, f, indent=2, cls=DecimalEncoder)
        logger.info(f"Report saved as {filename}.json")

    elif format == 'text':
        with open(f"{filename}.txt", 'w') as f:
            f.write("LEAVE MANAGEMENT SYSTEM HEALTH REPORT\n")
            f.write("="*80 + "\n\n")

            f.write(f"Generated: {report['timestamp']}\n\n")

            f.write("OVERALL HEALTH\n")
            f.write("-"*80 + "\n")
            f.write(f"Score: {report['overall_health']['score']}/100\n")
            f.write(f"Rating: {report['overall_health']['rating']}\n\n")

            if report['overall_health']['issues_summary']:
                f.write("CRITICAL ISSUES\n")
                for i, issue in enumerate(report['overall_health']['issues_summary'], 1):
                    f.write(f"{i}. {issue}\n")
                f.write("\n")

            f.write("DATABASE STATISTICS\n")
            f.write("-"*80 + "\n")
            stats = report['database_stats']
            f.write(f"Users: {stats['users']['total']} (Active: {stats['users']['active']})\n")
            f.write(f"Leave Types: {stats['leave_types']['total']} (Active: {stats['leave_types']['active']})\n")
            f.write(f"Leave Policies: {stats['leave_policies']['total']} (Active: {stats['leave_policies']['active']})\n")
            f.write(f"Leave Requests: {stats['leave_requests']['total']}\n")
            f.write(f"  - Pending: {stats['leave_requests']['pending']}\n")
            f.write(f"  - Approved: {stats['leave_requests']['approved']}\n")
            f.write(f"  - Rejected: {stats['leave_requests']['rejected']}\n")
            f.write(f"  - Cancelled: {stats['leave_requests']['cancelled']}\n\n")

            f.write("DATA INTEGRITY\n")
            f.write("-"*80 + "\n")
            f.write(f"Integrity Score: {report['data_integrity']['integrity_score']}/100\n")
            if report['data_integrity']['issues']:
                f.write("Issues:\n")
                for issue in report['data_integrity']['issues']:
                    f.write(f"- {issue}\n")
            else:
                f.write("No data integrity issues found.\n")
            f.write("\n")

            f.write("USER SETUP\n")
            f.write("-"*80 + "\n")
            f.write(f"Setup Score: {report['user_setup']['setup_score']}/100\n")
            f.write("Group Counts:\n")
            for group, count in report['user_setup']['group_counts'].items():
                f.write(f"- {group.capitalize()}: {count}\n")
            f.write(f"Users without groups: {report['user_setup']['users_without_groups']}\n\n")

            f.write("LEAVE METRICS\n")
            f.write("-"*80 + "\n")
            f.write("Leave Usage by Type:\n")
            for leave_type, metrics in report['leave_metrics']['leave_usage_by_type'].items():
                f.write(f"- {leave_type}: {metrics['used']} used of {metrics['allocated']} allocated ({metrics['utilization_rate']}%)\n")
            f.write("\n")
            f.write(f"Total Requests: {report['leave_metrics']['request_metrics']['total_requests']}\n")
            f.write(f"Approval Rate: {report['leave_metrics']['request_metrics']['approval_rate']}%\n")
            f.write(f"Rejection Rate: {report['leave_metrics']['request_metrics']['rejection_rate']}%\n\n")

            f.write("PERFORMANCE METRICS\n")
            f.write("-"*80 + "\n")
            f.write(f"Performance Score: {report['performance']['performance_score']}/100\n")
            for metric, value in report['performance'].items():
                if metric != 'performance_score':
                    f.write(f"- {metric}: {value:.2f}ms\n")

        logger.info(f"Report saved as {filename}.txt")

    return filename

def print_report_summary(report):
    """Print a summary of the health report to the console"""
    print("\n")
    print("="*80)
    print(" LEAVE MANAGEMENT SYSTEM HEALTH REPORT ")
    print("="*80)

    print(f"\nOverall Health Score: {report['overall_health']['score']}/100 ({report['overall_health']['rating']})")

    print("\nKey Metrics:")
    print(f"- Data Integrity: {report['data_integrity']['integrity_score']}/100")
    print(f"- User Setup: {report['user_setup']['setup_score']}/100")
    print(f"- Performance: {report['performance']['performance_score']}/100")

    print("\nDatabase Stats:")
    stats = report['database_stats']
    print(f"- Users: {stats['users']['total']} (Active: {stats['users']['active']})")
    print(f"- Leave Types: {stats['leave_types']['total']}")
    print(f"- Leave Requests: {stats['leave_requests']['total']} (Pending: {stats['leave_requests']['pending']})")

    if report['overall_health']['issues_summary']:
        print("\nCritical Issues:")
        for i, issue in enumerate(report['overall_health']['issues_summary'][:5], 1):
            print(f"  {i}. {issue}")

        if len(report['overall_health']['issues_summary']) > 5:
            print(f"  ... and {len(report['overall_health']['issues_summary']) - 5} more issues")

    print("\nRecommendations:")
    if report['overall_health']['score'] < 70:
        print("- Address data integrity issues as a priority")
        print("- Review user group assignments and leave policies")
    elif report['overall_health']['score'] < 90:
        print("- Continue regular health checks")
        print("- Optimize database queries for better performance")
    else:
        print("- System is in excellent health")
        print("- Continue regular monitoring")

    print("\n" + "="*80)
    print(f" Report generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ")
    print("="*80 + "\n")

def main():
    """Main function to generate health report"""
    parser = argparse.ArgumentParser(description='Generate health report for Leave Management System')
    parser.add_argument('--format', choices=['json', 'text', 'both'], default='both',
                      help='Output format for the report (default: both)')
    parser.add_argument('--quiet', action='store_true',
                      help='Do not print summary to console')

    args = parser.parse_args()

    try:
        logger.info("Generating Leave Management System health report...")
        report = generate_health_report()

        if args.format in ['json', 'both']:
            save_report_to_file(report, format='json')

        if args.format in ['text', 'both']:
            save_report_to_file(report, format='text')

        if not args.quiet:
            print_report_summary(report)

        logger.info("Health report generation completed successfully.")
        return 0

    except Exception as e:
        logger.error(f"Error generating health report: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
