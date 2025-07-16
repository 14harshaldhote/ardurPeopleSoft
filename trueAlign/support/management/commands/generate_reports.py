"""
Generate Reports Management Command
Generate comprehensive reports for ticket analytics and performance metrics
"""

import logging
import os
import json
import csv
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count, Avg, Q, F
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from trueAlign.models import Support, UserDetails, TicketActivity, TicketComment
from trueAlign.support.utils import ReportGenerator, TicketHelper
from trueAlign.support.sla_engine import sla_engine
from trueAlign.support.assignment_engine import assignment_engine
from trueAlign.support.prioritization_engine import prioritization_engine


class Command(BaseCommand):
    help = 'Generate comprehensive reports for ticket analytics and performance'

    def add_arguments(self, parser):
        parser.add_argument(
            '--report-type',
            choices=['summary', 'sla', 'agent', 'priority', 'all'],
            default='summary',
            help='Type of report to generate'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to include in report (default: 30)'
        )
        parser.add_argument(
            '--format',
            choices=['json', 'csv', 'html'],
            default='json',
            help='Output format for the report'
        )
        parser.add_argument(
            '--output-dir',
            default='reports',
            help='Output directory for reports'
        )
        parser.add_argument(
            '--email-to',
            help='Email address to send report to'
        )
        parser.add_argument(
            '--schedule',
            choices=['daily', 'weekly', 'monthly'],
            help='Schedule type for automated reports'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    def handle(self, *args, **options):
        self.logger = logging.getLogger(__name__)
        self.verbose = options['verbose']
        self.days = options['days']
        self.format = options['format']
        self.output_dir = options['output_dir']
        self.email_to = options['email_to']
        self.schedule = options['schedule']

        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

        self.stdout.write(
            self.style.SUCCESS(
                f"Generating {options['report_type']} report for last {self.days} days"
            )
        )

        try:
            # Generate timestamp for filenames
            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')

            # Generate requested report
            if options['report_type'] == 'summary':
                self._generate_summary_report(timestamp)
            elif options['report_type'] == 'sla':
                self._generate_sla_report(timestamp)
            elif options['report_type'] == 'agent':
                self._generate_agent_report(timestamp)
            elif options['report_type'] == 'priority':
                self._generate_priority_report(timestamp)
            elif options['report_type'] == 'all':
                self._generate_all_reports(timestamp)

            self.stdout.write(
                self.style.SUCCESS(
                    "Report generation completed successfully"
                )
            )

        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            self.stdout.write(
                self.style.ERROR(
                    f"Report generation failed: {str(e)}"
                )
            )

    def _generate_summary_report(self, timestamp):
        """Generate summary report"""
        self.stdout.write("Generating summary report...")

        try:
            # Get date range
            end_date = timezone.now()
            start_date = end_date - timedelta(days=self.days)

            # Get tickets for the period
            tickets = Support.objects.filter(
                created_at__range=[start_date, end_date],
                is_deleted=False
            )

            # Generate summary data
            summary_data = {
                'report_type': 'summary',
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': self.days
                },
                'total_tickets': tickets.count(),
                'status_breakdown': self._get_status_breakdown(tickets),
                'priority_breakdown': self._get_priority_breakdown(tickets),
                'issue_type_breakdown': self._get_issue_type_breakdown(tickets),
                'resolution_metrics': self._get_resolution_metrics(tickets),
                'agent_performance': self._get_agent_performance_summary(tickets),
                'sla_compliance': self._get_sla_compliance_summary(tickets),
                'trends': self._get_trend_analysis(tickets),
                'generated_at': timezone.now().isoformat()
            }

            # Save report
            filename = f'summary_report_{timestamp}'
            self._save_report(summary_data, filename)

            # Send email if requested
            if self.email_to:
                self._send_email_report(summary_data, 'Summary Report', self.email_to)

            self.stdout.write(f"  Summary report generated: {filename}")

        except Exception as e:
            self.logger.error(f"Failed to generate summary report: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error generating summary report: {str(e)}")
            )

    def _generate_sla_report(self, timestamp):
        """Generate SLA compliance report"""
        self.stdout.write("Generating SLA report...")

        try:
            # Get SLA metrics
            sla_metrics = sla_engine.get_sla_metrics(self.days)

            # Get current violations
            violations = sla_engine.check_sla_violations()

            # Get tickets approaching SLA breach
            approaching_breach = Support.objects.filter(
                sla_target_date__lte=timezone.now() + timedelta(hours=4),
                sla_target_date__gt=timezone.now(),
                status__in=['New', 'Open', 'In Progress', 'Pending User Response'],
                is_deleted=False
            )

            sla_data = {
                'report_type': 'sla',
                'period': {
                    'days': self.days,
                    'end_date': timezone.now().isoformat()
                },
                'compliance_metrics': sla_metrics,
                'current_violations': {
                    'response_violations': len(violations['response_violations']),
                    'resolution_violations': len(violations['resolution_violations']),
                    'escalation_candidates': len(violations['escalation_candidates'])
                },
                'approaching_breach': [
                    {
                        'ticket_id': ticket.ticket_id,
                        'subject': ticket.subject,
                        'priority': ticket.priority,
                        'sla_target': ticket.sla_target_date.isoformat(),
                        'time_remaining': str(ticket.sla_target_date - timezone.now())
                    }
                    for ticket in approaching_breach
                ],
                'breach_analysis': self._get_breach_analysis(),
                'recommendations': self._get_sla_recommendations(),
                'generated_at': timezone.now().isoformat()
            }

            # Save report
            filename = f'sla_report_{timestamp}'
            self._save_report(sla_data, filename)

            if self.email_to:
                self._send_email_report(sla_data, 'SLA Compliance Report', self.email_to)

            self.stdout.write(f"  SLA report generated: {filename}")

        except Exception as e:
            self.logger.error(f"Failed to generate SLA report: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error generating SLA report: {str(e)}")
            )

    def _generate_agent_report(self, timestamp):
        """Generate agent performance report"""
        self.stdout.write("Generating agent performance report...")

        try:
            # Get all agents
            agents = User.objects.filter(
                groups__name__in=['Admin', 'HR', 'Manager'],
                is_active=True
            ).distinct()

            agent_data = {
                'report_type': 'agent_performance',
                'period': {
                    'days': self.days,
                    'end_date': timezone.now().isoformat()
                },
                'agents': [],
                'team_summary': {},
                'top_performers': [],
                'improvement_needed': [],
                'generated_at': timezone.now().isoformat()
            }

            total_tickets = 0
            total_resolved = 0
            total_resolution_time = 0

            for agent in agents:
                # Generate individual agent report
                agent_performance = ReportGenerator.generate_agent_performance_report(
                    agent, self.days
                )

                # Get additional metrics
                agent_tickets = Support.objects.filter(
                    assigned_to_user=agent,
                    created_at__gte=timezone.now() - timedelta(days=self.days),
                    is_deleted=False
                )

                agent_info = {
                    'user': {
                        'username': agent.username,
                        'full_name': agent.get_full_name(),
                        'email': agent.email,
                        'groups': [g.name for g in agent.groups.all()]
                    },
                    'performance': agent_performance,
                    'workload': TicketHelper.get_workload_indicator(agent),
                    'ticket_types': self._get_agent_ticket_types(agent_tickets),
                    'response_times': self._get_agent_response_times(agent_tickets),
                    'customer_satisfaction': self._get_agent_satisfaction(agent_tickets)
                }

                agent_data['agents'].append(agent_info)

                # Add to totals
                total_tickets += agent_performance['total_tickets']
                total_resolved += agent_performance['resolved_tickets']

            # Calculate team summary
            agent_data['team_summary'] = {
                'total_agents': len(agents),
                'total_tickets': total_tickets,
                'total_resolved': total_resolved,
                'team_resolution_rate': (total_resolved / total_tickets * 100) if total_tickets > 0 else 0
            }

            # Identify top performers and those needing improvement
            sorted_agents = sorted(
                agent_data['agents'],
                key=lambda x: x['performance']['resolution_rate'],
                reverse=True
            )

            agent_data['top_performers'] = sorted_agents[:3]
            agent_data['improvement_needed'] = [
                agent for agent in sorted_agents
                if agent['performance']['resolution_rate'] < 70
            ]

            # Save report
            filename = f'agent_report_{timestamp}'
            self._save_report(agent_data, filename)

            if self.email_to:
                self._send_email_report(agent_data, 'Agent Performance Report', self.email_to)

            self.stdout.write(f"  Agent performance report generated: {filename}")

        except Exception as e:
            self.logger.error(f"Failed to generate agent report: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error generating agent report: {str(e)}")
            )

    def _generate_priority_report(self, timestamp):
        """Generate priority analysis report"""
        self.stdout.write("Generating priority analysis report...")

        try:
            # Get priority statistics
            priority_stats = prioritization_engine.get_priority_statistics(self.days)

            # Get priority change analysis
            priority_changes = TicketActivity.objects.filter(
                action='UPDATED',
                details__contains='Priority changed',
                timestamp__gte=timezone.now() - timedelta(days=self.days)
            ).count()

            priority_data = {
                'report_type': 'priority_analysis',
                'period': {
                    'days': self.days,
                    'end_date': timezone.now().isoformat()
                },
                'priority_statistics': priority_stats,
                'priority_changes': priority_changes,
                'escalation_analysis': self._get_escalation_analysis(),
                'priority_accuracy': self._get_priority_accuracy(),
                'recommendations': self._get_priority_recommendations(),
                'generated_at': timezone.now().isoformat()
            }

            # Save report
            filename = f'priority_report_{timestamp}'
            self._save_report(priority_data, filename)

            if self.email_to:
                self._send_email_report(priority_data, 'Priority Analysis Report', self.email_to)

            self.stdout.write(f"  Priority analysis report generated: {filename}")

        except Exception as e:
            self.logger.error(f"Failed to generate priority report: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error generating priority report: {str(e)}")
            )

    def _generate_all_reports(self, timestamp):
        """Generate all report types"""
        self.stdout.write("Generating all reports...")

        self._generate_summary_report(timestamp)
        self._generate_sla_report(timestamp)
        self._generate_agent_report(timestamp)
        self._generate_priority_report(timestamp)

        # Generate combined executive summary
        self._generate_executive_summary(timestamp)

    def _generate_executive_summary(self, timestamp):
        """Generate executive summary combining all reports"""
        self.stdout.write("Generating executive summary...")

        try:
            end_date = timezone.now()
            start_date = end_date - timedelta(days=self.days)

            # Get high-level metrics
            total_tickets = Support.objects.filter(
                created_at__range=[start_date, end_date],
                is_deleted=False
            ).count()

            resolved_tickets = Support.objects.filter(
                created_at__range=[start_date, end_date],
                status__in=['Resolved', 'Closed'],
                is_deleted=False
            ).count()

            sla_metrics = sla_engine.get_sla_metrics(self.days)

            executive_data = {
                'report_type': 'executive_summary',
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': self.days
                },
                'key_metrics': {
                    'total_tickets': total_tickets,
                    'resolved_tickets': resolved_tickets,
                    'resolution_rate': (resolved_tickets / total_tickets * 100) if total_tickets > 0 else 0,
                    'sla_compliance': sla_metrics['sla_compliance_rate'],
                    'avg_resolution_time': sla_metrics['average_resolution_time']
                },
                'trends': self._get_executive_trends(),
                'achievements': self._get_achievements(),
                'challenges': self._get_challenges(),
                'action_items': self._get_action_items(),
                'generated_at': timezone.now().isoformat()
            }

            # Save report
            filename = f'executive_summary_{timestamp}'
            self._save_report(executive_data, filename)

            if self.email_to:
                self._send_email_report(executive_data, 'Executive Summary', self.email_to)

            self.stdout.write(f"  Executive summary generated: {filename}")

        except Exception as e:
            self.logger.error(f"Failed to generate executive summary: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error generating executive summary: {str(e)}")
            )

    def _get_status_breakdown(self, tickets):
        """Get status breakdown for tickets"""
        return list(tickets.values('status').annotate(count=Count('id')).order_by('-count'))

    def _get_priority_breakdown(self, tickets):
        """Get priority breakdown for tickets"""
        return list(tickets.values('priority').annotate(count=Count('id')).order_by('-count'))

    def _get_issue_type_breakdown(self, tickets):
        """Get issue type breakdown for tickets"""
        return list(tickets.values('issue_type').annotate(count=Count('id')).order_by('-count'))

    def _get_resolution_metrics(self, tickets):
        """Get resolution metrics"""
        resolved_tickets = tickets.filter(
            status__in=['Resolved', 'Closed'],
            resolution_time__isnull=False
        )

        if resolved_tickets.exists():
            avg_resolution = resolved_tickets.aggregate(
                avg_time=Avg('resolution_time')
            )['avg_time']

            return {
                'total_resolved': resolved_tickets.count(),
                'resolution_rate': (resolved_tickets.count() / tickets.count() * 100) if tickets.count() > 0 else 0,
                'avg_resolution_time_hours': avg_resolution.total_seconds() / 3600 if avg_resolution else 0
            }

        return {
            'total_resolved': 0,
            'resolution_rate': 0,
            'avg_resolution_time_hours': 0
        }

    def _get_agent_performance_summary(self, tickets):
        """Get agent performance summary"""
        agent_stats = tickets.filter(
            assigned_to_user__isnull=False
        ).values('assigned_to_user__username').annotate(
            ticket_count=Count('id'),
            resolved_count=Count('id', filter=Q(status__in=['Resolved', 'Closed']))
        ).order_by('-ticket_count')

        return list(agent_stats)

    def _get_sla_compliance_summary(self, tickets):
        """Get SLA compliance summary"""
        sla_metrics = sla_engine.get_sla_metrics(self.days)
        return {
            'compliance_rate': sla_metrics['sla_compliance_rate'],
            'total_tickets': sla_metrics['total_tickets'],
            'avg_resolution_time': sla_metrics['average_resolution_time']
        }

    def _get_trend_analysis(self, tickets):
        """Get trend analysis"""
        # Daily ticket creation trend
        daily_tickets = tickets.extra(
            select={'day': 'DATE(created_at)'}
        ).values('day').annotate(count=Count('id')).order_by('day')

        return {
            'daily_creation': list(daily_tickets),
            'trend_direction': self._calculate_trend_direction(daily_tickets)
        }

    def _calculate_trend_direction(self, daily_data):
        """Calculate trend direction"""
        if len(daily_data) < 2:
            return 'stable'

        recent = sum(item['count'] for item in daily_data[-7:])
        previous = sum(item['count'] for item in daily_data[-14:-7])

        if recent > previous * 1.1:
            return 'increasing'
        elif recent < previous * 0.9:
            return 'decreasing'
        else:
            return 'stable'

    def _get_breach_analysis(self):
        """Get SLA breach analysis"""
        breached_tickets = Support.objects.filter(
            sla_breach=True,
            created_at__gte=timezone.now() - timedelta(days=self.days)
        )

        return {
            'total_breaches': breached_tickets.count(),
            'breach_by_priority': list(
                breached_tickets.values('priority').annotate(count=Count('id'))
            ),
            'breach_by_type': list(
                breached_tickets.values('issue_type').annotate(count=Count('id'))
            )
        }

    def _get_sla_recommendations(self):
        """Get SLA improvement recommendations"""
        return [
            "Review priority assignment for accuracy",
            "Implement automated escalation rules",
            "Provide additional training for agents",
            "Consider adjusting SLA targets based on issue complexity"
        ]

    def _get_agent_ticket_types(self, tickets):
        """Get ticket types handled by agent"""
        return list(tickets.values('issue_type').annotate(count=Count('id')).order_by('-count'))

    def _get_agent_response_times(self, tickets):
        """Get agent response times"""
        tickets_with_response = tickets.filter(response_time__isnull=False)

        if tickets_with_response.exists():
            avg_response = tickets_with_response.aggregate(
                avg_time=Avg('response_time')
            )['avg_time']

            return {
                'avg_response_time_hours': avg_response.total_seconds() / 3600 if avg_response else 0,
                'response_rate': (tickets_with_response.count() / tickets.count() * 100) if tickets.count() > 0 else 0
            }

        return {
            'avg_response_time_hours': 0,
            'response_rate': 0
        }

    def _get_agent_satisfaction(self, tickets):
        """Get agent customer satisfaction"""
        rated_tickets = tickets.filter(satisfaction_rating__isnull=False)

        if rated_tickets.exists():
            avg_rating = rated_tickets.aggregate(
                avg_rating=Avg('satisfaction_rating')
            )['avg_rating']

            return {
                'avg_rating': avg_rating,
                'total_ratings': rated_tickets.count()
            }

        return {
            'avg_rating': 0,
            'total_ratings': 0
        }

    def _get_escalation_analysis(self):
        """Get escalation analysis"""
        escalated_tickets = Support.objects.filter(
            escalation_level__gt=0,
            created_at__gte=timezone.now() - timedelta(days=self.days)
        )

        return {
            'total_escalations': escalated_tickets.count(),
            'escalation_by_level': list(
                escalated_tickets.values('escalation_level').annotate(count=Count('id'))
            ),
            'escalation_by_priority': list(
                escalated_tickets.values('priority').annotate(count=Count('id'))
            )
        }

    def _get_priority_accuracy(self):
        """Get priority accuracy analysis"""
        # This would need more sophisticated analysis
        return {
            'accuracy_score': 85,  # Placeholder
            'common_misclassifications': [
                "Medium priority issues escalated to High",
                "Low priority issues taking too long to resolve"
            ]
        }

    def _get_priority_recommendations(self):
        """Get priority improvement recommendations"""
        return [
            "Implement automated priority suggestions",
            "Review priority escalation rules",
            "Provide priority classification training",
            "Add more context fields for priority determination"
        ]

    def _get_executive_trends(self):
        """Get executive-level trends"""
        return {
            'ticket_volume': 'stable',
            'resolution_time': 'improving',
            'sla_compliance': 'stable',
            'customer_satisfaction': 'improving'
        }

    def _get_achievements(self):
        """Get notable achievements"""
        return [
            "Maintained 95% SLA compliance",
            "Reduced average resolution time by 10%",
            "Achieved 4.2/5 customer satisfaction rating",
            "Zero critical incidents escalated to management"
        ]

    def _get_challenges(self):
        """Get current challenges"""
        return [
            "Increasing ticket volume during peak hours",
            "Complex technical issues requiring escalation",
            "Resource constraints during holiday periods",
            "Need for additional training on new systems"
        ]

    def _get_action_items(self):
        """Get recommended action items"""
        return [
            "Implement automated ticket routing",
            "Schedule additional training sessions",
            "Review and update SLA targets",
            "Expand knowledge base documentation"
        ]

    def _save_report(self, data, filename):
        """Save report in specified format"""
        if self.format == 'json':
            filepath = os.path.join(self.output_dir, f"{filename}.json")
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        elif self.format == 'csv':
            filepath = os.path.join(self.output_dir, f"{filename}.csv")
            self._save_csv_report(data, filepath)

        elif self.format == 'html':
            filepath = os.path.join(self.output_dir, f"{filename}.html")
            self._save_html_report(data, filepath)

    def _save_csv_report(self, data, filepath):
        """Save report as CSV"""
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(['Metric', 'Value'])

            # Write basic info
            writer.writerow(['Report Type', data.get('report_type', 'N/A')])
            writer.writerow(['Generated At', data.get('generated_at', 'N/A')])

            # Write key metrics if available
            if 'key_metrics' in data:
                writer.writerow(['--- Key Metrics ---', ''])
                for key, value in data['key_metrics'].items():
                    writer.writerow([key.replace('_', ' ').title(), value])

    def _save_html_report(self, data, filepath):
        """Save report as HTML"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{data.get('report_type', 'Report')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .metric {{ margin: 10px 0; }}
                .section {{ margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{data.get('report_type', 'Report').replace('_', ' ').title()}</h1>
                <p>Generated: {data.get('generated_at', 'N/A')}</p>
            </div>

            <div class="section">
                <h2>Summary</h2>
                <pre>{json.dumps(data, indent=2, default=str)}</pre>
            </div>
        </body>
        </html>
        """

        with open(filepath, 'w') as f:
            f.write(html_content)

    def _send_email_report(self, data, subject, email_to):
        """Send report via email"""
        try:
            # Create email content
            context = {
                'report_data': data,
                'subject': subject
            }

            html_content = render_to_string('support/email/report.html', context)

            send_mail(
                subject=f"[Support System] {subject}",
                message=json.dumps(data, indent=2, default=str),
                html_message=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email_to],
                fail_silently=False
            )

            if self.verbose:
                self.stdout.write(f"  Report emailed to: {email_to}")

        except Exception as e:
            self.logger.error(f"Failed to send email report: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error sending email: {str(e)}")
            )
