"""
SLA Monitoring Management Command
Monitors SLA compliance and sends alerts for violations
"""

import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from trueAlign.models import Support
from trueAlign.support.sla_engine import sla_engine
from trueAlign.support.logging_system import ticket_logger


class Command(BaseCommand):
    help = 'Monitor SLA compliance and send alerts for violations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--send-warnings',
            action='store_true',
            help='Send SLA warning notifications'
        )
        parser.add_argument(
            '--escalate',
            action='store_true',
            help='Escalate tickets that require escalation'
        )
        parser.add_argument(
            '--report',
            action='store_true',
            help='Generate SLA compliance report'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    def handle(self, *args, **options):
        self.logger = logging.getLogger(__name__)
        self.verbose = options['verbose']

        self.stdout.write(
            self.style.SUCCESS(
                f"Starting SLA monitoring at {timezone.now()}"
            )
        )

        try:
            # Run complete SLA monitoring
            results = sla_engine.run_sla_monitoring()

            # Display results
            self._display_results(results)

            # Send warnings if requested
            if options['send_warnings']:
                self._send_warnings()

            # Escalate tickets if requested
            if options['escalate']:
                self._escalate_tickets()

            # Generate report if requested
            if options['report']:
                self._generate_report()

            self.stdout.write(
                self.style.SUCCESS(
                    "SLA monitoring completed successfully"
                )
            )

        except Exception as e:
            self.logger.error(f"SLA monitoring failed: {str(e)}")
            self.stdout.write(
                self.style.ERROR(
                    f"SLA monitoring failed: {str(e)}"
                )
            )

    def _display_results(self, results):
        """Display monitoring results"""
        self.stdout.write(
            self.style.WARNING(
                f"SLA Monitoring Results:"
            )
        )
        self.stdout.write(f"  Violations checked: {results['violations_checked']}")
        self.stdout.write(f"  Warnings sent: {results['warnings_sent']}")
        self.stdout.write(f"  Escalations processed: {results['escalations_processed']}")

        if results['errors']:
            self.stdout.write(
                self.style.ERROR(
                    f"  Errors: {len(results['errors'])}"
                )
            )
            if self.verbose:
                for error in results['errors']:
                    self.stdout.write(f"    {error}")

    def _send_warnings(self):
        """Send SLA warning notifications"""
        self.stdout.write("Sending SLA warnings...")

        try:
            warnings = sla_engine.send_sla_warnings()
            total_warnings = sum(warnings.values())

            self.stdout.write(
                self.style.SUCCESS(
                    f"Sent {total_warnings} SLA warnings"
                )
            )

            if self.verbose:
                self.stdout.write(f"  Response warnings: {warnings['response_warnings']}")
                self.stdout.write(f"  Resolution warnings: {warnings['resolution_warnings']}")
                self.stdout.write(f"  Escalation warnings: {warnings['escalation_warnings']}")

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f"Failed to send warnings: {str(e)}"
                )
            )

    def _escalate_tickets(self):
        """Escalate tickets that require escalation"""
        self.stdout.write("Processing ticket escalations...")

        try:
            violations = sla_engine.check_sla_violations()
            escalation_candidates = violations.get('escalation_candidates', [])

            escalated_count = 0
            for candidate in escalation_candidates:
                ticket = candidate['ticket']
                needed_level = candidate['needed_level']

                if sla_engine.escalate_ticket(ticket, needed_level):
                    escalated_count += 1
                    if self.verbose:
                        self.stdout.write(
                            f"  Escalated ticket {ticket.ticket_id} to level {needed_level}"
                        )

            self.stdout.write(
                self.style.SUCCESS(
                    f"Escalated {escalated_count} tickets"
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f"Failed to escalate tickets: {str(e)}"
                )
            )

    def _generate_report(self):
        """Generate SLA compliance report"""
        self.stdout.write("Generating SLA compliance report...")

        try:
            # Get SLA metrics for last 30 days
            metrics = sla_engine.get_sla_metrics(30)

            self.stdout.write(
                self.style.WARNING(
                    "SLA Compliance Report (Last 30 Days):"
                )
            )
            self.stdout.write(f"  Total tickets: {metrics['total_tickets']}")
            self.stdout.write(f"  SLA compliance rate: {metrics['sla_compliance_rate']:.2f}%")
            self.stdout.write(f"  Average resolution time: {metrics['average_resolution_time']:.2f} hours")

            # Priority breakdown
            self.stdout.write("\n  Priority Breakdown:")
            for priority, data in metrics['priority_breakdown'].items():
                self.stdout.write(
                    f"    {priority}: {data['total']} tickets, "
                    f"{data['compliance_rate']:.2f}% compliance"
                )

            # Get current violations
            violations = sla_engine.check_sla_violations()

            self.stdout.write(
                self.style.ERROR(
                    f"\n  Current Violations:"
                )
            )
            self.stdout.write(f"    Response violations: {len(violations['response_violations'])}")
            self.stdout.write(f"    Resolution violations: {len(violations['resolution_violations'])}")
            self.stdout.write(f"    Escalation candidates: {len(violations['escalation_candidates'])}")

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f"Failed to generate report: {str(e)}"
                )
            )
