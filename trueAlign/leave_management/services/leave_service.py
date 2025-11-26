"""
Comprehensive Leave Management Service Layer
Handles all business logic for leave operations
"""
from django.db import transaction
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.cache import cache
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
import logging

from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest, Attendance
)

# Import Django Notifications
try:
    from notifications.signals import notify
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False
    notify = None

# Import utilities
from ..utils import (
    can_approve_leave, get_potential_approvers, get_auto_approver,
    validate_approval_hierarchy, is_hr, is_admin
)
from ..audit import LeaveAuditLogger
from ..events import EventDispatcher, LeaveCreatedEvent, LeaveApprovedEvent, LeaveRejectedEvent
from ..rules import RuleEngine
from ..delivery import NotificationDelivery

logger = logging.getLogger(__name__)


class LeaveServiceError(Exception):
    """Custom exception for leave service errors"""
    pass


class LeaveService:
    """Main service class for all leave operations"""
    
    # Cache timeout in seconds (1 hour)
    CACHE_TIMEOUT = 3600
    
    @staticmethod
    def get_cached_leave_policies(user: User) -> Optional[LeavePolicy]:
        """Get user's leave policy with caching"""
        cache_key = f"leave_policy_{user.id}"
        policy = cache.get(cache_key)
        
        if policy is None:
            user_groups = user.groups.all()
            if user_groups:
                policy = LeavePolicy.objects.filter(
                    group__in=user_groups,
                    is_active=True,
                    is_deleted=False
                ).first()
                
                if policy:
                    cache.set(cache_key, policy, LeaveService.CACHE_TIMEOUT)
        
        return policy
    
    @staticmethod
    def get_cached_leave_allocations(policy: LeavePolicy) -> List[LeaveAllocation]:
        """Get leave allocations for a policy with caching"""
        cache_key = f"leave_allocations_{policy.id}"
        allocations = cache.get(cache_key)
        
        if allocations is None:
            allocations = list(LeaveAllocation.objects.filter(
                policy=policy,
                is_deleted=False
            ).select_related('leave_type'))
            
            cache.set(cache_key, allocations, LeaveService.CACHE_TIMEOUT)
        
        return allocations
    
    @staticmethod
    def clear_user_cache(user: User):
        """Clear cache for a specific user"""
        cache_keys = [
            f"leave_policy_{user.id}",
            f"leave_balance_{user.id}_{timezone.now().year}"
        ]
        cache.delete_many(cache_keys)

    @staticmethod
    def apply_leave(user: User, leave_data: Dict) -> Tuple[LeaveRequest, Dict]:
        """
        Apply for leave with comprehensive validation
        Returns: (LeaveRequest instance, validation_result)
        """
        try:
            with transaction.atomic():
                # Get the leave type object (handle both ID and object cases)
                leave_type_value = leave_data['leave_type']
                logger.debug(f"Processing leave_type_value: {leave_type_value} (type: {type(leave_type_value)})")
                
                if isinstance(leave_type_value, LeaveType):
                    leave_type = leave_type_value
                    logger.debug(f"Using LeaveType object: {leave_type.name}")
                elif isinstance(leave_type_value, (int, str)):
                    try:
                        leave_type = LeaveType.objects.get(id=int(leave_type_value))
                        logger.debug(f"Retrieved LeaveType by ID {leave_type_value}: {leave_type.name}")
                    except (LeaveType.DoesNotExist, ValueError):
                        logger.error(f"Invalid leave type ID: {leave_type_value}")
                        raise LeaveServiceError(f"Invalid leave type: {leave_type_value}")
                else:
                    logger.error(f"Invalid leave type format: {type(leave_type_value)}")
                    raise LeaveServiceError(f"Invalid leave type format: {type(leave_type_value)}")
                
                # Create leave request instance
                leave_request = LeaveRequest(
                    user=user,
                    leave_type=leave_type,
                    start_date=leave_data['start_date'],
                    end_date=leave_data['end_date'],
                    half_day=leave_data.get('half_day', False),
                    reason=leave_data['reason'],
                    is_retroactive=leave_data.get('is_retroactive', False)
                )

                # Handle documentation if provided
                if 'documentation' in leave_data:
                    leave_request.documentation = leave_data['documentation']

                # Calculate leave days
                leave_request.leave_days = leave_request.calculate_leave_days()
                
                # Ensure the leave_type relationship is properly loaded
                leave_request.leave_type = leave_type

                # Validate the request
                validation_result = LeaveService.validate_leave_request(leave_request)

                if not validation_result['is_valid']:
                    # Log failed application
                    LeaveAuditLogger.log_leave_application(user, leave_request, validation_result)
                    return leave_request, validation_result

                # Auto-assign approver if not specified
                if not leave_data.get('approver'):
                    auto_approver = get_auto_approver(user)
                    if auto_approver:
                        leave_request.approver = auto_approver

                # Save the leave request
                leave_request.save()

                # Log successful application
                success_result = {
                    'is_valid': True,
                    'errors': [],
                    'warnings': validation_result.get('warnings', []),
                    'can_auto_convert': False
                }
                LeaveAuditLogger.log_leave_application(user, leave_request, success_result)

                # Send notification via Event System
                try:
                    event = LeaveCreatedEvent(leave_request, user)
                    notifications = RuleEngine().process(event)
                    NotificationDelivery().send(notifications)
                except Exception as e:
                    logger.warning(f"Failed to dispatch leave created event: {str(e)}")

                logger.info(f"Leave request created successfully: ID {leave_request.id}")

                return leave_request, success_result

        except (ValidationError, ValueError, TypeError) as e:
            logger.error(f"Error applying leave for user {user.username}: {str(e)}", exc_info=True)
            raise LeaveServiceError(f"Failed to apply leave: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error applying leave for user {user.username}: {str(e)}", exc_info=True)
            raise LeaveServiceError("An unexpected error occurred while applying for leave")

    @staticmethod
    def validate_leave_request(leave_request: LeaveRequest) -> Dict:
        """
        Comprehensive validation of leave request
        Returns validation result with detailed messages
        """
        validation_errors = []

        try:
            # Basic date validation
            if leave_request.start_date > leave_request.end_date:
                validation_errors.append("End date must be after start date")

            # Check if leave type allows half day
            if leave_request.half_day and not leave_request.leave_type.can_be_half_day:
                validation_errors.append(f"{leave_request.leave_type.name} cannot be taken as half day")

            # Check for documentation requirement
            if (leave_request.leave_type.requires_documentation and
                not leave_request.documentation):
                validation_errors.append(f"{leave_request.leave_type.name} requires supporting documentation")

            # Check advance notice requirement
            if not leave_request.is_retroactive:
                advance_notice_error = LeaveService._validate_advance_notice(leave_request)
                if advance_notice_error:
                    validation_errors.append(advance_notice_error)

            # Check consecutive days limit
            consecutive_days_error = LeaveService._validate_consecutive_days(leave_request)
            if consecutive_days_error:
                validation_errors.append(consecutive_days_error)

            # Check for overlapping leaves
            overlapping_error = LeaveService._check_overlapping_leaves(leave_request)
            if overlapping_error:
                validation_errors.append(overlapping_error)

            # Check leave balance
            if leave_request.leave_type.is_paid:
                balance_error = LeaveService._validate_leave_balance(leave_request)
                if balance_error:
                    validation_errors.append(balance_error)

            # Check holiday/weekend conflicts
            holiday_weekend_warnings = LeaveService._check_holiday_weekend_conflicts(leave_request)

            return {
                'is_valid': len(validation_errors) == 0,
                'errors': validation_errors,
                'warnings': holiday_weekend_warnings,
                'can_auto_convert': LeaveService._can_auto_convert_to_lop(leave_request)
            }

        except (ValidationError, ValueError, AttributeError) as e:
            logger.error(f"Validation error for leave request: {str(e)}", exc_info=True)
            return {
                'is_valid': False,
                'errors': [f"Validation error: {str(e)}"],
                'warnings': [],
                'can_auto_convert': False
            }
        except Exception as e:
            logger.error(f"Unexpected error validating leave request: {str(e)}", exc_info=True)
            return {
                'is_valid': False,
                'errors': ["An unexpected validation error occurred"],
                'warnings': [],
                'can_auto_convert': False
            }

    @staticmethod
    def _validate_advance_notice(leave_request: LeaveRequest) -> Optional[str]:
        """Validate advance notice requirement"""
        try:
            policy = leave_request.get_user_policy()
            if policy:
                allocation = LeaveAllocation.objects.get(
                    policy=policy,
                    leave_type=leave_request.leave_type
                )
                if allocation.advance_notice_days > 0:
                    min_request_date = timezone.now().date() + timedelta(days=allocation.advance_notice_days)
                    if leave_request.start_date < min_request_date:
                        return f"{leave_request.leave_type.name} requires {allocation.advance_notice_days} days advance notice"
        except LeaveAllocation.DoesNotExist:
            pass
        return None

    @staticmethod
    def _validate_consecutive_days(leave_request: LeaveRequest) -> Optional[str]:
        """Validate consecutive days limit"""
        try:
            policy = leave_request.get_user_policy()
            if policy:
                allocation = LeaveAllocation.objects.get(
                    policy=policy,
                    leave_type=leave_request.leave_type
                )
                if allocation.max_consecutive_days > 0:
                    days_requested = (leave_request.end_date - leave_request.start_date).days + 1
                    if days_requested > allocation.max_consecutive_days:
                        return f"You can only take {allocation.max_consecutive_days} consecutive days of {leave_request.leave_type.name}"
        except LeaveAllocation.DoesNotExist:
            pass
        return None

    @staticmethod
    def _check_overlapping_leaves(leave_request: LeaveRequest) -> Optional[str]:
        """Check for overlapping approved leaves"""
        overlapping_leaves = LeaveRequest.objects.filter(
            user=leave_request.user,
            status='Approved',
            start_date__lte=leave_request.end_date,
            end_date__gte=leave_request.start_date
        )

        if leave_request.id:
            overlapping_leaves = overlapping_leaves.exclude(id=leave_request.id)

        if overlapping_leaves.exists():
            return "You already have approved leave during this period"
        return None

    @staticmethod
    def _validate_leave_balance(leave_request: LeaveRequest) -> Optional[str]:
        """Validate sufficient leave balance"""
        try:
            has_balance = leave_request.has_sufficient_balance()
            logger.debug(f"Balance validation for {leave_request.user.username}: {has_balance}")
            if not has_balance:
                return f"Insufficient {leave_request.leave_type.name} balance"
            return None
        except Exception as e:
            logger.error(f"Error in balance validation: {str(e)}")
            return f"Error checking {leave_request.leave_type.name} balance"

    @staticmethod
    def _check_holiday_weekend_conflicts(leave_request: LeaveRequest) -> List[str]:
        """Check if leave period includes holidays or weekends"""
        warnings = []
        current_date = leave_request.start_date

        while current_date <= leave_request.end_date:
            # Check for weekends
            if current_date.weekday() >= 5 and not leave_request.leave_type.count_weekends:
                warnings.append(f"Leave period includes weekend ({current_date})")

            # Check for holidays (if Holiday model exists)
            try:
                from trueAlign.models import Holiday
                # Check if Holiday model has is_active field, otherwise just check by date
                holiday_fields = [f.name for f in Holiday._meta.get_fields()]
                if 'is_active' in holiday_fields:
                    if Holiday.objects.filter(date=current_date, is_active=True).exists():
                        warnings.append(f"Leave period includes holiday ({current_date})")
                else:
                    if Holiday.objects.filter(date=current_date).exists():
                        warnings.append(f"Leave period includes holiday ({current_date})")
            except (ImportError, AttributeError):
                pass

            current_date += timedelta(days=1)

        return warnings

    @staticmethod
    def _can_auto_convert_to_lop(leave_request: LeaveRequest) -> bool:
        """Check if leave can be auto-converted to Loss of Pay"""
        try:
            LeaveType.objects.get(name='Loss of Pay', is_paid=False, is_active=True)
            return True
        except LeaveType.DoesNotExist:
            return False

    @staticmethod
    def _revert_leave_balance(leave_request: LeaveRequest):
        """Revert leave balance when cancelling an approved leave"""
        try:
            if leave_request.leave_type.is_paid and leave_request.leave_days > 0:
                balance = UserLeaveBalance.objects.get(
                    user=leave_request.user,
                    leave_type=leave_request.leave_type,
                    year=leave_request.start_date.year
                )
                balance.used -= leave_request.leave_days
                balance.save()
                logger.info(f"Reverted {leave_request.leave_days} days for user {leave_request.user.username}")
        except UserLeaveBalance.DoesNotExist:
            logger.warning(f"No balance record found to revert for leave request {leave_request.id}")
        except Exception as e:
            logger.error(f"Error reverting leave balance: {str(e)}")

    @staticmethod
    def approve_leave(leave_request: LeaveRequest, approver: User, comments: str = "") -> Dict:
        """
        Approve a leave request with validation
        """
        try:
            with transaction.atomic():
                # Validate approver can approve this leave
                if not can_approve_leave(approver, leave_request.user):
                    raise LeaveServiceError("You are not authorized to approve this leave request")

                # Check if already processed
                if leave_request.status != 'Pending':
                    raise LeaveServiceError(f"Leave request is already {leave_request.status}")

                # Update leave request
                leave_request.status = 'Approved'
                leave_request.approver = approver
                if comments:
                    leave_request.rejection_reason = comments  # Using same field for approval comments

                leave_request.save()

                # Send notification via Event System
                try:
                    event = LeaveApprovedEvent(leave_request, approver)
                    notifications = RuleEngine().process(event)
                    NotificationDelivery().send(notifications)
                except Exception as e:
                    logger.warning(f"Failed to dispatch leave approved event: {str(e)}")

                logger.info(f"Leave approved: ID={leave_request.id}, Approver={approver.username}")

                return {
                    'success': True,
                    'message': 'Leave request approved successfully',
                    'leave_request_id': leave_request.id
                }

        except (ValidationError, PermissionError) as e:
            logger.error(f"Permission/validation error approving leave {leave_request.id}: {str(e)}", exc_info=True)
            raise LeaveServiceError(f"Failed to approve leave: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error approving leave {leave_request.id}: {str(e)}", exc_info=True)
            raise LeaveServiceError("An unexpected error occurred while approving leave")

    @staticmethod
    def reject_leave(leave_request: LeaveRequest, approver: User, reason: str) -> Dict:
        """
        Reject a leave request
        """
        try:
            with transaction.atomic():
                # Validate approver can reject this leave
                if not can_approve_leave(approver, leave_request.user):
                    raise LeaveServiceError("You are not authorized to reject this leave request")

                # Check if already processed
                if leave_request.status != 'Pending':
                    raise LeaveServiceError(f"Leave request is already {leave_request.status}")

                # Update leave request
                leave_request.status = 'Rejected'
                leave_request.approver = approver
                leave_request.rejection_reason = reason

                leave_request.save()

                # Send notification via Event System
                try:
                    event = LeaveRejectedEvent(leave_request, approver, reason)
                    notifications = RuleEngine().process(event)
                    NotificationDelivery().send(notifications)
                except Exception as e:
                    logger.warning(f"Failed to dispatch leave rejected event: {str(e)}")

                logger.info(f"Leave rejected: ID={leave_request.id}, Approver={approver.username}")

                return {
                    'success': True,
                    'message': 'Leave request rejected',
                    'leave_request_id': leave_request.id
                }

        except (ValidationError, PermissionError) as e:
            logger.error(f"Permission/validation error rejecting leave {leave_request.id}: {str(e)}", exc_info=True)
            raise LeaveServiceError(f"Failed to reject leave: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error rejecting leave {leave_request.id}: {str(e)}", exc_info=True)
            raise LeaveServiceError("An unexpected error occurred while rejecting leave")

    @staticmethod
    def cancel_leave(leave_request: LeaveRequest, user: User, reason: str = "") -> Dict:
        """
        Cancel a leave request
        """
        try:
            with transaction.atomic():
                # Check if user can cancel this leave
                if leave_request.user.id != user.id and not (is_hr(user) or is_admin(user)):
                    raise LeaveServiceError("You can only cancel your own leave requests")

                # Check if can be cancelled
                if leave_request.status in ['Cancelled', 'Rejected']:
                    raise LeaveServiceError("Leave request is already cancelled or rejected")

                # Store previous status for balance reversal
                previous_status = leave_request.status

                # Update leave request
                leave_request.status = 'Cancelled'
                if reason:
                    leave_request.rejection_reason = f"Cancelled: {reason}"

                leave_request.save()

                # If it was approved, we need to revert the balance
                if previous_status == 'Approved':
                    LeaveService._revert_leave_balance(leave_request)
                
                leave_request.save()

                # Send notification to approver/HR if leave was approved
                if NOTIFICATIONS_AVAILABLE and leave_request.approver:
                    try:
                        notify.send(
                            sender=user,
                            recipient=leave_request.approver,
                            verb='cancelled an approved leave request',
                            action_object=leave_request,
                            description=f'{user.get_full_name()} has cancelled their {leave_request.status.lower()} leave request for {leave_request.leave_type.name} from {leave_request.start_date} to {leave_request.end_date}'
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send leave cancellation notification: {str(e)}")

                logger.info(f"Leave cancelled: ID={leave_request.id}, User={user.username}")

                return {
                    'success': True,
                    'message': 'Leave request cancelled successfully',
                    'leave_request_id': leave_request.id
                }

        except (ValidationError, PermissionError) as e:
            logger.error(f"Permission/validation error cancelling leave {leave_request.id}: {str(e)}", exc_info=True)
            raise LeaveServiceError(f"Failed to cancel leave: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error cancelling leave {leave_request.id}: {str(e)}", exc_info=True)
            raise LeaveServiceError("An unexpected error occurred while cancelling leave")

    @staticmethod
    def get_user_leave_balance(user: User, year: int = None) -> Dict:
        """
        Get comprehensive leave balance for a user
        """
        if not year:
            year = timezone.now().year

        try:
            balances = UserLeaveBalance.objects.filter(
                user=user,
                year=year
            ).select_related('leave_type')

            # If no balances exist, try to create them automatically
            if not balances.exists():
                try:
                    LeaveService.allocate_leaves_to_user(user, {}, year)
                    balances = UserLeaveBalance.objects.filter(
                        user=user,
                        year=year
                    ).select_related('leave_type')
                except Exception as e:
                    logger.warning(f"Could not auto-allocate leaves for user {user.username}: {str(e)}")

            balance_data = []
            for balance in balances:
                balance_data.append({
                    'leave_type': balance.leave_type.name,
                    'allocated': float(balance.allocated),
                    'used': float(balance.used),
                    'available': float(balance.available),
                    'carried_forward': float(balance.carried_forward),
                    'additional': float(balance.additional),
                    'is_paid': balance.leave_type.is_paid
                })

            return {
                'success': True,
                'year': year,
                'balances': balance_data,
                'total_allocated': sum(b['allocated'] for b in balance_data if b['is_paid']),
                'total_used': sum(b['used'] for b in balance_data if b['is_paid']),
                'total_available': sum(b['available'] for b in balance_data if b['is_paid'])
            }

        except Exception as e:
            logger.error(f"Error getting leave balance for user {user.username}: {str(e)}")
            raise LeaveServiceError(f"Failed to get leave balance: {str(e)}")

    @staticmethod
    def allocate_leaves_to_user(user: User, allocations: Dict, year: int = None) -> Dict:
        """
        Allocate leaves to a specific user based on their policy
        """
        if not year:
            year = timezone.now().year

        try:
            with transaction.atomic():
                # Get user's policy
                user_groups = user.groups.all()
                if not user_groups:
                    raise LeaveServiceError("User has no assigned groups/roles")

                policy = LeavePolicy.objects.filter(
                    group__in=user_groups,
                    is_active=True
                ).first()

                if not policy:
                    logger.warning(f"No active leave policy found for user {user.username}")
                    return {
                        'success': False,
                        'message': "No active leave policy found for user's groups",
                        'allocations': []
                    }

                # Get policy allocations
                policy_allocations = LeaveAllocation.objects.filter(policy=policy)

                created_balances = []
                for allocation in policy_allocations:
                    # Create or update user balance
                    balance, created = UserLeaveBalance.objects.get_or_create(
                        user=user,
                        leave_type=allocation.leave_type,
                        year=year,
                        defaults={
                            'allocated': allocation.annual_days,
                            'used': Decimal('0'),
                            'carried_forward': Decimal('0'),
                            'additional': Decimal('0'),
                            'is_deleted': False
                        }
                    )

                    if not created:
                        # Update allocation if it exists
                        balance.allocated = allocation.annual_days
                        balance.save()

                    created_balances.append({
                        'leave_type': allocation.leave_type.name,
                        'allocated': float(allocation.annual_days),
                        'created': created
                    })

                logger.info(f"Leave allocation completed for user {user.username}, year {year}")

                return {
                    'success': True,
                    'message': f'Leaves allocated for {year}',
                    'allocations': created_balances
                }

        except Exception as e:
            logger.error(f"Error allocating leaves to user {user.username}: {str(e)}")
            raise LeaveServiceError(f"Failed to allocate leaves: {str(e)}")

    @staticmethod
    def bulk_allocate_leaves(user_list: List[User], year: int = None) -> Dict:
        """
        Bulk allocate leaves to multiple users using optimized DB operations
        """
        if not year:
            year = timezone.now().year

        try:
            with transaction.atomic():
                # Pre-fetch policies for all users to avoid N+1
                users_with_groups = User.objects.filter(id__in=[u.id for u in user_list]).prefetch_related('groups')
                
                # Group users by policy to minimize policy lookups
                policy_map = {} # policy_id -> policy
                user_policy_map = {} # user_id -> policy
                
                for user in users_with_groups:
                    user_groups = user.groups.all()
                    if not user_groups:
                        continue
                        
                    # Find policy for user's group
                    # Optimization: Cache policies
                    policy = LeavePolicy.objects.filter(
                        group__in=user_groups,
                        is_active=True
                    ).first()
                    
                    if policy:
                        policy_map[policy.id] = policy
                        user_policy_map[user.id] = policy

                # Pre-fetch allocations for all involved policies
                allocations_map = {} # policy_id -> list of allocations
                if policy_map:
                    all_allocations = LeaveAllocation.objects.filter(
                        policy__in=policy_map.values(),
                        is_deleted=False
                    ).select_related('leave_type')
                    
                    for alloc in all_allocations:
                        if alloc.policy_id not in allocations_map:
                            allocations_map[alloc.policy_id] = []
                        allocations_map[alloc.policy_id].append(alloc)

                # Prepare bulk operations
                balances_to_create = []
                balances_to_update = []
                results = []
                
                # Fetch existing balances to decide create vs update
                existing_balances = UserLeaveBalance.objects.filter(
                    user__in=user_list,
                    year=year
                ).select_related('leave_type')
                
                existing_balance_map = {} # (user_id, leave_type_id) -> balance
                for b in existing_balances:
                    existing_balance_map[(b.user_id, b.leave_type_id)] = b

                for user in user_list:
                    policy = user_policy_map.get(user.id)
                    if not policy:
                        results.append({
                            'user': user.username,
                            'success': False,
                            'message': "No active leave policy found"
                        })
                        continue

                    allocations = allocations_map.get(policy.id, [])
                    user_success = True
                    
                    for allocation in allocations:
                        key = (user.id, allocation.leave_type.id)
                        if key in existing_balance_map:
                            # Update existing
                            balance = existing_balance_map[key]
                            if balance.allocated != allocation.annual_days:
                                balance.allocated = allocation.annual_days
                                balances_to_update.append(balance)
                        else:
                            # Create new
                            balances_to_create.append(UserLeaveBalance(
                                user=user,
                                leave_type=allocation.leave_type,
                                year=year,
                                allocated=allocation.annual_days,
                                used=Decimal('0'),
                                carried_forward=Decimal('0'),
                                additional=Decimal('0'),
                                is_deleted=False
                            ))
                    
                    results.append({
                        'user': user.username,
                        'success': True,
                        'message': f'Allocated {len(allocations)} leave types'
                    })

                # Execute bulk operations
                if balances_to_create:
                    UserLeaveBalance.objects.bulk_create(balances_to_create)
                
                if balances_to_update:
                    UserLeaveBalance.objects.bulk_update(balances_to_update, ['allocated'])

                successful_allocations = sum(1 for r in results if r['success'])
                logger.info(f"Bulk allocation optimized: {successful_allocations}/{len(user_list)} successful. Created: {len(balances_to_create)}, Updated: {len(balances_to_update)}")

                return {
                    'success': True,
                    'message': f'Bulk allocation completed: {successful_allocations}/{len(user_list)} successful',
                    'results': results,
                    'year': year
                }

        except Exception as e:
            logger.error(f"Error in bulk leave allocation: {str(e)}")
            raise LeaveServiceError(f"Bulk allocation failed: {str(e)}")

    @staticmethod
    def apply_comp_off(user: User, comp_off_data: Dict) -> Dict:
        """
        Apply for compensation off
        """
        try:
            with transaction.atomic():
                comp_off_request = CompOffRequest(
                    user=user,
                    worked_date=comp_off_data['worked_date'],
                    reason=comp_off_data['reason'],
                    hours_worked=comp_off_data['hours_worked']
                )

                # Auto-assign approver
                auto_approver = get_auto_approver(user)
                if auto_approver:
                    comp_off_request.approver = auto_approver

                comp_off_request.save()

                # Send notification to approver
                if NOTIFICATIONS_AVAILABLE and comp_off_request.approver:
                    try:
                        notify.send(
                            sender=user,
                            recipient=comp_off_request.approver,
                            verb='submitted a comp-off request',
                            action_object=comp_off_request,
                            description=f'{user.get_full_name()} has submitted a comp-off request for {comp_off_request.worked_date} ({comp_off_request.hours_worked} hours worked)'
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send comp-off application notification: {str(e)}")

                logger.info(f"Comp-off request created: ID={comp_off_request.id}, User={user.username}")

                return {
                    'success': True,
                    'message': 'Comp-off request submitted successfully',
                    'request_id': comp_off_request.id
                }

        except (ValidationError, ValueError) as e:
            logger.error(f"Validation error applying comp-off for user {user.username}: {str(e)}", exc_info=True)
            raise LeaveServiceError(f"Failed to apply comp-off: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error applying comp-off for user {user.username}: {str(e)}", exc_info=True)
            raise LeaveServiceError("An unexpected error occurred while applying for comp-off")

    @staticmethod
    def get_leave_summary(user: User, year: int = None) -> Dict:
        """
        Get comprehensive leave summary for dashboard
        """
        if not year:
            year = timezone.now().year

        try:
            # Get leave requests for the year
            leave_requests = LeaveRequest.objects.filter(
                user=user,
                start_date__year=year
            ).select_related('leave_type', 'approver')

            # Get leave balances
            balance_result = LeaveService.get_user_leave_balance(user, year)

            # Calculate statistics
            total_requests = leave_requests.count()
            approved_requests = leave_requests.filter(status='Approved').count()
            pending_requests = leave_requests.filter(status='Pending').count()
            rejected_requests = leave_requests.filter(status='Rejected').count()

            # Upcoming leaves
            upcoming_leaves = leave_requests.filter(
                status='Approved',
                start_date__gte=timezone.now().date()
            ).order_by('start_date')[:5]

            # Recent requests
            recent_requests = leave_requests.order_by('-created_at')[:10]

            return {
                'success': True,
                'year': year,
                'statistics': {
                    'total_requests': total_requests,
                    'approved_requests': approved_requests,
                    'pending_requests': pending_requests,
                    'rejected_requests': rejected_requests
                },
                'balances': balance_result['balances'] if balance_result['success'] else [],
                'upcoming_leaves': [
                    {
                        'id': leave.id,
                        'leave_type': leave.leave_type.name,
                        'start_date': leave.start_date,
                        'end_date': leave.end_date,
                        'days': float(leave.leave_days)
                    }
                    for leave in upcoming_leaves
                ],
                'recent_requests': [
                    {
                        'id': leave.id,
                        'leave_type': leave.leave_type.name,
                        'start_date': leave.start_date,
                        'end_date': leave.end_date,
                        'status': leave.status,
                        'days': float(leave.leave_days),
                        'created_at': leave.created_at
                    }
                    for leave in recent_requests
                ]
            }

        except Exception as e:
            logger.error(f"Error getting leave summary for user {user.username}: {str(e)}")
            raise LeaveServiceError(f"Failed to get leave summary: {str(e)}")

    @staticmethod
    def get_team_leave_calendar(manager: User, year: int = None, month: int = None) -> Dict:
        """
        Get team leave calendar for managers
        """
        if not year:
            year = timezone.now().year
        if not month:
            month = timezone.now().month

        try:
            # Get team members (employees if user is manager)
            from django.contrib.auth.models import Group

            # For now, assume all employees are team members
            # In a real system, you'd have a proper reporting structure
            employee_group = Group.objects.get(name='Employee')
            team_members = User.objects.filter(groups=employee_group, is_active=True)

            # Get approved leaves for the month
            approved_leaves = LeaveRequest.objects.filter(
                user__in=team_members,
                status='Approved',
                start_date__year=year,
                start_date__month=month
            ).select_related('user', 'leave_type')

            calendar_data = {}
            for leave in approved_leaves:
                date_key = leave.start_date.strftime('%Y-%m-%d')
                if date_key not in calendar_data:
                    calendar_data[date_key] = []

                calendar_data[date_key].append({
                    'user': leave.user.get_full_name() or leave.user.username,
                    'leave_type': leave.leave_type.name,
                    'is_half_day': leave.half_day,
                    'days': float(leave.leave_days)
                })

            return {
                'success': True,
                'year': year,
                'month': month,
                'calendar_data': calendar_data,
                'team_size': team_members.count()
            }

        except Exception as e:
            logger.error(f"Error getting team calendar: {str(e)}")
            raise LeaveServiceError(f"Failed to get team calendar: {str(e)}")
