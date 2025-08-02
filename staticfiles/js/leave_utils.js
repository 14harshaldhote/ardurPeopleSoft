/**
 * Leave Management Utility Functions
 *
 * This module provides helper functions for leave request management,
 * date calculations, validations, and AJAX operations.
 */

/**
 * Calculate working days between two dates
 * Excludes weekends and optionally holidays
 *
 * @param {Date|string} startDate - Leave start date
 * @param {Date|string} endDate - Leave end date
 * @param {boolean} includeWeekends - Whether to count weekends
 * @param {Array} holidays - Array of holiday dates to exclude
 * @return {number} Number of working days
 */
const calculateLeaveDays = (startDate, endDate, includeWeekends = false, holidays = []) => {
    // Convert string dates to Date objects if needed
    const start = startDate instanceof Date ? startDate : new Date(startDate);
    const end = endDate instanceof Date ? endDate : new Date(endDate);

    // Validate dates
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        console.error('Invalid date provided');
        return 0;
    }

    // Ensure start date is before end date
    if (start > end) {
        console.error('Start date is after end date');
        return 0;
    }

    let count = 0;
    const currentDate = new Date(start);

    // Convert holidays to Date objects for comparison
    const holidayDates = holidays.map(h => h instanceof Date ? h : new Date(h));

    // Loop through each day
    while (currentDate <= end) {
        const dayOfWeek = currentDate.getDay();
        const isWeekend = (dayOfWeek === 0 || dayOfWeek === 6); // 0 = Sunday, 6 = Saturday

        // Check if we should count this day
        if ((includeWeekends || !isWeekend) &&
            !holidayDates.some(h => h.toDateString() === currentDate.toDateString())) {
            count++;
        }

        // Move to next day
        currentDate.setDate(currentDate.getDate() + 1);
    }

    return count;
};

/**
 * Check if user has sufficient leave balance
 *
 * @param {string} leaveType - The type of leave
 * @param {number} days - Number of days requested
 * @param {Object} balanceData - User's current leave balances
 * @return {boolean} True if balance is sufficient
 */
const validateLeaveBalance = (leaveType, days, balanceData) => {
    if (!balanceData || !balanceData[leaveType]) {
        console.error(`No balance data found for ${leaveType}`);
        return false;
    }

    const balance = parseFloat(balanceData[leaveType].balance);
    return balance >= days;
};

/**
 * Update leave request status via AJAX
 *
 * @param {number} leaveId - ID of the leave request
 * @param {string} status - New status (Approved, Rejected, etc)
 * @param {string} comment - Optional comment with the decision
 * @return {Promise} Promise resolving to response data
 */
const updateLeaveStatus = async (leaveId, status, comment = '') => {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    try {
        const response = await fetch('/leave/api/update-status/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                leave_id: leaveId,
                status: status,
                comment: comment
            })
        });

        if (!response.ok) {
            throw new Error(`Error updating leave status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Failed to update leave status:', error);
        throw error;
    }
};

/**
 * Format date for display
 *
 * @param {Date|string} date - Date to format
 * @param {string} format - Optional format (short, medium, long)
 * @return {string} Formatted date
 */
const formatLeaveDate = (date, format = 'medium') => {
    const dateObj = date instanceof Date ? date : new Date(date);

    if (isNaN(dateObj.getTime())) {
        return 'Invalid date';
    }

    const options = {
        short: { month: 'short', day: 'numeric' },
        medium: { year: 'numeric', month: 'short', day: 'numeric' },
        long: { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }
    };

    return dateObj.toLocaleDateString(undefined, options[format] || options.medium);
};

/**
 * Fetch user's leave balances
 *
 * @param {number} userId - Optional user ID (defaults to current user)
 * @return {Promise} Promise resolving to balance data
 */
const fetchLeaveBalances = async (userId = null) => {
    let url = '/leave/api/balances/';
    if (userId) {
        url += `?user_id=${userId}`;
    }

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Error fetching leave balances: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch leave balances:', error);
        throw error;
    }
};

/**
 * Initialize leave request form with date validation
 *
 * @param {string} formId - ID of the leave request form
 * @param {Object} options - Configuration options
 */
const initLeaveRequestForm = (formId, options = {}) => {
    const form = document.getElementById(formId);
    if (!form) return;

    const startDateInput = form.querySelector('[name="start_date"]');
    const endDateInput = form.querySelector('[name="end_date"]');
    const leaveTypeSelect = form.querySelector('[name="leave_type"]');
    const daysDisplay = form.querySelector('#days_count');

    if (startDateInput && endDateInput) {
        // Update days count when dates change
        const updateDaysCount = () => {
            const startDate = startDateInput.value;
            const endDate = endDateInput.value;

            if (startDate && endDate) {
                const days = calculateLeaveDays(
                    startDate,
                    endDate,
                    options.includeWeekends || false,
                    options.holidays || []
                );

                if (daysDisplay) {
                    daysDisplay.textContent = days;
                }

                // Validate against balance if needed
                if (options.validateBalance && leaveTypeSelect) {
                    const leaveType = leaveTypeSelect.value;
                    fetchLeaveBalances().then(balances => {
                        const isValid = validateLeaveBalance(leaveType, days, balances);
                        if (!isValid) {
                            daysDisplay.classList.add('text-red-600');
                            daysDisplay.classList.add('font-bold');
                        } else {
                            daysDisplay.classList.remove('text-red-600');
                            daysDisplay.classList.remove('font-bold');
                        }
                    });
                }
            }
        };

        startDateInput.addEventListener('change', updateDaysCount);
        endDateInput.addEventListener('change', updateDaysCount);
        if (leaveTypeSelect) {
            leaveTypeSelect.addEventListener('change', updateDaysCount);
        }
    }

    // Form validation
    form.addEventListener('submit', (e) => {
        const startDate = new Date(startDateInput.value);
        const endDate = new Date(endDateInput.value);

        // Basic validation
        if (startDate > endDate) {
            e.preventDefault();
            alert('Start date cannot be after end date');
            return false;
        }

        if (options.validateBalance && leaveTypeSelect) {
            const leaveType = leaveTypeSelect.value;
            const days = calculateLeaveDays(
                startDate,
                endDate,
                options.includeWeekends || false,
                options.holidays || []
            );

            fetchLeaveBalances().then(balances => {
                const isValid = validateLeaveBalance(leaveType, days, balances);
                if (!isValid) {
                    e.preventDefault();
                    alert('Insufficient leave balance');
                    return false;
                }
            });
        }
    });
};

// Export functions for module use
if (typeof module !== 'undefined') {
    module.exports = {
        calculateLeaveDays,
        validateLeaveBalance,
        updateLeaveStatus,
        formatLeaveDate,
        fetchLeaveBalances,
        initLeaveRequestForm
    };
}
