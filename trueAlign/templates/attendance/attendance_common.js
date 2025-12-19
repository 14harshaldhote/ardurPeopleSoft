/**
 * Attendance Common JavaScript Utilities
 * Phase 2-4 Infrastructure Integration
 * 
 * Provides standardized API calls, error handling, and utilities
 * for all attendance templates.
 */

// ============================================
// API CALL WRAPPER
// ============================================

/**
 * Standard API call wrapper with version support
 * @param {string} endpoint - API endpoint (e.g., '/dashboard/')
 * @param {object} options - Fetch options
 * @returns {Promise} - Promise with response data
 */
async function callAttendanceAPI(endpoint, options = {}) {
    const url = `/api/v1/attendance${endpoint}`;

    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'X-API-Version': '1.0',
            'Accept': 'application/json',
            ...options.headers
        }
    };

    try {
        const response = await fetch(url, { ...defaultOptions, ...options });
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new APIError(data.message || 'Request failed', data);
        }

        return data.data;
    } catch (error) {
        if (error instanceof APIError) {
            throw error;
        }
        throw new APIError(error.message || 'Network error', null);
    }
}

/**
 * Custom API Error class
 */
class APIError extends Error {
    constructor(message, responseData) {
        super(message);
        this.name = 'APIError';
        this.responseData = responseData;
        this.fieldErrors = responseData?.field_errors || {};
    }
}

// ============================================
// NOTIFICATION SYSTEM
// ============================================

/**
 * Show notification to user
 * @param {string} message - Message to display
 * @param {string} type - Type: 'success', 'error', 'warning', 'info'
 * @param {number} duration - Duration in ms (default: 5000)
 */
function showNotification(message, type = 'info', duration = 5000) {
    // Remove existing notifications
    const existing = document.getElementById('attendance-notification');
    if (existing) {
        existing.remove();
    }

    const colors = {
        success: 'bg-green-100 border-green-500 text-green-800',
        error: 'bg-red-100 border-red-500 text-red-800',
        warning: 'bg-yellow-100 border-yellow-500 text-yellow-800',
        info: 'bg-blue-100 border-blue-500 text-blue-800'
    };

    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠',
        info: 'ℹ'
    };

    const notification = document.createElement('div');
    notification.id = 'attendance-notification';
    notification.className = `fixed top-4 right-4 z-50 p-4 border-l-4 rounded shadow-lg ${colors[type] || colors.info}`;
    notification.innerHTML = `
        <div class="flex items-center gap-3">
            <span class="text-xl font-bold">${icons[type] || icons.info}</span>
            <span class="flex-1">${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="text-xl hover:opacity-70">&times;</button>
        </div>
    `;

    document.body.appendChild(notification);

    if (duration > 0) {
        setTimeout(() => notification.remove(), duration);
    }
}

/**
 * Display field-specific validation errors
 * @param {object} fieldErrors - Object with field names as keys
 */
function showFieldErrors(fieldErrors) {
    // Clear existing errors
    document.querySelectorAll('.field-error').forEach(el => el.remove());

    Object.entries(fieldErrors).forEach(([field, errors]) => {
        const fieldElement = document.querySelector(`[name="${field}"]`);
        if (fieldElement) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'field-error text-red-600 text-sm mt-1';
            errorDiv.textContent = Array.isArray(errors) ? errors.join(', ') : errors;
            fieldElement.parentElement.appendChild(errorDiv);
            fieldElement.classList.add('border-red-500');
        }
    });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Get CSRF token from cookie
 */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Show loading state on button
 * @param {HTMLElement} button - Button element
 * @param {boolean} loading - Loading state
 */
function setButtonLoading(button, loading) {
    if (loading) {
        button.dataset.originalText = button.innerHTML;
        button.disabled = true;
        button.innerHTML = `
            <svg class="animate-spin inline h-4 w-4 mr-2" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Loading...
        `;
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalText || button.innerHTML;
    }
}

/**
 * Format date for display
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date
 */
function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-IN', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

/**
 * Format time for display
 * @param {string} timeString - ISO time string
 * @returns {string} - Formatted time
 */
function formatTime(timeString) {
    if (!timeString) return '-';
    const date = new Date(timeString);
    return date.toLocaleTimeString('en-IN', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// ============================================
// EXPORT FUNCTIONS
// ============================================

/**
 * Handle CSV export with progress tracking
 * @param {object} filters - Export filters
 */
async function exportCSV(filters = {}) {
    const button = event?.target;
    if (button) setButtonLoading(button, true);

    try {
        const data = await callAttendanceAPI('/export/csv/', {
            method: 'POST',
            body: JSON.stringify(filters),
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        });

        if (data.job_id) {
            // Async export with progress tracking
            showNotification('Export started. You will be notified when ready.', 'info');
            pollExportStatus(data.job_id);
        } else if (data.download_url) {
            // Direct download
            window.location.href = data.download_url;
            showNotification('Export successful!', 'success');
        }
    } catch (error) {
        showNotification(error.message, 'error');
    } finally {
        if (button) setButtonLoading(button, false);
    }
}

/**
 * Poll export job status
 * @param {string} jobId - Export job ID
 */
function pollExportStatus(jobId) {
    let attempts = 0;
    const maxAttempts = 60; // 2 minutes max

    const interval = setInterval(async () => {
        attempts++;

        if (attempts > maxAttempts) {
            clearInterval(interval);
            showNotification('Export taking longer than expected. Please check back later.', 'warning');
            return;
        }

        try {
            const data = await callAttendanceAPI(`/export/${jobId}/status/`);

            if (data.status === 'completed') {
                clearInterval(interval);
                window.location.href = data.download_url;
                showNotification('Export ready! Downloading...', 'success');
            } else if (data.status === 'failed') {
                clearInterval(interval);
                showNotification('Export failed: ' + (data.error_message || 'Unknown error'), 'error');
            } else {
                // Update progress if UI element exists
                const progressEl = document.getElementById('export-progress');
                if (progressEl && data.progress) {
                    progressEl.style.width = `${data.progress}%`;
                    progressEl.textContent = `${data.progress}%`;
                }
            }
        } catch (error) {
            clearInterval(interval);
            showNotification('Failed to check export status', 'error');
        }
    }, 2000);
}

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', function () {
    console.log('Attendance Common JS loaded - Phase 2-4 infrastructure');

    // Add CSRF token to all AJAX requests
    const csrfToken = getCookie('csrftoken');
    if (csrfToken) {
        // For jQuery if available
        if (window.jQuery) {
            $.ajaxSetup({
                headers: { 'X-CSRFToken': csrfToken }
            });
        }
    }

    // Clear field errors on input
    document.querySelectorAll('input, select, textarea').forEach(element => {
        element.addEventListener('input', function () {
            this.classList.remove('border-red-500');
            const error = this.parentElement.querySelector('.field-error');
            if (error) error.remove();
        });
    });
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        callAttendanceAPI,
        showNotification,
        showFieldErrors,
        getCookie,
        setButtonLoading,
        formatDate,
        formatTime,
        exportCSV
    };
}
