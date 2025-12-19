/**
 * Attendance Common Utilities
 * Shared utilities for attendance module
 */

// Cookie utility
function getCookie(name) {
    const cookies = document.cookie.split(';').map(c => c.trim());
    for (const c of cookies) {
        if (c.startsWith(name + '=')) {
            return decodeURIComponent(c.split('=')[1]);
        }
    }
    return null;
}

// Format time utilities
function formatTime(timeString) {
    if (!timeString) return '--:-- --';
    try {
        const date = new Date(timeString);
        return date.toLocaleTimeString('en-US', {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    } catch (e) {
        return timeString;
    }
}

function formatDate(dateString) {
    if (!dateString) return '';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    } catch (e) {
        return dateString;
    }
}

function formatDuration(minutes) {
    if (!minutes || minutes <= 0) return '0h 0m';
    const hours = Math.floor(minutes / 60);
    const mins = Math.round(minutes % 60);
    if (hours > 0) {
        return `${hours}h ${mins}m`;
    }
    return `${mins}m`;
}

// Status badge utilities
function getStatusClass(status) {
    const statusClasses = {
        'Present': 'bg-green-100 text-green-800 border-green-200',
        'Present & Late': 'bg-yellow-100 text-yellow-800 border-yellow-200',
        'Absent': 'bg-red-100 text-red-800 border-red-200',
        'On Leave': 'bg-purple-100 text-purple-800 border-purple-200',
        'Holiday': 'bg-blue-100 text-blue-800 border-blue-200',
        'Weekend': 'bg-gray-100 text-gray-800 border-gray-200',
        'Not Marked': 'bg-gray-100 text-gray-500 border-gray-200'
    };
    return statusClasses[status] || 'bg-gray-100 text-gray-600 border-gray-200';
}

function getStatusIcon(status) {
    const icons = {
        'Present': '✓',
        'Present & Late': '⏰',
        'Absent': '✗',
        'On Leave': '📅',
        'Holiday': '🎉',
        'Weekend': '🏠'
    };
    return icons[status] || '—';
}

// API helper
async function fetchAttendanceAPI(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken') || ''
        }
    };

    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };

    try {
        const response = await fetch(url, mergedOptions);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Notification helper
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg transition-all duration-300 transform translate-x-full`;

    const typeClasses = {
        'success': 'bg-green-500 text-white',
        'error': 'bg-red-500 text-white',
        'warning': 'bg-yellow-500 text-white',
        'info': 'bg-blue-500 text-white'
    };

    notification.classList.add(...(typeClasses[type] || typeClasses.info).split(' '));
    notification.textContent = message;

    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.classList.remove('translate-x-full');
    }, 10);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.classList.add('translate-x-full');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Export for module usage if needed
if (typeof window !== 'undefined') {
    window.AttendanceUtils = {
        getCookie,
        formatTime,
        formatDate,
        formatDuration,
        getStatusClass,
        getStatusIcon,
        fetchAttendanceAPI,
        showNotification
    };
}
