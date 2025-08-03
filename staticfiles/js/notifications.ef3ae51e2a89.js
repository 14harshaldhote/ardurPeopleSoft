/**
 * ArdurTrueAlign Real-Time Notification System
 * Handles browser notifications, polling, and real-time updates
 */

class NotificationManager {
    constructor(options = {}) {
        this.options = {
            pollingInterval: options.pollingInterval || 30000, // 30 seconds
            maxNotifications: options.maxNotifications || 100,
            enableBrowserNotifications: options.enableBrowserNotifications !== false,
            enableSound: options.enableSound !== false,
            apiEndpoint: '/api/notifications/',
            ...options
        };
        
        this.notifications = [];
        this.unreadCount = 0;
        this.isPolling = false;
        this.pollingTimer = null;
        this.lastPollingTime = null;
        
        // UI Elements
        this.notificationButton = null;
        this.notificationBadge = null;
        this.notificationContainer = null;
        
        this.init();
    }
    
    async init() {
        console.log('Initializing NotificationManager...');
        
        // Request browser notification permission
        if (this.options.enableBrowserNotifications) {
            await this.requestNotificationPermission();
        }
        
        // Setup UI elements
        this.setupUI();
        
        // Start polling
        this.startPolling();
        
        // Setup event listeners
        this.setupEventListeners();
        
        console.log('NotificationManager initialized successfully');
    }
    
    async requestNotificationPermission() {
        if ('Notification' in window) {
            if (Notification.permission === 'default') {
                const permission = await Notification.requestPermission();
                console.log('Notification permission:', permission);
            }
        } else {
            console.warn('Browser does not support notifications');
        }
    }
    
    setupUI() {
        // Find or create notification button
        this.notificationButton = document.querySelector('.notification-btn') || this.createNotificationButton();
        
        // Create notification badge
        this.notificationBadge = this.notificationButton.querySelector('.notification-badge') || this.createNotificationBadge();
        
        // Create notification container
        this.notificationContainer = this.createNotificationContainer();
        
        // Add click handler for notification button
        this.notificationButton.addEventListener('click', (e) => {
            e.preventDefault();
            this.toggleNotificationContainer();
        });
    }
    
    createNotificationButton() {
        // This method assumes there's already a notification button in the DOM
        // If not, you can create one dynamically
        const button = document.createElement('button');
        button.className = 'notification-btn relative p-2 text-gray-600 hover:text-gray-900 focus:outline-none';
        button.innerHTML = `
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                      d="M15 17h5l-5 5v-5zM11 1L6 6h5v5l5-5H11V1z"></path>
            </svg>
        `;
        
        // Add to header or navigation
        const header = document.querySelector('header, .header, nav');
        if (header) {
            header.appendChild(button);
        }
        
        return button;
    }
    
    createNotificationBadge() {
        const badge = document.createElement('span');
        badge.className = 'notification-badge absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center hidden';
        this.notificationButton.appendChild(badge);
        return badge;
    }
    
    createNotificationContainer() {
        const container = document.createElement('div');
        container.className = 'notification-container absolute right-0 mt-2 w-96 bg-white rounded-lg shadow-xl border z-50 max-h-96 overflow-hidden hidden';
        container.innerHTML = `
            <div class="notification-header p-4 border-b bg-gray-50">
                <div class="flex justify-between items-center">
                    <h3 class="text-lg font-semibold text-gray-900">Notifications</h3>
                    <button class="mark-all-read-btn text-sm text-blue-600 hover:text-blue-800">
                        Mark all read
                    </button>
                </div>
            </div>
            <div class="notification-list overflow-y-auto max-h-80">
                <div class="no-notifications p-8 text-center text-gray-500 hidden">
                    <svg class="w-12 h-12 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-5 5v-5z"></path>
                    </svg>
                    <p>No notifications</p>
                </div>
            </div>
        `;
        
        // Position relative to notification button
        this.notificationButton.parentElement.style.position = 'relative';
        this.notificationButton.parentElement.appendChild(container);
        
        // Setup mark all read button
        const markAllReadBtn = container.querySelector('.mark-all-read-btn');
        markAllReadBtn.addEventListener('click', () => this.markAllNotificationsRead());
        
        return container;
    }
    
    setupEventListeners() {
        // Close notification container when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.notificationButton.contains(e.target) && !this.notificationContainer.contains(e.target)) {
                this.hideNotificationContainer();
            }
        });
        
        // Handle visibility change (pause polling when tab is not visible)
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.pausePolling();
            } else {
                this.resumePolling();
            }
        });
    }
    
    async startPolling() {
        if (this.isPolling) return;
        
        this.isPolling = true;
        console.log('Starting notification polling...');
        
        // Initial fetch
        await this.fetchNotifications();
        
        // Setup polling interval
        this.pollingTimer = setInterval(() => {
            this.fetchNotifications();
        }, this.options.pollingInterval);
    }
    
    pausePolling() {
        if (this.pollingTimer) {
            clearInterval(this.pollingTimer);
            this.pollingTimer = null;
        }
        this.isPolling = false;
        console.log('Notification polling paused');
    }
    
    resumePolling() {
        if (!this.isPolling) {
            this.startPolling();
            console.log('Notification polling resumed');
        }
    }
    
    async fetchNotifications() {
        try {
            const response = await fetch(this.options.apiEndpoint, {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json',
                },
                credentials: 'same-origin'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.processNotifications(data.notifications, data.unread_count);
                this.lastPollingTime = new Date(data.timestamp);
            }
            
        } catch (error) {
            console.error('Error fetching notifications:', error);
        }
    }
    
    processNotifications(newNotifications, unreadCount) {
        // Check for new notifications since last poll
        const existingIds = new Set(this.notifications.map(n => n.id));
        const actuallyNewNotifications = newNotifications.filter(n => !existingIds.has(n.id));
        
        // Show browser notifications for new notifications
        if (actuallyNewNotifications.length > 0) {
            actuallyNewNotifications.forEach(notification => {
                this.showBrowserNotification(notification);
                this.playNotificationSound();
            });
        }
        
        // Update internal state
        this.notifications = newNotifications;
        this.unreadCount = unreadCount;
        
        // Update UI
        this.updateNotificationBadge();
        this.updateNotificationList();
    }
    
    showBrowserNotification(notification) {
        if (!this.options.enableBrowserNotifications || Notification.permission !== 'granted') {
            return;
        }
        
        const options = {
            body: notification.message,
            icon: '/static/images/notification-icon.png',
            badge: '/static/images/notification-badge.png',
            tag: `notification-${notification.id}`,
            requireInteraction: false,
            silent: false
        };
        
        const browserNotification = new Notification(notification.title, options);
        
        // Auto close after 5 seconds
        setTimeout(() => {
            browserNotification.close();
        }, 5000);
        
        // Handle click
        browserNotification.onclick = () => {
            window.focus();
            this.handleNotificationClick(notification);
            browserNotification.close();
        };
    }
    
    playNotificationSound() {
        if (!this.options.enableSound) return;
        
        // Create audio element for notification sound
        const audio = new Audio('/static/sounds/notification.mp3');
        audio.volume = 0.3;
        audio.play().catch(e => {
            // Ignore audio play errors (user hasn't interacted with page yet)
            console.debug('Could not play notification sound:', e);
        });
    }
    
    updateNotificationBadge() {
        if (this.unreadCount > 0) {
            this.notificationBadge.textContent = this.unreadCount > 99 ? '99+' : this.unreadCount;
            this.notificationBadge.classList.remove('hidden');
        } else {
            this.notificationBadge.classList.add('hidden');
        }
    }
    
    updateNotificationList() {
        const listContainer = this.notificationContainer.querySelector('.notification-list');
        const noNotificationsMsg = listContainer.querySelector('.no-notifications');
        
        // Clear existing notifications
        const existingNotifications = listContainer.querySelectorAll('.notification-item');
        existingNotifications.forEach(item => item.remove());
        
        if (this.notifications.length === 0) {
            noNotificationsMsg.classList.remove('hidden');
            return;
        }
        
        noNotificationsMsg.classList.add('hidden');
        
        // Add notifications
        this.notifications.forEach(notification => {
            const notificationElement = this.createNotificationElement(notification);
            listContainer.appendChild(notificationElement);
        });
    }
    
    createNotificationElement(notification) {
        const element = document.createElement('div');
        element.className = `notification-item p-4 border-b hover:bg-gray-50 cursor-pointer ${notification.read ? 'opacity-60' : ''}`;
        element.dataset.notificationId = notification.id;
        
        const timeAgo = this.getTimeAgo(new Date(notification.timestamp));
        
        element.innerHTML = `
            <div class="flex items-start space-x-3">
                <div class="flex-shrink-0">
                    ${this.getNotificationIcon(notification.event_type)}
                </div>
                <div class="flex-1 min-w-0">
                    <p class="text-sm font-medium text-gray-900 ${notification.read ? '' : 'font-semibold'}">
                        ${this.escapeHtml(notification.title)}
                    </p>
                    <p class="text-sm text-gray-600 mt-1">
                        ${this.escapeHtml(notification.message)}
                    </p>
                    <p class="text-xs text-gray-400 mt-1">${timeAgo}</p>
                </div>
                <div class="flex-shrink-0">
                    ${!notification.read ? '<div class="w-2 h-2 bg-blue-500 rounded-full"></div>' : ''}
                </div>
            </div>
        `;
        
        // Add click handler
        element.addEventListener('click', () => {
            this.handleNotificationClick(notification);
        });
        
        return element;
    }
    
    getNotificationIcon(eventType) {
        const icons = {
            'support_ticket_created': `<svg class="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 2L3 9v6a2 2 0 002 2h10a2 2 0 002-2V9l-7-7z"></path></svg>`,
            'support_ticket_updated': `<svg class="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20"><path d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4z"></path></svg>`,
            'leave_request_created': `<svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20"><path d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1z"></path></svg>`,
            'leave_request_approved': `<svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>`,
            'leave_request_rejected': `<svg class="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>`,
            'attendance_alert': `<svg class="w-5 h-5 text-orange-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>`,
            'system_announcement': `<svg class="w-5 h-5 text-purple-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path></svg>`,
            default: `<svg class="w-5 h-5 text-gray-500" fill="currentColor" viewBox="0 0 20 20"><path d="M10 2L3 9v6a2 2 0 002 2h10a2 2 0 002-2V9l-7-7z"></path></svg>`
        };
        
        return icons[eventType] || icons.default;
    }
    
    async handleNotificationClick(notification) {
        // Mark as read if not already
        if (!notification.read) {
            await this.markNotificationRead(notification.id);
        }
        
        // Handle different event types
        switch (notification.event_type) {
            case 'support_ticket_created':
            case 'support_ticket_updated':
                if (notification.event_reference_id) {
                    window.location.href = `/support/ticket/${notification.event_reference_id}/`;
                }
                break;
            case 'leave_request_created':
            case 'leave_request_approved':
            case 'leave_request_rejected':
                window.location.href = '/leave-management/my-leaves/';
                break;
            case 'attendance_alert':
                window.location.href = '/attendance/dashboard/';
                break;
            default:
                console.log('Notification clicked:', notification);
        }
        
        this.hideNotificationContainer();
    }
    
    async markNotificationRead(notificationId) {
        try {
            const response = await fetch(`/api/notifications/${notificationId}/read/`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': this.getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                // Update local state
                const notification = this.notifications.find(n => n.id === notificationId);
                if (notification) {
                    notification.read = true;
                    this.unreadCount = Math.max(0, this.unreadCount - 1);
                    this.updateNotificationBadge();
                    this.updateNotificationList();
                }
            }
        } catch (error) {
            console.error('Error marking notification as read:', error);
        }
    }
    
    async markAllNotificationsRead() {
        try {
            const response = await fetch('/api/notifications/mark-all-read/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': this.getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                // Update local state
                this.notifications.forEach(notification => {
                    notification.read = true;
                });
                this.unreadCount = 0;
                this.updateNotificationBadge();
                this.updateNotificationList();
            }
        } catch (error) {
            console.error('Error marking all notifications as read:', error);
        }
    }
    
    toggleNotificationContainer() {
        if (this.notificationContainer.classList.contains('hidden')) {
            this.showNotificationContainer();
        } else {
            this.hideNotificationContainer();
        }
    }
    
    showNotificationContainer() {
        this.notificationContainer.classList.remove('hidden');
        
        // Mark all as read when opening
        if (this.unreadCount > 0) {
            setTimeout(() => {
                this.markAllNotificationsRead();
            }, 1000);
        }
    }
    
    hideNotificationContainer() {
        this.notificationContainer.classList.add('hidden');
    }
    
    getCSRFToken() {
        const cookieValue = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrftoken='))
            ?.split('=')[1];
        return cookieValue || '';
    }
    
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    
    getTimeAgo(date) {
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        if (diffInSeconds < 60) {
            return 'Just now';
        } else if (diffInSeconds < 3600) {
            const minutes = Math.floor(diffInSeconds / 60);
            return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`;
        } else if (diffInSeconds < 86400) {
            const hours = Math.floor(diffInSeconds / 3600);
            return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
        } else {
            const days = Math.floor(diffInSeconds / 86400);
            return `${days} ${days === 1 ? 'day' : 'days'} ago`;
        }
    }
    
    destroy() {
        if (this.pollingTimer) {
            clearInterval(this.pollingTimer);
        }
        this.isPolling = false;
        console.log('NotificationManager destroyed');
    }
}

// Initialize notification manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Get settings from server or use defaults
    fetch('/api/notifications/settings/')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.notificationManager = new NotificationManager({
                    pollingInterval: data.settings.polling_interval * 1000,
                    maxNotifications: data.settings.max_notifications,
                    enableBrowserNotifications: data.settings.browser_notifications_enabled,
                });
            }
        })
        .catch(error => {
            console.error('Error fetching notification settings:', error);
            // Initialize with defaults
            window.notificationManager = new NotificationManager();
        });
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.notificationManager) {
        window.notificationManager.destroy();
    }
});

// notifications.js
class NotificationHandler {
    constructor() {
        this.notifications = [];
        this.unreadCount = 0;
        this.notificationButton = document.querySelector('.notification-btn');
        this.notificationContainer = document.createElement('div');
        this.setupNotificationContainer();
        this.startPolling();
    }

    setupNotificationContainer() {
        this.notificationContainer.className = 'notification-container absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto hidden';
        this.notificationButton.parentElement.appendChild(this.notificationContainer);
        
        this.notificationButton.addEventListener('click', () => {
            this.notificationContainer.classList.toggle('hidden');
            if (!this.notificationContainer.classList.contains('hidden')) {
                this.markAllAsRead();
            }
        });
    }

    startPolling() {
        // Initial fetch
        this.fetchNotifications();
        
        // Poll every 30 seconds
        setInterval(() => this.fetchNotifications(), 30000);
    }

    async fetchNotifications() {
        try {
            const response = await fetch('/api/notifications/', {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json',
                },
                credentials: 'same-origin'
            });

            if (response.ok) {
                const data = await response.json();
                // Only process if we have new notifications
                if (data.notifications && this.notifications.length !== data.notifications.length) {
                    const newNotifications = data.notifications.filter(
                        n => !this.notifications.find(existing => existing.id === n.id)
                    );
                    
                    newNotifications.forEach(notification => {
                        this.handleNewNotification(notification);
                    });
                }
            }
        } catch (error) {
            console.error('Error fetching notifications:', error);
        }
    }

    handleNewNotification(data) {
        this.notifications.unshift(data);
        this.unreadCount++;
        this.updateNotificationBadge();
        this.showNotification(data);
        this.updateNotificationList();
    }

    showNotification(data) {
        // Show browser notification if permission granted
        if (Notification.permission === 'granted') {
            new Notification(data.message, {
                icon: '/static/images/notification-icon.png',
                body: data.message
            });
        }

        // Show toast notification
        const toast = document.createElement('div');
        toast.className = 'fixed top-4 right-4 bg-blue-500 text-white px-4 py-2 rounded shadow-lg z-50 animate-fade-in-out';
        toast.textContent = data.message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    updateNotificationList() {
        this.notificationContainer.innerHTML = `
            <div class="p-4">
                <h3 class="text-lg font-semibold mb-2">Notifications</h3>
                ${this.notifications.length === 0 ? 
                    '<p class="text-gray-500">No notifications</p>' :
                    this.notifications.map(notif => this.renderNotification(notif)).join('')}
            </div>
        `;
    }

    renderNotification(notification) {
        return `
            <div class="p-2 hover:bg-gray-50 rounded ${notification.read ? 'opacity-75' : ''}">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm">${notification.message}</p>
                        <p class="text-xs text-gray-500">${moment(notification.timestamp).fromNow()}</p>
                    </div>
                    ${notification.chat_id ? 
                        `<a href="/chat/${notification.chat_id}" class="text-blue-500 text-sm">View</a>` : 
                        ''}
                </div>
            </div>
        `;
    }

    updateNotificationBadge() {
        const badge = this.notificationButton.querySelector('.notification-badge') || 
            this.createNotificationBadge();
        
        if (this.unreadCount > 0) {
            badge.textContent = this.unreadCount;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    createNotificationBadge() {
        const badge = document.createElement('span');
        badge.className = 'notification-badge absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center';
        this.notificationButton.appendChild(badge);
        return badge;
    }

    markAllAsRead() {
        this.notifications.forEach(notif => notif.read = true);
        this.unreadCount = 0;
        this.updateNotificationBadge();
        this.updateNotificationList();
    }
}

// Initialize notification handler
document.addEventListener('DOMContentLoaded', () => {
    const notificationHandler = new NotificationHandler();
    
    // Request notification permission
    if (Notification.permission === 'default') {
        Notification.requestPermission();
    }
});