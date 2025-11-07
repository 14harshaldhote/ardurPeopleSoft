class NotificationHandler {
    constructor(options = {}) {
        this.options = {
            pollingInterval: options.pollingInterval || 30000,
            notificationContainer: options.notificationContainer || '#notification-list',
            notificationBadge: options.notificationBadge || '#notification-badge',
            maxNotifications: options.maxNotifications || 20
        };

        this.lastNotificationId = 0;
        this.setupNotifications();
    }

    setupNotifications() {
        // Request notification permission
        if ("Notification" in window) {
            Notification.requestPermission();
        }

        // Start polling
        this.pollNotifications();
        setInterval(() => this.pollNotifications(), this.options.pollingInterval);

        // Setup mark as read handlers
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-notification-id]')) {
                const notificationId = e.target.dataset.notificationId;
                this.markAsRead(notificationId);
            }
        });
    }

    async pollNotifications() {
        try {
            const response = await fetch('/api/notifications/');
            const data = await response.json();

            // Update notification badge
            this.updateBadge(data.unread_count);

            // Show new browser notifications
            data.notifications.forEach(notification => {
                if (!notification.unread) return;

                if (notification.id > this.lastNotificationId) {
                    this.showBrowserNotification(notification);
                    this.lastNotificationId = notification.id;
                }
            });

            // Update notification list in UI
            this.updateNotificationList(data.notifications);
        } catch (error) {
            console.error('Error polling notifications:', error);
        }
    }

    updateBadge(count) {
        const badge = document.querySelector(this.options.notificationBadge);
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'block' : 'none';
        }
    }

    updateNotificationList(notifications) {
        const container = document.querySelector(this.options.notificationContainer);
        if (!container) return;

        const html = notifications.map(notification => `
            <div class="notification-item ${notification.unread ? 'unread' : ''}" 
                 data-notification-id="${notification.id}">
                <div class="notification-header">
                    <span class="notification-actor">${notification.actor}</span>
                    <span class="notification-verb">${notification.verb}</span>
                    <span class="notification-time">
                        ${this.formatTimestamp(notification.timestamp)}
                    </span>
                </div>
                <div class="notification-description">${notification.description}</div>
                ${notification.url ? `
                    <a href="${notification.url}" class="notification-link">
                        View Details
                    </a>
                ` : ''}
            </div>
        `).join('');

        container.innerHTML = html || '<div class="no-notifications">No notifications</div>';
    }

    showBrowserNotification(notification) {
        if (Notification.permission === "granted") {
            new Notification(notification.actor + ' ' + notification.verb, {
                body: notification.description,
                icon: '/static/img/notification-icon.png'
            });
        }
    }

    async markAsRead(notificationId) {
        try {
            const response = await fetch(`/api/notifications/mark-read/${notificationId}/`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': this.getCsrfToken()
                }
            });

            if (response.ok) {
                const element = document.querySelector(`[data-notification-id="${notificationId}"]`);
                if (element) {
                    element.classList.remove('unread');
                }

                // Update badge count
                const badge = document.querySelector(this.options.notificationBadge);
                const currentCount = parseInt(badge.textContent);
                this.updateBadge(Math.max(0, currentCount - 1));
            }
        } catch (error) {
            console.error('Error marking notification as read:', error);
        }
    }

    async markAllAsRead() {
        try {
            const response = await fetch('/api/notifications/mark-all-read/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': this.getCsrfToken()
                }
            });

            if (response.ok) {
                // Update UI
                document.querySelectorAll('.notification-item.unread').forEach(el => {
                    el.classList.remove('unread');
                });

                // Update badge
                this.updateBadge(0);
            }
        } catch (error) {
            console.error('Error marking all notifications as read:', error);
        }
    }

    formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;

        // Less than 1 minute
        if (diff < 60000) {
            return 'Just now';
        }
        // Less than 1 hour
        if (diff < 3600000) {
            const minutes = Math.floor(diff / 60000);
            return `${minutes}m ago`;
        }
        // Less than 1 day
        if (diff < 86400000) {
            const hours = Math.floor(diff / 3600000);
            return `${hours}h ago`;
        }
        // Less than 7 days
        if (diff < 604800000) {
            const days = Math.floor(diff / 86400000);
            return `${days}d ago`;
        }
        // Otherwise show full date
        return date.toLocaleDateString();
    }

    getCsrfToken() {
        const name = 'csrftoken';
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
}

// Initialize notifications when document is ready
document.addEventListener('DOMContentLoaded', () => {
    window.notificationHandler = new NotificationHandler({
        pollingInterval: 30000,  // 30 seconds
        notificationContainer: '#notification-list',
        notificationBadge: '#notification-badge',
        maxNotifications: 20
    });
});
