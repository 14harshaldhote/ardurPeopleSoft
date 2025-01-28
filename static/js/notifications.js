// notifications.js
class NotificationHandler {
    constructor() {
        this.socket = null;
        this.notifications = [];
        this.unreadCount = 0;
        this.notificationButton = document.querySelector('.notification-btn');
        this.notificationContainer = document.createElement('div');
        this.setupNotificationContainer();
        this.connectWebSocket();
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

    connectWebSocket() {
        this.socket = new WebSocket(`ws://${window.location.host}/ws/notifications/`);
        
        this.socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'notification') {
                this.handleNewNotification(data);
            }
        };

        this.socket.onclose = () => {
            console.log('WebSocket closed. Trying to reconnect...');
            setTimeout(() => this.connectWebSocket(), 1000);
        };
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