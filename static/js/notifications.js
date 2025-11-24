/**
 * Notification System
 * Handles polling, UI updates, sound, and browser notifications
 */

class NotificationSystem {
    constructor(options = {}) {
        this.options = {
            pollInterval: 30000, // 30 seconds
            soundEnabled: true,
            browserNotifications: true,
            apiEndpoint: '/notifications/api/notifications/',
            markReadEndpoint: '/notifications/api/notifications/mark-read/',
            markAllReadEndpoint: '/notifications/api/notifications/mark-all-read/',
            ...options
        };

        this.state = {
            unreadCount: 0,
            notifications: [],
            lastPoll: null
        };

        this.elements = {
            badges: document.querySelectorAll('.notification-badge'),
            lists: document.querySelectorAll('.notification-list'),
            sound: document.getElementById('notification-sound'),
            dropdowns: document.querySelectorAll('[data-dropdown="notifications"]')
        };

        this.init();
    }

    init() {
        // Request browser permission
        if (this.options.browserNotifications && 'Notification' in window) {
            if (Notification.permission === 'default') {
                Notification.requestPermission();
            }
        }

        // Start polling
        this.poll();
        setInterval(() => this.poll(), this.options.pollInterval);

        // Bind events
        this.bindEvents();
    }

    bindEvents() {
        // Mark all read buttons
        const markAllBtns = document.querySelectorAll('.mark-all-read');
        markAllBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.markAllRead();
            });
        });
    }

    async poll() {
        try {
            const response = await fetch(this.options.apiEndpoint);
            if (!response.ok) throw new Error('Network response was not ok');

            const data = await response.json();
            this.handleUpdate(data);
        } catch (error) {
            console.error('Notification poll failed:', error);
        }
    }

    handleUpdate(data) {
        const { notifications, unread_count } = data;
        const prevCount = this.state.unreadCount;

        // Update state
        this.state.notifications = notifications;
        this.state.unreadCount = unread_count;

        // Update UI
        this.updateBadges();
        this.updateLists();

        // Trigger alerts if new unread notifications arrived
        if (unread_count > prevCount) {
            const newNotifications = notifications.filter(n => !n.read && new Date(n.timestamp) > (this.state.lastPoll || 0));
            if (newNotifications.length > 0) {
                this.playAlerts(newNotifications[0]);
            }
        }

        this.state.lastPoll = new Date();
    }

    updateBadges() {
        this.elements.badges.forEach(badge => {
            if (this.state.unreadCount > 0) {
                badge.textContent = this.state.unreadCount;
                badge.classList.remove('hidden');
                badge.classList.add('animate-bounce');
                // Remove animation after 1s
                setTimeout(() => badge.classList.remove('animate-bounce'), 1000);
            } else {
                badge.classList.add('hidden');
            }
        });
    }

    updateLists() {
        this.elements.lists.forEach(list => {
            if (this.state.notifications.length === 0) {
                list.innerHTML = `
                    <div class="p-8 text-center text-gray-500">
                        <i class="ri-notification-off-line text-3xl mb-2"></i>
                        <p>No notifications</p>
                    </div>
                `;
                return;
            }

            list.innerHTML = this.state.notifications.map(n => `
                <div class="p-4 border-b border-gray-100 hover:bg-gray-50 transition-colors duration-150 ${n.read ? 'opacity-75' : 'bg-blue-50/30'}">
                    <div class="flex gap-3">
                        <div class="flex-shrink-0 mt-1">
                            ${this.getIcon(n.module)}
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex justify-between items-start">
                                <h4 class="text-sm font-semibold text-gray-900 truncate pr-2">${n.title}</h4>
                                <span class="text-xs text-gray-500 whitespace-nowrap">${this.formatTime(n.timestamp)}</span>
                            </div>
                            <p class="text-sm text-gray-600 mt-0.5 line-clamp-2">${n.message}</p>
                            <div class="mt-2 flex gap-3">
                                ${n.url ? `<a href="${n.url}" class="text-xs font-medium text-primary-600 hover:text-primary-700">View Details</a>` : ''}
                                ${!n.read ? `<button onclick="window.notifications.markRead(${n.id})" class="text-xs text-gray-500 hover:text-gray-700">Mark as read</button>` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        });
    }

    getIcon(module) {
        const icons = {
            support: '<div class="w-8 h-8 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center"><i class="ri-customer-service-2-line"></i></div>',
            attendance: '<div class="w-8 h-8 rounded-full bg-green-100 text-green-600 flex items-center justify-center"><i class="ri-time-line"></i></div>',
            leave: '<div class="w-8 h-8 rounded-full bg-purple-100 text-purple-600 flex items-center justify-center"><i class="ri-calendar-event-line"></i></div>',
            default: '<div class="w-8 h-8 rounded-full bg-gray-100 text-gray-600 flex items-center justify-center"><i class="ri-notification-line"></i></div>'
        };
        return icons[module] || icons.default;
    }

    formatTime(isoString) {
        const date = new Date(isoString);
        const now = new Date();
        const diff = (now - date) / 1000; // seconds

        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return date.toLocaleDateString();
    }

    playAlerts(notification) {
        // Sound
        if (this.options.soundEnabled && this.elements.sound) {
            this.elements.sound.play().catch(e => console.log('Audio play failed:', e));
        }

        // Browser Notification
        if (this.options.browserNotifications && 'Notification' in window && Notification.permission === 'granted') {
            new Notification(notification.title, {
                body: notification.message,
                icon: '/static/images/favicon.ico' // Ensure this exists or remove
            });
        }
    }

    async markRead(id) {
        try {
            await fetch(this.options.markReadEndpoint.replace('0', id) + id + '/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': document.querySelector('[name=csrf-token]').content
                }
            });
            // Optimistic update
            const n = this.state.notifications.find(n => n.id === id);
            if (n) {
                n.read = true;
                this.state.unreadCount = Math.max(0, this.state.unreadCount - 1);
                this.updateBadge();
                this.updateList();
            }
        } catch (error) {
            console.error('Mark read failed:', error);
        }
    }

    async markAllRead() {
        try {
            await fetch(this.options.markAllReadEndpoint, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': document.querySelector('[name=csrf-token]').content
                }
            });

            this.state.notifications.forEach(n => n.read = true);
            this.state.unreadCount = 0;
            this.updateBadge();
            this.updateList();
        } catch (error) {
            console.error('Mark all read failed:', error);
        }
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.notification-list')) {
        window.notifications = new NotificationSystem();
    }
});
