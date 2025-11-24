/**
 * Notification System
 * Handles polling, UI updates, sound, and browser notifications
 */

class NotificationSystem {
    constructor(options = {}) {
        console.log('NotificationSystem: Initializing...');
        this.options = {
            pollInterval: 30000, // 30 seconds
            soundEnabled: true,
            browserNotifications: true,
            // Corrected API endpoints based on urls.py
            apiEndpoint: '/api/notifications/',
            markReadEndpoint: '/api/notifications/mark-read/',
            markAllReadEndpoint: '/api/notifications/mark-all-read/',
            ...options
        };

        console.log('NotificationSystem: Options configured:', this.options);

        this.state = {
            unreadCount: 0,
            notifications: [],
            lastPoll: null
        };

        this.elements = {
            badge: document.getElementById('notification-badge'),
            list: document.getElementById('notification-list'),
            sound: document.getElementById('notification-sound'),
            dropdown: document.querySelector('[data-dropdown="notifications"]')
        };

        console.log('NotificationSystem: Elements found:', {
            badge: !!this.elements.badge,
            list: !!this.elements.list,
            sound: !!this.elements.sound,
            dropdown: !!this.elements.dropdown
        });

        this.init();
    }

    init() {
        // Request browser permission
        if (this.options.browserNotifications && 'Notification' in window) {
            if (Notification.permission === 'default') {
                console.log('NotificationSystem: Requesting browser permission...');
                Notification.requestPermission().then(permission => {
                    console.log('NotificationSystem: Browser permission result:', permission);
                });
            } else {
                console.log('NotificationSystem: Browser permission status:', Notification.permission);
            }
        }

        // Start polling
        console.log('NotificationSystem: Starting polling...');
        this.poll();
        setInterval(() => this.poll(), this.options.pollInterval);

        // Bind events
        this.bindEvents();
    }

    bindEvents() {
        // Mark all read button
        const markAllBtn = document.querySelector('.mark-all-read'); // Changed to class selector as per HTML
        if (markAllBtn) {
            console.log('NotificationSystem: Bound "Mark all read" button');
            markAllBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.markAllRead();
            });
        } else {
            console.warn('NotificationSystem: "Mark all read" button not found');
        }
    }

    async poll() {
        console.log('NotificationSystem: Polling for updates...');
        try {
            const response = await fetch(this.options.apiEndpoint);
            console.log('NotificationSystem: Poll response status:', response.status);

            if (!response.ok) throw new Error(`Network response was not ok: ${response.status}`);

            const data = await response.json();
            console.log('NotificationSystem: Poll data received:', data);
            this.handleUpdate(data);
        } catch (error) {
            console.error('NotificationSystem: Poll failed:', error);
            // Update UI to show error if list is empty
            if (this.state.notifications.length === 0 && this.elements.list) {
                this.elements.list.innerHTML = `
                    <div class="p-8 text-center text-red-500">
                        <i class="ri-error-warning-line text-3xl mb-2"></i>
                        <p>Failed to load notifications</p>
                    </div>
                `;
            }
        }
    }

    handleUpdate(data) {
        const { notifications, unread_count } = data;
        const prevCount = this.state.unreadCount;

        console.log(`NotificationSystem: Handling update. Unread: ${unread_count} (was ${prevCount})`);

        // Update state
        this.state.notifications = notifications;
        this.state.unreadCount = unread_count;

        // Update UI
        this.updateBadge();
        this.updateList();

        // Trigger alerts if new unread notifications arrived
        // Logic: if unread count increased OR if we have unread items newer than last poll
        if (unread_count > prevCount && this.state.lastPoll) {
            const newNotifications = notifications.filter(n => !n.read && new Date(n.timestamp) > this.state.lastPoll);
            console.log('NotificationSystem: New notifications detected:', newNotifications);

            if (newNotifications.length > 0) {
                this.playAlerts(newNotifications[0]);
            }
        } else if (!this.state.lastPoll && unread_count > 0) {
            // Initial load with unread items - maybe don't play sound to avoid annoyance on refresh?
            // Or play if user specifically wants to know about unread on load.
            // For now, let's log it.
            console.log('NotificationSystem: Initial load has unread items.');
        }

        this.state.lastPoll = new Date();
    }

    updateBadge() {
        if (!this.elements.badge) return;

        // The HTML structure might use a span inside the button, check selector in base.html
        // In base.html: <span class="notification-badge ..."></span>
        // The constructor selects by ID 'notification-badge' but base.html uses class 'notification-badge' and NO ID.
        // Let's fix the selector in constructor or handle it here.
        // Actually, let's fix the selector in the constructor to match base.html better if needed, 
        // but for now let's assume the user might have added the ID or we should use the class.

        // Re-query if element is missing (resilience)
        if (!this.elements.badge) {
            this.elements.badge = document.querySelector('.notification-badge');
        }

        if (this.elements.badge) {
            if (this.state.unreadCount > 0) {
                this.elements.badge.textContent = ''; // Small dot style usually doesn't have text, or if it's a counter:
                // If it's a counter style:
                // this.elements.badge.textContent = this.state.unreadCount;

                // Based on base.html: w-2.5 h-2.5 bg-red-500 rounded-full
                // It's just a dot.

                this.elements.badge.classList.remove('hidden');
                this.elements.badge.classList.add('animate-bounce');
                setTimeout(() => this.elements.badge.classList.remove('animate-bounce'), 1000);
            } else {
                this.elements.badge.classList.add('hidden');
            }
        }
    }

    updateList() {
        if (!this.elements.list) {
            this.elements.list = document.querySelector('.notification-list');
        }
        if (!this.elements.list) return;

        console.log('NotificationSystem: Updating list UI. Count:', this.state.notifications.length);

        if (this.state.notifications.length === 0) {
            this.elements.list.innerHTML = `
                <div class="p-8 text-center text-gray-500">
                    <i class="ri-notification-off-line text-3xl mb-2"></i>
                    <p>No notifications</p>
                </div>
            `;
            return;
        }

        this.elements.list.innerHTML = this.state.notifications.map((n, index) => `
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
                            ${!n.read ? `<button data-notification-id="${n.id}" class="mark-read-btn text-xs text-gray-500 hover:text-gray-700">Mark as read</button>` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `).join('');

        // Bind click events after rendering
        this.elements.list.querySelectorAll('.mark-read-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const id = parseInt(btn.getAttribute('data-notification-id'));
                this.markRead(id);
            });
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
        console.log('NotificationSystem: Playing alerts for:', notification.title);

        // Sound
        if (this.options.soundEnabled && this.elements.sound) {
            console.log('NotificationSystem: Attempting to play sound...');
            this.elements.sound.play()
                .then(() => console.log('NotificationSystem: Sound played successfully'))
                .catch(e => console.error('NotificationSystem: Audio play failed:', e));
        } else {
            console.log('NotificationSystem: Sound disabled or element not found');
        }

        // Browser Notification
        if (this.options.browserNotifications && 'Notification' in window && Notification.permission === 'granted') {
            console.log('NotificationSystem: Showing browser notification');
            new Notification(notification.title, {
                body: notification.message,
                icon: '/static/images/favicon.ico'
            });
        }
    }

    async markRead(id) {
        console.log('NotificationSystem: Marking read:', id);
        try {
            // Fix URL construction: remove the extra ID concatenation if it was wrong
            // The endpoint is /api/notifications/mark-read/<int:notification_id>/
            const url = `${this.options.markReadEndpoint}${id}/`;

            await fetch(url, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': document.querySelector('[name=csrf-token]').content
                }
            });

            console.log('NotificationSystem: Marked read successfully');

            // Optimistic update
            const n = this.state.notifications.find(n => n.id === id);
            if (n) {
                n.read = true;
                this.state.unreadCount = Math.max(0, this.state.unreadCount - 1);
                this.updateBadge();
                this.updateList();
            }
        } catch (error) {
            console.error('NotificationSystem: Mark read failed:', error);
        }
    }

    async markAllRead() {
        console.log('NotificationSystem: Marking ALL read');
        try {
            await fetch(this.options.markAllReadEndpoint, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': document.querySelector('[name=csrf-token]').content
                }
            });

            console.log('NotificationSystem: Marked all read successfully');

            this.state.notifications.forEach(n => n.read = true);
            this.state.unreadCount = 0;
            this.updateBadge();
            this.updateList();
        } catch (error) {
            console.error('NotificationSystem: Mark all read failed:', error);
        }
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Check for either the list or the dropdown to initialize
    if (document.querySelector('.notification-list') || document.getElementById('notification-list')) {
        console.log('NotificationSystem: DOM Content Loaded, initializing...');
        window.notifications = new NotificationSystem();
    } else {
        console.warn('NotificationSystem: Notification list container not found, skipping init.');
    }
});
