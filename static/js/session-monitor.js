/**
 * Global Session Monitor
 * Handles session tracking, auto-logout warnings, and session expiry
 * Updated to work with Tailwind CSS modal in base.html
 */

class SessionMonitor {
  constructor(options = {}) {
    this.options = {
      warningMinutes: 5, // Show warning when 5 minutes left
      heartbeatInterval: 30000, // 30 seconds
      checkInterval: 60000, // Check every minute
      logoutUrl: "/logout/",
      loginUrl: "/login/",
      sessionStatusUrl: "/session/status/",
      updateActivityUrl: "/session/update-activity/",
      heartbeatUrl: "/session/heartbeat/",
      ...options,
    };

    this.sessionWarningShown = false;
    this.heartbeatTimer = null;
    this.checkTimer = null;
    this.countdownTimer = null;
    this.lastActivity = Date.now();
    this.isIdle = false;
    this.tabId = this.generateTabId();

    // Get modal elements from the DOM (created in base.html)
    this.modal = null;
    this.modalContent = null;
    this.continueBtn = null;
    this.logoutBtn = null;
    this.messageEl = null;
    this.countdownEl = null;

    this.init();
  }

  init() {
    // Get modal elements after DOM is ready
    this.getModalElements();

    this.setupEventListeners();
    this.startHeartbeat();
    this.startSessionCheck();
    this.setupModalEventHandlers();

    // Send initial heartbeat
    this.sendHeartbeat();

    console.log("Session Monitor initialized");
  }

  getModalElements() {
    this.modal = document.getElementById("sessionWarningModal");
    this.modalContent = document.getElementById("sessionWarningModalContent");
    this.continueBtn = document.getElementById("continueSessionBtn");
    this.logoutBtn = document.getElementById("logoutBtn");
    this.messageEl = document.getElementById("sessionWarningMessage");
    this.countdownEl = document.getElementById("sessionCountdown");

    if (!this.modal) {
      console.warn(
        "Session warning modal not found in DOM. Make sure it exists in base.html",
      );
    }
  }

  setupModalEventHandlers() {
    // Setup continue button
    if (this.continueBtn) {
      this.continueBtn.addEventListener("click", () => {
        this.extendSession();
      });
    }

    // Setup logout button
    if (this.logoutBtn) {
      this.logoutBtn.addEventListener("click", () => {
        window.location.href = this.options.logoutUrl;
      });
    }

    // Handle modal background click to close (treat as continue)
    if (this.modal) {
      this.modal.addEventListener("click", (e) => {
        if (e.target === this.modal) {
          this.extendSession();
        }
      });
    }

    // Handle escape key
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && this.sessionWarningShown) {
        this.extendSession();
      }
    });
  }

  generateTabId() {
    return "tab_" + Math.random().toString(36).substr(2, 9) + "_" + Date.now();
  }

  setupEventListeners() {
    // Track user activity
    const activityEvents = [
      "mousedown",
      "mousemove",
      "keypress",
      "scroll",
      "touchstart",
      "click",
    ];

    activityEvents.forEach((event) => {
      document.addEventListener(
        event,
        () => {
          this.updateActivity();
        },
        true,
      );
    });

    // Handle visibility change
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        this.handleTabHidden();
      } else {
        this.handleTabVisible();
      }
    });

    // Handle page unload
    window.addEventListener("beforeunload", () => {
      this.sendActivity({ type: "page_unload" });
    });

    // Handle network status
    window.addEventListener("online", () => {
      this.handleOnline();
    });

    window.addEventListener("offline", () => {
      this.handleOffline();
    });
  }

  updateActivity() {
    this.lastActivity = Date.now();
    if (this.isIdle) {
      this.isIdle = false;
      this.sendActivity({ is_idle: false });
    }

    // Hide warning if shown
    if (this.sessionWarningShown) {
      this.hideWarning();
    }
  }

  startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      this.sendHeartbeat();
    }, this.options.heartbeatInterval);
  }

  startSessionCheck() {
    this.checkTimer = setInterval(() => {
      this.checkSessionStatus();
    }, this.options.checkInterval);
  }

  sendHeartbeat() {
    const now = Date.now();
    const timeSinceActivity = now - this.lastActivity;
    const isCurrentlyIdle = timeSinceActivity > 60000; // 1 minute of inactivity

    if (isCurrentlyIdle !== this.isIdle) {
      this.isIdle = isCurrentlyIdle;
    }

    const data = {
      tab_id: this.tabId,
      is_idle: this.isIdle,
      is_visible: !document.hidden,
      url: window.location.href,
      title: document.title,
      timestamp: new Date().toISOString(),
    };

    this.sendRequest(this.options.heartbeatUrl, data);
  }

  sendActivity(additionalData = {}) {
    const data = {
      tab_id: this.tabId,
      is_idle: this.isIdle,
      timestamp: new Date().toISOString(),
      ...additionalData,
    };

    this.sendRequest(this.options.updateActivityUrl, data);
  }

  checkSessionStatus() {
    fetch(this.options.sessionStatusUrl + "?tab_id=" + this.tabId, {
      method: "GET",
      credentials: "same-origin",
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json",
      },
    })
      .then((response) => {
        if (response.status === 401) {
          this.handleSessionExpired();
          return null;
        }
        return response.json();
      })
      .then((data) => {
        if (data) {
          this.handleSessionStatus(data);
        }
      })
      .catch((error) => {
        console.error("Error checking session status:", error);
      });
  }

  handleSessionStatus(data) {
    if (data.status === "no_active_session") {
      this.handleSessionExpired();
      return;
    }

    if (data.warning && !this.sessionWarningShown) {
      this.showWarning(data.remaining_minutes);
    } else if (!data.warning && this.sessionWarningShown) {
      this.hideWarning();
    }
  }

  showWarning(remainingMinutes) {
    if (!this.modal) {
      console.error("Modal not found. Cannot show session warning.");
      return;
    }

    this.sessionWarningShown = true;

    // Update modal content
    if (this.messageEl) {
      this.messageEl.textContent = `Your session will expire in ${Math.ceil(remainingMinutes)} minutes due to inactivity.`;
    }

    // Show modal with proper accessibility
    this.modal.classList.remove("hidden");
    this.modal.setAttribute("aria-hidden", "false");

    // Animate modal in
    requestAnimationFrame(() => {
      if (this.modalContent) {
        this.modalContent.classList.remove("scale-95", "opacity-0");
        this.modalContent.classList.add("scale-100", "opacity-100");
      }
    });

    // Focus the continue button after animation
    setTimeout(() => {
      if (this.continueBtn) {
        this.continueBtn.focus();
      }
    }, 150);

    // Start countdown
    this.startCountdown(remainingMinutes * 60);
  }

  hideWarning() {
    if (!this.modal || !this.sessionWarningShown) {
      return;
    }

    this.sessionWarningShown = false;

    // Animate modal out
    if (this.modalContent) {
      this.modalContent.classList.remove("scale-100", "opacity-100");
      this.modalContent.classList.add("scale-95", "opacity-0");
    }

    // Hide modal after animation
    setTimeout(() => {
      this.modal.classList.add("hidden");
      this.modal.setAttribute("aria-hidden", "true");
    }, 300);

    // Clear countdown timer
    if (this.countdownTimer) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
  }

  startCountdown(seconds) {
    let remaining = seconds;

    this.countdownTimer = setInterval(() => {
      remaining--;

      const minutes = Math.floor(remaining / 60);
      const secs = remaining % 60;

      if (this.countdownEl) {
        this.countdownEl.textContent = `${minutes}:${secs.toString().padStart(2, "0")}`;
      }

      if (remaining <= 0) {
        clearInterval(this.countdownTimer);
        this.handleSessionExpired();
      }
    }, 1000);
  }

  extendSession() {
    this.updateActivity();
    this.hideWarning();

    // Send explicit activity update
    this.sendActivity({
      type: "manual_extension",
      extend_session: true,
    });
  }

  handleSessionExpired() {
    this.cleanup();

    // Show session expired message
    alert(
      "Your session has expired. You will be redirected to the login page.",
    );

    // Redirect to login
    window.location.href = this.options.loginUrl;
  }

  handleTabHidden() {
    this.sendActivity({
      type: "tab_visibility",
      action: "hidden",
      timestamp: new Date().toISOString(),
    });
  }

  handleTabVisible() {
    this.sendActivity({
      type: "tab_visibility",
      action: "visible",
      timestamp: new Date().toISOString(),
    });
  }

  handleOnline() {
    console.log("Connection restored");
    this.sendHeartbeat();
  }

  handleOffline() {
    console.log("Connection lost");
  }

  sendRequest(url, data) {
    fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json",
        "X-CSRFToken": this.getCSRFToken(),
        "X-Tab-ID": this.tabId,
      },
      body: JSON.stringify(data),
    })
      .then((response) => {
        if (response.status === 401) {
          this.handleSessionExpired();
          return null;
        }
        return response.json();
      })
      .then((data) => {
        if (data && data.warning && !this.sessionWarningShown) {
          this.showWarning(data.remaining_minutes);
        }
      })
      .catch((error) => {
        console.error("Error sending request:", error);
      });
  }

  getCSRFToken() {
    const cookies = document.cookie.split(";");
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split("=");
      if (name === "csrftoken") {
        return value;
      }
    }

    // Fallback to meta tag
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
      return csrfMeta.getAttribute("content");
    }

    return "";
  }

  cleanup() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }

    if (this.countdownTimer) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
  }

  destroy() {
    this.cleanup();
    this.hideWarning();
    console.log("Session Monitor destroyed");
  }
}

// Auto-initialize when DOM is ready
document.addEventListener("DOMContentLoaded", function () {
  // Only initialize if user is authenticated (check for a user-specific element or data attribute)
  if (
    document.body.dataset.authenticated === "true" ||
    document.querySelector("[data-user-authenticated]") ||
    document.getElementById("sessionWarningModal")
  ) {
    window.sessionMonitor = new SessionMonitor();
  }
});
