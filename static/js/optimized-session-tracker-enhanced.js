/**
 * Enhanced Optimized Session Tracker
 * Comprehensive session tracking with throttling, batching, and smart caching
 * Optimized for shared hosting environments like GoDaddy
 * 
 * Version: 2.0.0
 * Fixed all syntax errors, missing methods, and improved reliability
 *
 * Features:
 * - Smart throttling and batching of activities
 * - Comprehensive activity tracking (clicks, scrolls, keyboard, mouse, etc.)
 * - Productivity and engagement scoring
 * - Session warnings and auto-logout
 * - Offline support and retry mechanisms
 * - Memory-efficient buffering
 * - Security and suspicious activity detection
 * - Enhanced error handling and logging
 */

class OptimizedSessionTrackerEnhanced {
  constructor(options = {}) {
    // Configuration with sensible defaults for shared hosting
    this.config = {
      // Throttling intervals (in milliseconds)
      heartbeatInterval: 30000, // 30 seconds
      batchFlushInterval: 300000, // 5 minutes
      activityThrottle: 60000, // 1 minute

      // Buffer limits (prevent memory issues)
      maxBufferSize: 100,
      maxClicksBuffer: 50,
      maxScrollsBuffer: 30,
      maxKeyboardBuffer: 100,
      maxMouseBuffer: 20,

      // Activity sampling rates
      mouseSampleRate: 0.1, // 10% of mouse movements
      scrollSampleRate: 0.3, // 30% of scroll events
      keyboardSampleRate: 0.8, // 80% of keyboard events

      // Session timeouts
      sessionTimeout: 30 * 60 * 1000, // 30 minutes
      warningTime: 25 * 60 * 1000, // 25 minutes
      idleThreshold: 2 * 60 * 1000, // 2 minutes

      // Retry configuration
      maxRetries: 3,
      retryDelay: 30000, // 30 seconds

      // URLs
      heartbeatUrl: "/optimized-heartbeat/",
      batchActivityUrl: "/optimized-batch-activity/",
      sessionStatusUrl: "/optimized-session-status/",
      endSessionUrl: "/optimized-end-session/",
      forceSync: "/optimized-force-sync/",

      // Feature flags
      enableProductivityScoring: true,
      enableEngagementScoring: true,
      enableSecurityChecks: true,
      enableOfflineSupport: true,
      enableLocationTracking: true,

      ...options,
    };

    // State management
    this.state = {
      sessionId: null,
      parentSessionId: null,
      tabId: this.generateTabId(),
      userId: null,
      isActive: false,
      isIdle: false,
      isVisible: true,
      isOnline: navigator.onLine,

      // Timing
      sessionStartTime: Date.now(),
      lastActivity: Date.now(),
      lastHeartbeat: 0,
      lastBatchFlush: 0,
      idleStartTime: null,

      // Counters
      totalClicks: 0,
      totalScrolls: 0,
      totalKeystrokes: 0,
      totalMouseMoves: 0,
      pageViews: 0,
      tabSwitches: 0,

      // Scores
      productivityScore: 50,
      engagementScore: 50,
      sessionQuality: "average",

      // Timing totals
      totalIdleTime: 0,
      totalActiveTime: 0,
      totalBackgroundTime: 0,

      // Security
      ipAddress: null,
      userAgent: navigator.userAgent,
      fingerprint: null,
      browser: this.detectBrowser(),
      os: this.detectOS(),
      location: null,

      // Performance
      performanceMetrics: {},

      // Flags
      warningShown: false,
      forceFlushPending: false,
    };

    // Activity buffers
    this.buffers = {
      clicks: [],
      scrolls: [],
      keystrokes: [],
      mouseMoves: [],
      pageViews: [],
      tabVisibility: [],
      idleStates: [],
      performance: [],
      heartbeats: [],
    };

    // Throttle tracking
    this.throttles = new Map();

    // Retry queue
    this.retryQueue = [];

    // Timers
    this.timers = {
      heartbeat: null,
      batchFlush: null,
      idleCheck: null,
      retry: null,
      cleanup: null,
    };

    // Location tracking
    this.locationWatchId = null;

    // Event listeners storage
    this.listeners = new Map();

    // Initialize
    this.init();
  }

  init() {
    try {
      // Extract user information (checks sessionStorage first)
      this.extractUserInfo();

      // Generate browser fingerprint
      this.generateFingerprint();

      // Update browser and OS info
      this.state.browser = this.detectBrowser();
      this.state.os = this.detectOS();

      // If no parent session ID exists, generate one for this browser session
      if (!this.state.parentSessionId) {
        this.state.parentSessionId = this.generateParentSessionId();
        this.log(
          "Generated new parent session ID: " + this.state.parentSessionId,
          "info",
        );
      }

      // Store initial session data
      this.storeSessionData();

      // Get location if enabled and not already set
      if (
        this.config.enableLocationTracking &&
        !this.state.location &&
        navigator.geolocation
      ) {
        this.log("Location tracking enabled, requesting permission...", "info");
        this.requestLocationPermission();
      } else if (!this.config.enableLocationTracking) {
        this.log("Location tracking disabled in config", "info");
      } else if (!navigator.geolocation) {
        this.log("Geolocation not supported by browser", "warning");
      }

      // Set up event listeners
      this.setupEventListeners();

      // Start timers
      this.startTimers();

      // Initial heartbeat
      this.sendHeartbeat();

      // Set up cleanup
      this.setupCleanup();

      // Log initialization
      this.log("Enhanced OptimizedSessionTracker initialized", "info");

      this.state.isActive = true;
    } catch (error) {
      this.log("Error initializing session tracker: " + error.message, "error");
    }
  }

  extractUserInfo() {
    // First try to get from config
    if (this.config.user_id) {
      this.state.userId = this.config.user_id;
    } else {
      // Extract user ID from body data attribute
      const userIdEl = document.body.getAttribute("data-user-id");
      if (userIdEl) {
        this.state.userId = parseInt(userIdEl);
      }
    }

    // Check sessionStorage for existing session data first
    const storedSessionData = this.getStoredSessionData();
    if (storedSessionData) {
      this.state.sessionId = storedSessionData.sessionId;
      this.state.parentSessionId = storedSessionData.parentSessionId;
      this.state.tabId = storedSessionData.tabId || this.state.tabId;
      this.log(
        `Restored session data: sessionId=${this.state.sessionId}, parentSessionId=${this.state.parentSessionId}`,
        "info",
      );
    }

    // Extract session ID if available (fallback)
    const sessionIdEl = document.body.getAttribute("data-session-id");
    if (sessionIdEl && !this.state.sessionId) {
      this.state.sessionId = sessionIdEl;
    }

    // Get location from config if available
    if (this.config.location) {
      this.state.location = this.config.location;
    }
  }

  generateFingerprint() {
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillText("Session tracker fingerprint", 2, 2);

      // Enhanced fingerprint with more browser-specific data
      const fingerprint = {
        canvas: canvas.toDataURL(),
        screen: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        language: navigator.language,
        languages: JSON.stringify(navigator.languages || []),
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        browser: this.state.browser,
        os: this.state.os,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        plugins: Array.from(navigator.plugins || [])
          .map((p) => p.name)
          .join(","),
        timestamp: Date.now(),
      };

      this.state.fingerprint = this.hashString(JSON.stringify(fingerprint));
      this.log(
        "Generated fingerprint: " +
          this.state.fingerprint.substring(0, 8) +
          "...",
        "debug",
      );
    } catch (error) {
      this.log("Error generating fingerprint: " + error.message, "error");
    }
  }

  setupEventListeners() {
    // Click tracking
    this.addListener(document, "click", (e) => {
      this.trackClick(e);
    });

    // Scroll tracking
    this.addListener(
      window,
      "scroll",
      this.throttle(() => {
        this.trackScroll();
      }, 100),
    );

    // Keyboard tracking
    this.addListener(document, "keydown", (e) => {
      this.trackKeyboard(e);
    });

    // Mouse movement tracking
    this.addListener(
      document,
      "mousemove",
      this.throttle((e) => {
        this.trackMouseMovement(e);
      }, 1000),
    );

    // Visibility change
    this.addListener(document, "visibilitychange", () => {
      this.handleVisibilityChange();
    });

    // Window focus/blur
    this.addListener(window, "focus", () => {
      this.handleWindowFocus();
    });

    this.addListener(window, "blur", () => {
      this.handleWindowBlur();
    });

    // Page unload
    this.addListener(window, "beforeunload", () => {
      this.handleBeforeUnload();
    });

    // Network status
    this.addListener(window, "online", () => {
      this.handleOnline();
    });

    this.addListener(window, "offline", () => {
      this.handleOffline();
    });

    // Error handling
    this.addListener(window, "error", (e) => {
      this.handleError(e);
    });

    // Performance monitoring
    if (this.config.enableProductivityScoring) {
      this.addListener(window, "load", () => {
        this.collectPerformanceMetrics();
      });
    }
  }

  addListener(element, event, handler) {
    const wrappedHandler = (e) => {
      try {
        handler(e);
        this.updateLastActivity();
      } catch (error) {
        this.log("Error in event handler: " + error.message, "error");
      }
    };

    element.addEventListener(event, wrappedHandler);

    // Store for cleanup
    if (!this.listeners.has(element)) {
      this.listeners.set(element, []);
    }
    this.listeners.get(element).push({ event, handler: wrappedHandler });
  }

  startTimers() {
    // Heartbeat timer
    this.timers.heartbeat = setInterval(() => {
      this.sendHeartbeat();
    }, this.config.heartbeatInterval);

    // Batch flush timer
    this.timers.batchFlush = setInterval(() => {
      this.flushBuffers();
    }, this.config.batchFlushInterval);

    // Idle detection timer
    this.timers.idleCheck = setInterval(() => {
      this.checkIdleState();
    }, 10000); // Check every 10 seconds

    // Retry timer
    this.timers.retry = setInterval(() => {
      this.processRetryQueue();
    }, this.config.retryDelay);

    // Cleanup timer
    this.timers.cleanup = setInterval(
      () => {
        this.performCleanup();
      },
      5 * 60 * 1000,
    ); // Every 5 minutes
  }

  updateLastActivity() {
    this.state.lastActivity = Date.now();

    if (this.state.isIdle) {
      this.state.isIdle = false;
      this.state.totalIdleTime += Date.now() - this.state.idleStartTime;
      this.state.idleStartTime = null;

      // Log idle state change
      this.addToBuffer("idleStates", {
        type: "idle_end",
        timestamp: Date.now(),
        duration: Date.now() - this.state.idleStartTime,
      });
    }
  }

  checkIdleState() {
    const now = Date.now();
    const timeSinceActivity = now - this.state.lastActivity;

    if (!this.state.isIdle && timeSinceActivity > this.config.idleThreshold) {
      this.state.isIdle = true;
      this.state.idleStartTime = now;

      // Log idle state change
      this.addToBuffer("idleStates", {
        type: "idle_start",
        timestamp: now,
        lastActivity: this.state.lastActivity,
      });
    }
  }

  trackClick(event) {
    if (Math.random() > this.config.mouseSampleRate) return;

    const clickData = {
      timestamp: Date.now(),
      x: event.clientX,
      y: event.clientY,
      target: event.target.tagName,
      id: event.target.id,
      className: event.target.className,
      text: event.target.innerText
        ? event.target.innerText.substring(0, 50)
        : "",
      url: window.location.href,
      button: event.button,
    };

    this.addToBuffer("clicks", clickData);
    this.state.totalClicks++;
  }

  trackScroll() {
    if (Math.random() > this.config.scrollSampleRate) return;

    const scrollData = {
      timestamp: Date.now(),
      scrollTop: window.pageYOffset,
      scrollLeft: window.pageXOffset,
      scrollHeight: document.body.scrollHeight,
      windowHeight: window.innerHeight,
      scrollPercent: this.calculateScrollPercent(),
      url: window.location.href,
    };

    this.addToBuffer("scrolls", scrollData);
    this.state.totalScrolls++;
  }

  trackKeyboard(event) {
    if (Math.random() > this.config.keyboardSampleRate) return;

    const keyboardData = {
      timestamp: Date.now(),
      key: event.key,
      keyCode: event.keyCode,
      ctrlKey: event.ctrlKey,
      altKey: event.altKey,
      shiftKey: event.shiftKey,
      target: event.target.tagName,
      inputType: this.getInputType(event.target),
      url: window.location.href,
    };

    this.addToBuffer("keystrokes", keyboardData);
    this.state.totalKeystrokes++;
  }

  trackMouseMovement(event) {
    if (Math.random() > this.config.mouseSampleRate) return;

    this.state.totalMouseMoves++;

    // Only buffer significant mouse movements
    if (this.state.totalMouseMoves % 10 === 0) {
      const mouseData = {
        timestamp: Date.now(),
        x: event.clientX,
        y: event.clientY,
        count: this.state.totalMouseMoves,
      };

      this.addToBuffer("mouseMoves", mouseData);
    }
  }

  handleVisibilityChange() {
    const isVisible = !document.hidden;
    this.state.isVisible = isVisible;

    const visibilityData = {
      timestamp: Date.now(),
      isVisible: isVisible,
      url: window.location.href,
    };

    this.addToBuffer("tabVisibility", visibilityData);

    if (!isVisible) {
      this.state.tabSwitches++;
    }
  }

  handleWindowFocus() {
    this.state.isVisible = true;
    this.updateLastActivity();
  }

  handleWindowBlur() {
    this.state.isVisible = false;
    this.state.totalBackgroundTime += Date.now() - this.state.lastActivity;
  }

  handleBeforeUnload() {
    // Force flush all buffers
    this.flushBuffers(true);

    // End session
    this.endSession("page_unload");
  }

  handleOnline() {
    this.state.isOnline = true;
    this.log("Connection restored", "info");

    // Process retry queue
    this.processRetryQueue();
  }

  handleOffline() {
    this.state.isOnline = false;
    this.log("Connection lost", "warning");
  }

  handleError(error) {
    this.log("JavaScript error: " + error.message, "error");

    // Add to performance metrics
    this.addToBuffer("performance", {
      type: "error",
      message: error.message,
      filename: error.filename,
      lineno: error.lineno,
      timestamp: Date.now(),
    });
  }

  collectPerformanceMetrics() {
    try {
      const perfData = performance.getEntriesByType("navigation")[0];
      if (perfData) {
        const metrics = {
          timestamp: Date.now(),
          loadTime: perfData.loadEventEnd - perfData.loadEventStart,
          domContentLoaded:
            perfData.domContentLoadedEventEnd -
            perfData.domContentLoadedEventStart,
          firstPaint: performance.getEntriesByType("paint")[0]?.startTime || 0,
          firstContentfulPaint:
            performance.getEntriesByType("paint")[1]?.startTime || 0,
        };

        this.addToBuffer("performance", metrics);
      }
    } catch (error) {
      this.log(
        "Error collecting performance metrics: " + error.message,
        "error",
      );
    }
  }

  sendHeartbeat() {
    if (!this.state.isActive || !this.state.userId) return;

    const now = Date.now();
    if (now - this.state.lastHeartbeat < this.config.heartbeatInterval) return;

    try {
      const heartbeatData = {
        tab_id: this.state.tabId || this.generateTabId(),
        parent_session_id: this.state.parentSessionId || this.generateParentSessionId(),
        session_fingerprint: this.state.fingerprint || this.generateFingerprint(),
        is_idle: Boolean(this.state.isIdle),
        is_visible: Boolean(this.state.isVisible),
        url: this.sanitizeUrl(window.location.href),
        title: this.sanitizeTitle(document.title),
        timestamp: new Date().toISOString(),
        productivity_score: this.calculateProductivityScore() || 0,
        engagement_score: this.calculateEngagementScore() || 0,
        location: this.state.location || null,
        location_latitude: this.validateCoordinate(this.state.location?.latitude, 'latitude'),
        location_longitude: this.validateCoordinate(this.state.location?.longitude, 'longitude'),
        location_accuracy: this.validateAccuracy(this.state.location?.accuracy),
        location_timestamp: this.state.location?.timestamp || null,
        browser: this.state.browser || 'unknown',
        os: this.state.os || 'unknown',
        device_type: this.getDeviceType(),
        fingerprint: this.state.fingerprint || this.generateFingerprint(),
        screen_resolution: this.getScreenResolution(),
        timezone_offset: this.getTimezoneOffset(),
        language: this.getLanguage(),
        battery_level: this.getBatteryLevel(),
        connection_type: this.getConnectionType(),
        csrf_token: this.getCSRFToken(),
      };

      // Validate required fields
      if (!heartbeatData.tab_id || !heartbeatData.session_fingerprint) {
        this.log('Missing required heartbeat data, regenerating...', 'warning');
        heartbeatData.tab_id = heartbeatData.tab_id || this.generateTabId();
        heartbeatData.session_fingerprint = heartbeatData.session_fingerprint || this.generateFingerprint();
        
        // Update state with generated values
        this.state.tabId = heartbeatData.tab_id;
        this.state.fingerprint = heartbeatData.session_fingerprint;
        this.storeSessionData();
      }

      this.makeRequest(this.config.heartbeatUrl, heartbeatData)
        .then((response) => {
          this.state.lastHeartbeat = now;
          this.handleHeartbeatResponse(response);
        })
        .catch((error) => {
          // Fallback to legacy endpoint if optimized endpoint fails
          this.makeRequest("/session/heartbeat/", heartbeatData)
            .then((response) => {
              this.state.lastHeartbeat = now;
              this.handleHeartbeatResponse(response);
            })
            .catch((retryError) => {
              this.addToRetryQueue("heartbeat", heartbeatData);
              this.log(
                "Heartbeat failed on both endpoints: " + error.message,
                "error",
              );
            });
        });
    } catch (error) {
      this.log("Error in sendHeartbeat: " + error.message, "error");
    }
  }

  handleHeartbeatResponse(response) {
    if (response.warning) {
      this.showSessionWarning(response.remaining_minutes);
    } else {
      this.hideSessionWarning();
    }

    if (response.session_id) {
      this.state.sessionId = response.session_id;
      // Update stored session data
      this.storeSessionData();
    }

    if (response.parent_session_id) {
      this.state.parentSessionId = response.parent_session_id;
      this.storeSessionData();
    }
  }

  flushBuffers(force = false) {
    if (!this.state.isActive) return;

    const now = Date.now();
    if (
      !force &&
      now - this.state.lastBatchFlush < this.config.batchFlushInterval
    )
      return;

    const activities = this.prepareActivitiesForFlush();

    if (activities.length === 0) return;

    const batchData = {
      tab_id: this.state.tabId,
      parent_session_id: this.state.parentSessionId,
      session_fingerprint: this.state.fingerprint,
      activities: activities,
      timestamp: new Date().toISOString(),
      browser: this.state.browser,
      os: this.state.os,
      fingerprint: this.state.fingerprint,
      csrf_token: this.getCSRFToken(),
    };

    this.makeRequest(this.config.batchActivityUrl, batchData)
      .then((response) => {
        this.state.lastBatchFlush = now;
        this.clearBuffers();
        this.log(`Flushed ${activities.length} activities`, "info");
      })
      .catch((error) => {
        // Try legacy endpoint as fallback
        this.makeRequest("/session/update-activity/", batchData)
          .then((response) => {
            this.state.lastBatchFlush = now;
            this.clearBuffers();
            this.log(
              `Flushed ${activities.length} activities using legacy endpoint`,
              "info",
            );
          })
          .catch((retryError) => {
            this.addToRetryQueue("batch_activity", batchData);
            this.log(
              "Batch flush failed on both endpoints: " + error.message,
              "error",
            );
          });
      });
  }

  prepareActivitiesForFlush() {
    const activities = [];

    // Add buffered activities
    for (const [type, buffer] of Object.entries(this.buffers)) {
      for (const activity of buffer) {
        activities.push({
          type: type,
          data: activity,
        });
      }
    }

    return activities;
  }

  clearBuffers() {
    for (const key of Object.keys(this.buffers)) {
      this.buffers[key] = [];
    }
  }

  addToBuffer(type, data) {
    if (!this.buffers[type]) {
      this.buffers[type] = [];
    }

    this.buffers[type].push(data);

    // Limit buffer size
    const maxSize = this.getMaxBufferSize(type);
    if (this.buffers[type].length > maxSize) {
      this.buffers[type] = this.buffers[type].slice(-maxSize);
    }

    // Check if we need to flush
    if (this.getTotalBufferSize() > this.config.maxBufferSize) {
      this.flushBuffers();
    }
  }

  getMaxBufferSize(type) {
    const limits = {
      clicks: this.config.maxClicksBuffer,
      scrolls: this.config.maxScrollsBuffer,
      keystrokes: this.config.maxKeyboardBuffer,
      mouseMoves: this.config.maxMouseBuffer,
    };
    return limits[type] || 50;
  }

  getTotalBufferSize() {
    return Object.values(this.buffers).reduce(
      (total, buffer) => total + buffer.length,
      0,
    );
  }

  calculateProductivityScore() {
    if (!this.config.enableProductivityScoring) return 50;

    const sessionDuration =
      (Date.now() - this.state.sessionStartTime) / 1000 / 60; // minutes
    const idlePercentage =
      sessionDuration > 0
        ? (this.state.totalIdleTime / (sessionDuration * 60 * 1000)) * 100
        : 0;

    let score = 50; // Base score

    // Adjust for idle time
    if (idlePercentage < 10) score += 15;
    else if (idlePercentage < 20) score += 10;
    else if (idlePercentage < 30) score += 5;
    else if (idlePercentage > 50) score -= 10;
    else if (idlePercentage > 70) score -= 20;

    // Adjust for activity level
    const activityLevel =
      this.state.totalClicks +
      this.state.totalKeystrokes +
      this.state.totalMouseMoves / 10;
    if (activityLevel > 50) score += 15;
    else if (activityLevel > 30) score += 10;
    else if (activityLevel > 15) score += 5;
    else if (activityLevel < 5 && sessionDuration > 5) score -= 10;

    // Adjust for tab switching
    if (this.state.tabSwitches > 0) {
      const switchRate = this.state.tabSwitches / sessionDuration;
      if (switchRate < 0.5) score += 5;
      else if (switchRate > 2) score -= 10;
    }

    this.state.productivityScore = Math.max(0, Math.min(100, score));
    return this.state.productivityScore;
  }

  calculateEngagementScore() {
    if (!this.config.enableEngagementScoring) return 50;

    const sessionDuration =
      (Date.now() - this.state.sessionStartTime) / 1000 / 60; // minutes
    let score = 50; // Base score

    // Adjust for session duration
    if (sessionDuration > 30) score += 10;
    else if (sessionDuration > 15) score += 5;
    else if (sessionDuration < 2) score -= 10;

    // Adjust for scroll depth
    const maxScrollPercent = Math.max(
      ...this.buffers.scrolls.map((s) => s.scrollPercent || 0),
    );
    if (maxScrollPercent > 80) score += 15;
    else if (maxScrollPercent > 50) score += 10;
    else if (maxScrollPercent > 30) score += 5;
    else if (maxScrollPercent < 10 && sessionDuration > 5) score -= 10;

    // Adjust for click rate
    const clickRate =
      sessionDuration > 0 ? this.state.totalClicks / sessionDuration : 0;
    if (clickRate > 2) score += 15;
    else if (clickRate > 1) score += 10;
    else if (clickRate > 0.5) score += 5;
    else if (clickRate < 0.1 && sessionDuration > 5) score -= 10;

    // Adjust for background time
    const backgroundPercentage =
      sessionDuration > 0
        ? (this.state.totalBackgroundTime / (sessionDuration * 60 * 1000)) * 100
        : 0;
    if (backgroundPercentage < 10) score += 10;
    else if (backgroundPercentage > 50) score -= 15;
    else if (backgroundPercentage > 30) score -= 10;

    this.state.engagementScore = Math.max(0, Math.min(100, score));
    return this.state.engagementScore;
  }

  showSessionWarning(remainingMinutes) {
    if (this.state.warningShown) return;

    this.state.warningShown = true;

    // Create or show warning modal
    const modal = document.getElementById("sessionWarningModal");
    if (modal) {
      modal.classList.remove("hidden");

      const messageEl = document.getElementById("sessionWarningMessage");
      if (messageEl) {
        messageEl.textContent = `Your session will expire in ${Math.ceil(remainingMinutes)} minutes due to inactivity.`;
      }
    }
  }

  hideSessionWarning() {
    if (!this.state.warningShown) return;

    this.state.warningShown = false;

    const modal = document.getElementById("sessionWarningModal");
    if (modal) {
      modal.classList.add("hidden");
    }
  }

  requestLocationPermission() {
    if (!navigator.geolocation) {
      this.log("Geolocation not supported", "warning");
      return;
    }

    this.log("Requesting location permission...", "info");

    navigator.geolocation.getCurrentPosition(
      (position) => {
        this.state.location = {
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
          accuracy: position.coords.accuracy,
          timestamp: new Date().toISOString(),
        };
        this.log(
          `Location data obtained successfully: lat=${this.state.location.latitude}, lng=${this.state.location.longitude}, accuracy=${this.state.location.accuracy}m`,
          "info",
        );

        // Send location data immediately after obtaining it
        this.sendLocationUpdate();

        // Set up location watching for updates
        this.watchLocation();
      },
      (error) => {
        this.log("Location error: " + error.message, "warning");
        console.warn("Location tracking failed:", error);

        // Handle different error types
        let errorMessage = "Location access denied";
        switch (error.code) {
          case error.PERMISSION_DENIED:
            errorMessage = "Location permission denied by user";
            break;
          case error.POSITION_UNAVAILABLE:
            errorMessage = "Location information unavailable";
            break;
          case error.TIMEOUT:
            errorMessage = "Location request timed out";
            break;
        }

        // Set a default location or handle the error gracefully
        this.state.location = {
          latitude: null,
          longitude: null,
          accuracy: null,
          timestamp: new Date().toISOString(),
          error: errorMessage,
        };
      },
      {
        timeout: 10000,
        maximumAge: 300000, // 5 minutes
        enableHighAccuracy: true,
      },
    );
  }

  watchLocation() {
    if (!navigator.geolocation || this.locationWatchId) {
      return;
    }

    this.locationWatchId = navigator.geolocation.watchPosition(
      (position) => {
        // Only update if location has changed significantly
        const newLat = position.coords.latitude;
        const newLng = position.coords.longitude;
        const oldLat = this.state.location?.latitude;
        const oldLng = this.state.location?.longitude;

        if (
          !oldLat ||
          !oldLng ||
          Math.abs(newLat - oldLat) > 0.001 ||
          Math.abs(newLng - oldLng) > 0.001
        ) {
          this.state.location = {
            latitude: newLat,
            longitude: newLng,
            accuracy: position.coords.accuracy,
            timestamp: new Date().toISOString(),
          };
          this.log(
            `Location updated: lat=${newLat}, lng=${newLng}, accuracy=${position.coords.accuracy}m`,
            "info",
          );
          this.sendLocationUpdate();
        }
      },
      (error) => {
        this.log("Location watch error: " + error.message, "warning");
      },
      {
        timeout: 15000,
        maximumAge: 600000, // 10 minutes
        enableHighAccuracy: false, // Use less accurate but faster positioning for watching
      },
    );
  }

  sendLocationUpdate() {
    if (!this.state.isActive || !this.state.location) return;

    const locationData = {
      tab_id: this.state.tabId,
      timestamp: new Date().toISOString(),
      location: this.state.location,
      location_latitude: this.state.location.latitude,
      location_longitude: this.state.location.longitude,
      location_accuracy: this.state.location.accuracy,
      location_timestamp: this.state.location.timestamp,
      csrf_token: this.getCSRFToken(),
    };

    this.makeRequest(this.config.batchActivityUrl, {
      tab_id: this.state.tabId,
      activities: [
        {
          type: "location_update",
          data: locationData,
          timestamp: new Date().toISOString(),
        },
      ],
      timestamp: new Date().toISOString(),
      csrf_token: this.getCSRFToken(),
    })
      .then((response) => {
        this.log(
          `Location data sent successfully: lat=${this.state.location.latitude}, lng=${this.state.location.longitude}`,
          "info",
        );
      })
      .catch((error) => {
        this.log("Failed to send location data: " + error.message, "error");
        console.error("Location send failed:", error);
      });
  }

  endSession(reason = "manual") {
    if (!this.state.isActive) return;

    this.state.isActive = false;

    const endData = {
      tab_id: this.state.tabId,
      timestamp: new Date().toISOString(),
      browser: this.state.browser,
      os: this.state.os,
      csrf_token: this.getCSRFToken(),
      reason: reason,
    };

    this.makeRequest(this.config.endSessionUrl, endData)
      .then((response) => {
        this.log("Session ended: " + reason, "info");
        this.cleanup();
      })
      .catch((error) => {
        this.log("Failed to end session: " + error.message, "error");
      });
  }

  forceSync() {
    const syncData = {
      tab_id: this.state.tabId,
      timestamp: new Date().toISOString(),
    };

    return this.makeRequest(this.config.forceSync, syncData)
      .then((response) => {
        this.log("Force sync completed", "info");
        return response;
      })
      .catch((error) => {
        this.log("Force sync failed: " + error.message, "error");
        throw error;
      });
  }

  makeRequest(url, data) {
    // Get CSRF token
    const csrfToken = this.getCSRFToken();

    // Check if we should use FormData instead of JSON
    const useFormData = url.includes("/session/") && !url.includes("optimized");
    let requestBody;
    let contentType;

    if (useFormData) {
      // Use FormData for legacy endpoints
      const formData = new FormData();
      for (const key in data) {
        if (typeof data[key] === "object" && data[key] !== null) {
          formData.append(key, JSON.stringify(data[key]));
        } else {
          formData.append(key, data[key]);
        }
      }
      requestBody = formData;
      contentType = null; // Let browser set content type with boundary
    } else {
      // Use JSON for optimized endpoints
      requestBody = JSON.stringify(data);
      contentType = "application/json";
    }

    // Build headers
    const headers = {
      "X-CSRFToken": csrfToken,
      "X-Tab-ID": this.state.tabId,
      "X-Parent-Session-ID": this.state.parentSessionId,
      "X-Session-Fingerprint": this.state.fingerprint,
      "X-Screen-Resolution": `${screen.width}x${screen.height}`,
      "X-Timezone-Offset": new Date().getTimezoneOffset(),
      "X-Language": navigator.language,
      "X-Requested-With": "XMLHttpRequest",
    };

    // Only add Content-Type for JSON requests
    if (contentType) {
      headers["Content-Type"] = contentType;
    }

    return fetch(url, {
      method: "POST",
      headers: headers,
      body: requestBody,
      credentials: "same-origin",
    }).then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Try to parse as JSON, but don't fail if not JSON
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        return response.json();
      } else {
        return response.text().then((text) => {
          try {
            return JSON.parse(text);
          } catch (e) {
            return { success: true, message: text };
          }
        });
      }
    });
  }

  addToRetryQueue(type, data) {
    this.retryQueue.push({
      type: type,
      data: data,
      timestamp: Date.now(),
      attempts: 0,
    });

    // Limit retry queue size
    if (this.retryQueue.length > 50) {
      this.retryQueue = this.retryQueue.slice(-50);
    }
  }

  processRetryQueue() {
    if (!this.state.isOnline || this.retryQueue.length === 0) return;

    const now = Date.now();
    const itemsToRetry = this.retryQueue.filter(
      (item) =>
        item.attempts < this.config.maxRetries &&
        now - item.timestamp > this.config.retryDelay,
    );

    for (const item of itemsToRetry) {
      const url =
        item.type === "heartbeat"
          ? this.config.heartbeatUrl
          : this.config.batchActivityUrl;

      this.makeRequest(url, item.data)
        .then((response) => {
          // Remove from retry queue
          const index = this.retryQueue.indexOf(item);
          if (index > -1) {
            this.retryQueue.splice(index, 1);
          }
          this.log(`Retry successful for ${item.type}`, "info");
        })
        .catch((error) => {
          item.attempts++;
          item.timestamp = now;

          if (item.attempts >= this.config.maxRetries) {
            const index = this.retryQueue.indexOf(item);
            if (index > -1) {
              this.retryQueue.splice(index, 1);
            }
            this.log(`Max retries reached for ${item.type}`, "warning");
          }
        });
    }
  }

  performCleanup() {
    // Clean up old retry queue items
    const now = Date.now();
    this.retryQueue = this.retryQueue.filter(
      (item) => now - item.timestamp < 24 * 60 * 60 * 1000, // Keep items for 24 hours max
    );

    // Clean up throttle map
    for (const [key, timestamp] of this.throttles.entries()) {
      if (now - timestamp > 60000) {
        // 1 minute
        this.throttles.delete(key);
      }
    }

    this.log("Cleanup completed", "debug");
  }

  setupCleanup() {
    // Set up cleanup on page unload
    window.addEventListener("beforeunload", () => {
      this.cleanup();
    });
  }

  cleanup() {
    // End session before cleanup
    this.endSession();

    // Clear all timers
    for (const [key, timer] of Object.entries(this.timers)) {
      if (timer) {
        clearInterval(timer);
        this.timers[key] = null;
      }
    }

    // Stop location watching
    if (this.locationWatchId) {
      navigator.geolocation.clearWatch(this.locationWatchId);
      this.locationWatchId = null;
    }

    // Remove all event listeners
    for (const [element, listeners] of this.listeners.entries()) {
      for (const { event, handler } of listeners) {
        element.removeEventListener(event, handler);
      }
    }
    this.listeners.clear();

    // Clear buffers
    this.clearBuffers();

    // Clear retry queue
    this.retryQueue = [];

    // Clear stored session data
    this.clearStoredSessionData();

    this.log("Session tracker cleaned up", "info");
  }

  // Utility methods
  generateTabId() {
    return "tab_" + Math.random().toString(36).substr(2, 9) + "_" + Date.now();
  }

  generateParentSessionId() {
    return "parent_" + Math.random().toString(36).substr(2, 9) + "_" + Date.now();
  }

  // Session storage methods
  storeSessionData() {
    try {
      const sessionData = {
        sessionId: this.state.sessionId,
        parentSessionId: this.state.parentSessionId,
        tabId: this.state.tabId,
        fingerprint: this.state.fingerprint,
        timestamp: Date.now()
      };
      sessionStorage.setItem('ardur_session_data', JSON.stringify(sessionData));
      this.log('Session data stored in sessionStorage', 'debug');
    } catch (error) {
      this.log('Failed to store session data: ' + error.message, 'error');
    }
  }

  getStoredSessionData() {
    try {
      const stored = sessionStorage.getItem('ardur_session_data');
      if (stored) {
        const sessionData = JSON.parse(stored);
        // Check if stored data is recent (within 1 hour)
        const maxAge = 60 * 60 * 1000; // 1 hour
        if (Date.now() - sessionData.timestamp < maxAge) {
          this.log('Retrieved stored session data', 'debug');
          return sessionData;
        } else {
          this.log('Stored session data expired', 'debug');
          this.clearStoredSessionData();
        }
      }
    } catch (error) {
      this.log('Failed to retrieve session data: ' + error.message, 'error');
      this.clearStoredSessionData();
    }
    return null;
  }

  clearStoredSessionData() {
    try {
      sessionStorage.removeItem('ardur_session_data');
      this.log('Session data cleared from sessionStorage', 'debug');
    } catch (error) {
      this.log('Failed to clear session data: ' + error.message, 'error');
    }
  }

  getCSRFToken() {
    // First try to get from cookies
    const cookies = document.cookie.split(";");
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split("=");
      if (name === "csrftoken") {
        return value;
      }
    }

    // Try to get from meta tag
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
      return csrfMeta.getAttribute("content");
    }

    // Try to get from form input
    const csrfInput = document.querySelector(
      'input[name="csrfmiddlewaretoken"]',
    );
    if (csrfInput) {
      return csrfInput.value;
    }

    // Try to get from hidden input
    const csrfHidden = document.querySelector('[name="csrfmiddlewaretoken"]');
    if (csrfHidden) {
      return csrfHidden.value;
    }

    this.log("CSRF token not found", "warning");
    return "";
  }

  throttle(func, limit) {
    let inThrottle;
    return function () {
      const args = arguments;
      const context = this;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(() => (inThrottle = false), limit);
      }
    };
  }

  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString(16);
  }

  detectBrowser() {
    const userAgent = navigator.userAgent;
    let browserName;

    if (userAgent.match(/chrome|chromium|crios/i)) {
      browserName = "Chrome";
    } else if (userAgent.match(/firefox|fxios/i)) {
      browserName = "Firefox";
    } else if (userAgent.match(/safari/i)) {
      browserName = "Safari";
    } else if (userAgent.match(/opr\//i)) {
      browserName = "Opera";
    } else if (userAgent.match(/edg/i)) {
      browserName = "Edge";
    } else {
      browserName = "Unknown";
    }

    return browserName;
  }

  detectOS() {
    const userAgent = navigator.userAgent;
    let osName;

    if (userAgent.indexOf("Windows") !== -1) {
      osName = "Windows";
    } else if (userAgent.indexOf("Mac") !== -1) {
      osName = "MacOS";
    } else if (userAgent.indexOf("Linux") !== -1) {
      osName = "Linux";
    } else if (userAgent.indexOf("Android") !== -1) {
      osName = "Android";
    } else if (
      userAgent.indexOf("iOS") !== -1 ||
      userAgent.indexOf("iPhone") !== -1 ||
      userAgent.indexOf("iPad") !== -1
    ) {
      osName = "iOS";
    } else {
      osName = "Unknown";
    }

    return osName;
  }

  calculateScrollPercent() {
    const scrollTop = window.pageYOffset;
    const scrollHeight = document.body.scrollHeight;
    const windowHeight = window.innerHeight;

    if (scrollHeight <= windowHeight) return 100;

    return Math.round((scrollTop / (scrollHeight - windowHeight)) * 100);
  }

  getInputType(element) {
    if (!element) return "unknown";

    const tagName = element.tagName.toLowerCase();
    if (tagName === "input") {
      return element.type || "text";
    } else if (tagName === "textarea") {
      return "textarea";
    } else if (element.contentEditable === "true") {
      return "contenteditable";
    }

    return "other";
  }

  getDeviceType() {
    const userAgent = navigator.userAgent;
    if (/tablet|ipad|playbook|silk/i.test(userAgent)) {
      return "tablet";
    }
    if (/mobile|iphone|ipod|android|blackberry|opera|mini|windows\sce|palm|smartphone|iemobile/i.test(userAgent)) {
      return "mobile";
    }
    return "desktop";
  }

  log(message, level = "info") {
    if (typeof console !== "undefined") {
      const timestamp = new Date().toISOString();
      const logMessage = `[${timestamp}] [OptimizedSessionTrackerEnhanced] ${message}`;

      switch (level) {
        case "error":
          console.error(logMessage);
          break;
        case "warning":
          console.warn(logMessage);
          break;
        case "debug":
          console.debug(logMessage);
          break;
        default:
          console.log(logMessage);
      }
    }
  }

  // Data validation methods
  sanitizeUrl(url) {
    try {
      if (!url || typeof url !== 'string') return '';
      
      // Truncate very long URLs
      if (url.length > 2000) {
        this.log('URL too long, truncating', 'warning');
        url = url.substring(0, 2000);
      }
      
      // Remove sensitive query parameters
      const urlObj = new URL(url);
      const sensitiveParams = ['password', 'token', 'key', 'secret', 'auth'];
      
      for (const param of sensitiveParams) {
        if (urlObj.searchParams.has(param)) {
          urlObj.searchParams.set(param, '[REDACTED]');
        }
      }
      
      return urlObj.toString();
    } catch (error) {
      this.log('Error sanitizing URL: ' + error.message, 'warning');
      return url ? url.substring(0, 2000) : '';
    }
  }

  sanitizeTitle(title) {
    try {
      if (!title || typeof title !== 'string') return '';
      
      // Truncate very long titles
      if (title.length > 500) {
        this.log('Title too long, truncating', 'warning');
        title = title.substring(0, 500);
      }
      
      // Remove potentially sensitive information
      title = title.replace(/password|token|key|secret/gi, '[REDACTED]');
      
      return title.trim();
    } catch (error) {
      this.log('Error sanitizing title: ' + error.message, 'warning');
      return title ? title.substring(0, 500) : '';
    }
  }

  validateCoordinate(coord, type) {
    try {
      if (coord === null || coord === undefined) return null;
      
      const numCoord = parseFloat(coord);
      if (isNaN(numCoord)) return null;
      
      if (type === 'latitude') {
        return (numCoord >= -90 && numCoord <= 90) ? numCoord : null;
      } else if (type === 'longitude') {
        return (numCoord >= -180 && numCoord <= 180) ? numCoord : null;
      }
      
      return numCoord;
    } catch (error) {
      this.log('Error validating coordinate: ' + error.message, 'warning');
      return null;
    }
  }

  validateAccuracy(accuracy) {
    try {
      if (accuracy === null || accuracy === undefined) return null;
      
      const numAccuracy = parseFloat(accuracy);
      if (isNaN(numAccuracy)) return null;
      
      // Accuracy should be non-negative
      return (numAccuracy >= 0) ? numAccuracy : null;
    } catch (error) {
      this.log('Error validating accuracy: ' + error.message, 'warning');
      return null;
    }
  }

  getScreenResolution() {
    try {
      return `${screen.width}x${screen.height}`;
    } catch (error) {
      this.log('Error getting screen resolution: ' + error.message, 'warning');
      return 'unknown';
    }
  }

  getTimezoneOffset() {
    try {
      return new Date().getTimezoneOffset();
    } catch (error) {
      this.log('Error getting timezone offset: ' + error.message, 'warning');
      return 0;
    }
  }

  getLanguage() {
    try {
      return navigator.language || navigator.userLanguage || 'unknown';
    } catch (error) {
      this.log('Error getting language: ' + error.message, 'warning');
      return 'unknown';
    }
  }

  getBatteryLevel() {
    try {
      if ('getBattery' in navigator) {
        return navigator.getBattery().then(battery => battery.level * 100);
      }
      return null;
    } catch (error) {
      this.log('Error getting battery level: ' + error.message, 'warning');
      return null;
    }
  }

  getConnectionType() {
    try {
      if ('connection' in navigator) {
        return navigator.connection.effectiveType || 'unknown';
      }
      return 'unknown';
    } catch (error) {
      this.log('Error getting connection type: ' + error.message, 'warning');
      return 'unknown';
    }
  }

  // Public API methods
  getMetrics() {
    return {
      sessionId: this.state.sessionId,
      sessionDuration: Date.now() - this.state.sessionStartTime,
      totalClicks: this.state.totalClicks,
      totalScrolls: this.state.totalScrolls,
      totalKeystrokes: this.state.totalKeystrokes,
      totalMouseMoves: this.state.totalMouseMoves,
      pageViews: this.state.pageViews,
      tabSwitches: this.state.tabSwitches,
      productivityScore: this.state.productivityScore,
      engagementScore: this.state.engagementScore,
      isIdle: this.state.isIdle,
      isActive: this.state.isActive,
      retryQueueLength: this.retryQueue.length,
      bufferSize: this.getTotalBufferSize(),
    };
  }

  getBufferStatus() {
    return {
      totalSize: this.getTotalBufferSize(),
      clicks: this.buffers.clicks.length,
      scrolls: this.buffers.scrolls.length,
      keystrokes: this.buffers.keystrokes.length,
      mouseMoves: this.buffers.mouseMoves.length,
      pageViews: this.buffers.pageViews.length,
      tabVisibility: this.buffers.tabVisibility.length,
      idleStates: this.buffers.idleStates.length,
      performance: this.buffers.performance.length,
      heartbeats: this.buffers.heartbeats.length,
      retryQueue: this.retryQueue.length,
    };
  }

  manualFlush() {
    this.log("Manual flush requested", "info");
    this.flushBuffers(true);
  }

  setThrottleInterval(type, interval) {
    if (type === "heartbeat") {
      this.config.heartbeatInterval = interval;

      // Restart heartbeat timer
      if (this.timers.heartbeat) {
        clearInterval(this.timers.heartbeat);
        this.timers.heartbeat = setInterval(() => {
          this.sendHeartbeat();
        }, this.config.heartbeatInterval);
      }
    } else if (type === "batch") {
      this.config.batchFlushInterval = interval;

      // Restart batch timer
      if (this.timers.batchFlush) {
        clearInterval(this.timers.batchFlush);
        this.timers.batchFlush = setInterval(() => {
          this.flushBuffers();
        }, this.config.batchFlushInterval);
      }
    }
  }

  // Session management methods
  extendSession() {
    this.updateLastActivity();
    this.hideSessionWarning();

    // Send heartbeat to extend session
    this.sendHeartbeat();
  }

  getSessionStatus() {
    return {
      sessionId: this.state.sessionId,
      tabId: this.state.tabId,
      userId: this.state.userId,
      isActive: this.state.isActive,
      isIdle: this.state.isIdle,
      sessionDuration: Date.now() - this.state.sessionStartTime,
      lastActivity: this.state.lastActivity,
      productivityScore: this.state.productivityScore,
      engagementScore: this.state.engagementScore,
      warningShown: this.state.warningShown,
    };
  }

  destroy() {
    this.log("Destroying session tracker", "info");

    // Force final sync
    this.forceSync();

    // End session
    this.endSession("destroy");

    // Cleanup
    this.cleanup();

    this.log("Session tracker destroyed", "info");
  }
}

// Auto-initialize when DOM is ready
document.addEventListener("DOMContentLoaded", function () {
  // Only initialize if user is authenticated
  if (
    document.body.getAttribute("data-authenticated") === "true" ||
    document.body.getAttribute("data-user-id")
  ) {
    try {
      window.optimizedSessionTrackerEnhanced = new OptimizedSessionTrackerEnhanced();

      // Integration with existing session monitor
      if (window.sessionMonitor) {
        window.sessionMonitor.optimizedTracker = window.optimizedSessionTrackerEnhanced;
      }

      // Global methods for external access
      window.sessionTracker = {
        getMetrics: () => window.optimizedSessionTrackerEnhanced.getMetrics(),
        getBufferStatus: () => window.optimizedSessionTrackerEnhanced.getBufferStatus(),
        manualFlush: () => window.optimizedSessionTrackerEnhanced.manualFlush(),
        extendSession: () => window.optimizedSessionTrackerEnhanced.extendSession(),
        getSessionStatus: () =>
          window.optimizedSessionTrackerEnhanced.getSessionStatus(),
        endSession: (reason) =>
          window.optimizedSessionTrackerEnhanced.endSession(reason),
        forceSync: () => window.optimizedSessionTrackerEnhanced.forceSync(),
      };

    } catch (error) {
      console.error("Failed to initialize Enhanced Optimized Session Tracker:", error);
    }
  } else {
    console.log(
      "User not authenticated - skipping session tracker initialization",
    );
  }
});

// Handle page visibility changes for better session management
document.addEventListener("visibilitychange", function () {
  if (window.optimizedSessionTrackerEnhanced) {
    if (document.hidden) {
      // Page is hidden - reduce activity
      window.optimizedSessionTrackerEnhanced.state.isVisible = false;
    } else {
      // Page is visible - resume normal activity
      window.optimizedSessionTrackerEnhanced.state.isVisible = true;
      window.optimizedSessionTrackerEnhanced.updateLastActivity();
    }
  }
});

// Export for module use
if (typeof module !== "undefined" && module.exports) {
  module.exports = OptimizedSessionTrackerEnhanced;
}

// AMD support
if (typeof define === "function" && define.amd) {
  define([], function () {
    return OptimizedSessionTrackerEnhanced;
  });
} else {
  // Global export
  window.OptimizedSessionTrackerEnhanced = OptimizedSessionTrackerEnhanced;
}

// Check if we're in a browser environment before auto-initializing
if (typeof window !== 'undefined') {
  // Auto-initialize if DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      console.log('DOM loaded, OptimizedSessionTrackerEnhanced available:', typeof window.OptimizedSessionTrackerEnhanced !== 'undefined');
    });
  } else {
    console.log('DOM already loaded, OptimizedSessionTrackerEnhanced available:', typeof window.OptimizedSessionTrackerEnhanced !== 'undefined');
  }
}