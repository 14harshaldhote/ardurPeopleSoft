/*
 * Session Tracker - Comprehensive browser activity monitoring
 *
 * Features:
 * - Cross-tab session tracking
 * - Idle detection with auto-logout
 * - Performance monitoring
 * - Browser fingerprinting
 * - Location tracking
 * - URL frequency tracking
 * - Activity monitoring (clicks, keyboard, scrolls)
 */
/**
 * Calculate productivity score based on user activity
 * @param {object} state - The current session state object.
 */
window.SessionTracker = (function () {
  // Configuration
  const config = {
    idleThreshold: 5 * 60 * 1000, // 5 minutes in milliseconds
    autoLogoutThreshold: 30 * 60 * 1000, // 30 minutes in milliseconds
    warningThreshold: 25 * 60 * 1000, // 25 minutes in milliseconds
    heartbeatInterval: 30 * 1000, // 30 seconds in milliseconds
    activitySampleInterval: 5 * 1000, // 5 seconds in milliseconds
    performanceSampleInterval: 60 * 1000, // 1 minute in milliseconds
    storagePrefix: "trueAlign_",
    apiEndpoints: {
      createSession: "/api/session/create/",
      updateSession: "/api/session/update/",
      endSession: "/session/end/",
      checkSession: "/session/status/",
    },
    debug: false,
  };

  // State variables
  let state = {
    // Session identification
    sessionId: null,
    tabId: generateUUID(),
    parentSessionId: null,
    sessionStartTime: Date.now(),

    // Activity tracking
    lastActivity: Date.now(),
    isIdle: false,
    idleStartTime: null,
    idleWarningShown: false,
    isActive: true,
    total_idle_time: 0,
    working_time: 0,
    focus_time: 0,

    // Tab tracking
    tab_switches: 0,
    background_time: 0,
    backgroundStartTime: null,
    tab_opened_time: new Date().toISOString(),
    tab_last_focus: new Date().toISOString(),
    is_primary_tab: true,

    // Timers
    heartbeatTimer: null,
    activitySampleTimer: null,
    performanceSampleTimer: null,

    // Client information
    browserFingerprint: null,
    locationData: null,
    visitedUrls: {},
    currentUrl: window.location.href,
    currentTitle: document.title,
    referrer: document.referrer,

    // Activity buffers
    activityBuffer: {
      clicks: [],
      keystrokes: [],
      scrolls: [],
      mouseMoves: [],
      tabVisibility: [],
      idleStateChanges: [],
    },

    // Metrics
    performanceMetrics: {},
    productivity_score: null,
    engagement_score: null,
    session_quality: null,
    security_score: null,
    security_anomalies: [],

    // Device information
    deviceInfo: {
      batteryLevel: null,
      connectionType: null,
      screenResolution: `${window.screen.width}x${window.screen.height}`,
      deviceType: detectDeviceType(),
    },

    // Cross-tab communication
    relatedTabs: [],
    broadcast_messages_sent: 0,
    broadcast_messages_received: 0,
    cross_tab_activity_syncs: 0,

    // Security
    csrfToken: getCSRFToken(),
  };

  // Initialize cross-tab communication
  const broadcastChannel =
    typeof BroadcastChannel !== "undefined"
      ? new BroadcastChannel("trueAlign_session_channel")
      : null;

  /**
   * Initialize the session tracker
   */
  function init() {
    // Check for existing session in storage
    checkExistingSession();

    // Generate browser fingerprint
    generateFingerprint();

    // Get location data if available
    getLocationData();

    // Set up event listeners
    setupEventListeners();

    // Start timers
    startTimers();

    // Initialize device info
    initDeviceInfo();

    // Create or update session
    initializeSession();

    calculateScrollPercentage()
  }
  /**
   * Creates a throttled function that only invokes `func` at most once per
   * every `wait` milliseconds.
   *
   * @param {Function} func The function to throttle.
   * @param {number} wait The number of milliseconds to throttle invocations to.
   * @returns {Function} Returns the new throttled function.
   */
  function throttle(func, wait) {
    let context, args, result;
    let timeout = null;
    let previous = 0;

    const later = function () {
      previous = Date.now();
      timeout = null;
      result = func.apply(context, args);
      if (!timeout) context = args = null;
    };

    return function () {
      const now = Date.now();
      if (!previous) previous = now;
      const remaining = wait - (now - previous);
      context = this;
      args = arguments;

      if (remaining <= 0 || remaining > wait) {
        if (timeout) {
          clearTimeout(timeout);
          timeout = null;
        }
        previous = now;
        result = func.apply(context, args);
        if (!timeout) context = args = null;
      } else if (!timeout) {
        timeout = setTimeout(later, remaining);
      }

      return result;
    };
  }
  /**
   * Sample performance metrics and send to server
   */
  function samplePerformance() {
    if (!state.sessionId) return;

    // Collect performance metrics
    const metrics = {};

    // Navigation timing
    if (window.performance && window.performance.timing) {
      const timing = window.performance.timing;
      const navigationStart = timing.navigationStart;

      metrics.page_load = timing.loadEventEnd - navigationStart;
      metrics.dom_ready = timing.domComplete - navigationStart;
      metrics.first_paint = timing.responseStart - navigationStart;
      metrics.backend = timing.responseEnd - timing.requestStart;
      metrics.network_latency = timing.responseStart - timing.requestStart;
    }

    // Memory info
    if (window.performance && window.performance.memory) {
      metrics.memory = {
        used_js_heap: window.performance.memory.usedJSHeapSize,
        total_js_heap: window.performance.memory.totalJSHeapSize,
        js_heap_limit: window.performance.memory.jsHeapSizeLimit,
      };
    }

    // Resource timing
    if (window.performance && window.performance.getEntriesByType) {
      const resources = window.performance.getEntriesByType("resource");
      if (resources && resources.length > 0) {
        metrics.resources = {
          count: resources.length,
          total_size: resources.reduce(
            (sum, r) => sum + (r.transferSize || 0),
            0,
          ),
          avg_load_time:
            resources.reduce((sum, r) => sum + r.duration, 0) /
            resources.length,
        };
      }
    }

    // Calculate productivity and engagement scores
    calculateProductivityScore(state);
    calculateEngagementScore(state);

    // Update state and send to server
    state.performanceMetrics = { ...state.performanceMetrics, ...metrics };

    sendApiRequest(config.apiEndpoints.updateSession, {
      session_id: state.sessionId,
      performance_metrics: metrics,
      productivity_score: state.productivity_score,
      engagement_score: state.engagement_score,
      session_quality: state.session_quality,
    });
  }

  /**
   * Check for existing session in storage or URL parameters
   */
  function checkExistingSession() {
    // Check URL parameters first (for cross-domain support)
    const urlParams = new URLSearchParams(window.location.search);
    const sessionParam = urlParams.get("session_id");
    const parentSessionParam = urlParams.get("parent_session_id");

    if (sessionParam) {
      state.sessionId = sessionParam;
    }

    if (parentSessionParam) {
      state.parentSessionId = parentSessionParam;
    }

    // Check local storage
    if (!state.sessionId) {
      state.sessionId = localStorage.getItem(
        `${config.storagePrefix}sessionId`,
      );
    }

    if (!state.parentSessionId) {
      state.parentSessionId = localStorage.getItem(
        `${config.storagePrefix}parentSessionId`,
      );
    }

    // Check session storage for tab-specific data
    const storedTabId = sessionStorage.getItem(`${config.storagePrefix}tabId`);
    if (storedTabId) {
      state.tabId = storedTabId;
    } else {
      sessionStorage.setItem(`${config.storagePrefix}tabId`, state.tabId);
    }
  }

  /**
   * Initialize a new session or update existing one
   */
  function initializeSession() {
    const clientData = {
      tab_id: state.tabId,
      parent_session_id: state.parentSessionId,
      browser_fingerprint: state.browserFingerprint,
      ip_address: null, // Will be determined server-side
      user_agent: navigator.userAgent,
      device_type: state.deviceInfo.deviceType,
      screen_resolution: state.deviceInfo.screenResolution,
      timezone_offset: new Date().getTimezoneOffset(),
      language: navigator.language,
      url: state.currentUrl,
      title: state.currentTitle,
      referrer: state.referrer,
      location_data: state.locationData,
    };

    // Initialize tab-specific data
    const tabData = {
      tab_title: document.title,
      tab_url: window.location.href,
      tab_opened_time: new Date().toISOString(),
      tab_last_focus: new Date().toISOString(),
      is_primary_tab: !state.parentSessionId,
    };

    // Merge tab data into client data
    Object.assign(clientData, tabData);

    if (state.sessionId) {
      // Update existing session
      const updateData = {
        session_id: state.sessionId,
        client_data: clientData,
        last_activity: new Date().toISOString(),
        is_idle: state.isIdle,
        tab_visibility: {
          action: "session_update",
          timestamp: new Date().toISOString(),
          url: window.location.href,
        },
      };

      sendApiRequest(
        config.apiEndpoints.updateSession,
        updateData,
        handleSessionResponse,
      );
    } else {
      // Create new session
      const createData = {
        client_data: clientData,
      };

      sendApiRequest(
        config.apiEndpoints.createSession,
        createData,
        handleSessionResponse,
      );
    }
  }

  /**
   * Send API request
   */
  function sendApiRequest(endpoint, data, callback) {
    if (!endpoint) {
      console.error("Invalid endpoint for API request");
      if (callback) callback({ success: false, error: "Invalid endpoint" });
      return;
    }

    // Ensure session_id is included if available
    if (state.sessionId && !data.session_id) {
      data.session_id = state.sessionId;
    }

    // Add tab_id if available and not already included
    if (state.tabId && !data.tab_id) {
      data.tab_id = state.tabId;
    }

    // Add CSRF token
    data.csrfmiddlewaretoken = state.csrfToken;

    fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": state.csrfToken,
      },
      body: JSON.stringify(data),
      credentials: "same-origin",
    })
      .then((response) => response.json())
      .then((result) => {
        if (callback && typeof callback === "function") {
          callback(result);
        }
      })
      .catch((error) => {
        if (callback)
          callback({
            success: false,
            error: "Network error: " + error.message,
          });
      });
  }

  /**
   * Handle session API response
   */
  function handleSessionResponse(response) {
    if (response && response.success) {
      state.sessionId = response.session_id;

      // If this is a new parent session, store it
      if (!state.parentSessionId && response.is_new_session) {
        state.parentSessionId = response.session_id;
        localStorage.setItem(
          `${config.storagePrefix}parentSessionId`,
          state.parentSessionId,
        );

        // Mark as primary tab if this is a new parent session
        state.is_primary_tab = true;
      }

      // Store session ID
      localStorage.setItem(`${config.storagePrefix}sessionId`, state.sessionId);

      // Initialize session start time if not set
      if (!state.sessionStartTime) {
        state.sessionStartTime = Date.now();
      }

      // Initialize tab opened time if not set
      if (!state.tab_opened_time) {
        state.tab_opened_time = new Date().toISOString();
      }

      // Initialize tab last focus time if not set
      if (!state.tab_last_focus) {
        state.tab_last_focus = new Date().toISOString();
      }

      // Send initial tab data
      sendApiRequest(config.apiEndpoints.updateSession, {
        session_id: state.sessionId,
        tab_id: state.tabId,
        is_primary_tab: state.is_primary_tab,
        tab_opened_time: state.tab_opened_time,
        tab_last_focus: state.tab_last_focus,
        tab_title: document.title,
        tab_url: window.location.href,
      });

      // Broadcast session info to other tabs if needed
      if (response.is_new_session && broadcastChannel) {
        const broadcastMessage = {
          type: "new_session",
          sessionId: state.sessionId,
          parentSessionId: state.parentSessionId,
          tabId: state.tabId,
          timestamp: new Date().toISOString(),
        };

        broadcastChannel.postMessage(broadcastMessage);
        state.broadcast_messages_sent++;
      }
    } else {
      console.error(
        "Failed to initialize session:",
        response ? response.error : "Unknown error",
      );
    }
  }

  /**
   * Set up all event listeners
   */
  function setupEventListeners() {
    // User activity events
    document.addEventListener("click", handleUserActivity);
    document.addEventListener("keydown", handleUserActivity);
    document.addEventListener("mousemove", throttle(handleUserActivity, 1000));
    document.addEventListener("scroll", throttle(handleUserActivity, 1000));

    // Tab visibility events
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", handleWindowFocus);
    window.addEventListener("blur", handleWindowBlur);

    // Page lifecycle events
    window.addEventListener("beforeunload", handleBeforeUnload);
    window.addEventListener("pagehide", handlePageHide);

    // Detailed activity tracking
    document.addEventListener("click", trackClick);
    document.addEventListener("keydown", trackKeyboard);
    window.addEventListener("scroll", throttle(trackScroll, 500));
    document.addEventListener("mousemove", throttle(trackMouseMovement, 1000));

    // URL change detection for SPAs
    if (window.history && window.history.pushState) {
      const originalPushState = window.history.pushState;
      window.history.pushState = function () {
        originalPushState.apply(this, arguments);
        handleUrlChange();
      };
      window.addEventListener("popstate", handleUrlChange);
    }

    // Cross-tab communication
    if (broadcastChannel) {
      broadcastChannel.onmessage = handleBroadcastMessage;
    }

    // Handle window errors
    window.addEventListener("error", handleError);
  }

  /**
   * Start all timers
   */
  function startTimers() {
    // Heartbeat timer to update session status
    state.heartbeatTimer = setInterval(heartbeat, config.heartbeatInterval);

    // Activity sampling timer
    state.activitySampleTimer = setInterval(
      sampleActivity,
      config.activitySampleInterval,
    );

    // Performance sampling timer
    state.performanceSampleTimer = setInterval(
      samplePerformance,
      config.performanceSampleInterval,
    );
  }

  /**
   * Initialize device information
   */
  function initDeviceInfo() {
    // Get screen resolution
    state.deviceInfo.screenResolution = `${window.screen.width}x${window.screen.height}`;

    // Get device type
    state.deviceInfo.deviceType = detectDeviceType();

    // Get battery information if available
    if (navigator.getBattery) {
      navigator.getBattery().then(function (battery) {
        updateBatteryInfo(battery);

        // Listen for battery changes
        battery.addEventListener("levelchange", function () {
          updateBatteryInfo(battery);
        });
      });
    }

    // Get connection information if available
    if (navigator.connection) {
      updateConnectionInfo(navigator.connection);

      // Listen for connection changes
      navigator.connection.addEventListener("change", function () {
        updateConnectionInfo(navigator.connection);
      });
    }
  }

  /**
   * Update battery information
   */
  function updateBatteryInfo(battery) {
    state.deviceInfo.batteryLevel = Math.round(battery.level * 100);
    sendApiRequest(config.apiEndpoints.updateSession, {
      session_id: state.sessionId,
      device_info: {
        battery_level: state.deviceInfo.batteryLevel,
      },
    });
  }

  /**
   * Update connection information
   */
  function updateConnectionInfo(connection) {
    state.deviceInfo.connectionType =
      connection.effectiveType || connection.type;
    sendApiRequest(config.apiEndpoints.updateSession, {
      session_id: state.sessionId,
      device_info: {
        connection_type: state.deviceInfo.connectionType,
      },
    });
  }

  /**
   * Generate a browser fingerprint
   */
  function generateFingerprint() {
    const components = [
      navigator.userAgent,
      navigator.language,
      new Date().getTimezoneOffset(),
      screen.colorDepth,
      screen.pixelDepth,
      screen.width + "x" + screen.height,
      navigator.hardwareConcurrency,
      navigator.deviceMemory,
      navigator.platform,
      !!navigator.doNotTrack,
      getCanvasFingerprint(),
    ];

    state.browserFingerprint = hashString(components.join("###"));
  }

  /**
   * Get canvas fingerprint
   */
  function getCanvasFingerprint() {
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      canvas.width = 200;
      canvas.height = 50;

      // Text with different styles
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#F60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("TrueAlign", 2, 15);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.fillText("Session", 4, 17);

      return canvas.toDataURL();
    } catch (e) {
      return "canvas-not-supported";
    }
  }

  /**
   * Get location data if available
   */
  function getLocationData() {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        function (position) {
          state.locationData = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
          };

          // Update session with location data
          if (state.sessionId) {
            sendApiRequest(config.apiEndpoints.updateSession, {
              session_id: state.sessionId,
              location_data: state.locationData,
            });
          }
        },
        function (error) {
          console.log("Geolocation error:", error.message);
        },
        {
          enableHighAccuracy: false,
          timeout: 5000,
          maximumAge: 600000, // 10 minutes
        },
      );
    }
  }

  /**
   * Handle user activity
   */
  function handleUserActivity() {
    const now = Date.now();
    const wasIdle = state.isIdle;

    // Update last activity time
    state.lastActivity = now;

    // If we were idle, reset idle state
    if (wasIdle) {
      state.isIdle = false;

      // Calculate idle duration and add to total
      if (state.idleStartTime) {
        const idleDuration = now - state.idleStartTime;
        state.total_idle_time = (state.total_idle_time || 0) + idleDuration;
        console.log(
          `Added ${idleDuration}ms to total idle time, now: ${state.total_idle_time}ms`,
        );
      }

      state.idleStartTime = null;
      state.idleWarningShown = false;

      // Create idle state change record
      const idleStateChange = {
        action: "idle_end",
        timestamp: new Date().toISOString(),
        duration: state.idleStartTime
          ? (now - state.idleStartTime) / 1000
          : null, // in seconds
      };

      // Add to activity buffer
      if (!state.activityBuffer.idleStateChanges) {
        state.activityBuffer.idleStateChanges = [];
      }
      state.activityBuffer.idleStateChanges.push(idleStateChange);

      // Update session with idle status change
      if (state.sessionId) {
        sendApiRequest(config.apiEndpoints.updateSession, {
          session_id: state.sessionId,
          is_idle: false,
          idle_state_changes: [idleStateChange],
          total_idle_time: state.total_idle_time / 1000, // Convert to seconds
          last_activity: new Date().toISOString(),
        });
      }

      // Hide any idle warning
      hideIdleWarning();
    }
  }

  /**
   * Handle visibility change
   */
  function handleVisibilityChange() {
    const isVisible = document.visibilityState === "visible";
    const visibilityData = {
      action: isVisible ? "tab_visible" : "tab_hidden",
      timestamp: new Date().toISOString(),
      url: window.location.href,
      title: document.title,
      tab_id: state.tabId,
    };

    // Update tab switches count if becoming visible
    if (isVisible) {
      state.tab_switches = (state.tab_switches || 0) + 1;
    } else {
      // Start tracking background time when tab becomes hidden
      state.backgroundStartTime = Date.now();
    }

    // Update session with visibility change
    if (state.sessionId) {
      const updateData = {
        session_id: state.sessionId,
        tab_visibility_log: [visibilityData],
        tab_switches: state.tab_switches,
        tab_last_focus: isVisible ? new Date().toISOString() : null,
      };

      sendApiRequest(config.apiEndpoints.updateSession, updateData);
    }

    // Add to activity buffer
    state.activityBuffer.tabVisibility.push(visibilityData);
  }

  /**
   * Handle window focus
   */
  function handleWindowFocus() {
    state.isActive = true;
    const focusData = {
      action: "focus_gained",
      timestamp: new Date().toISOString(),
      url: window.location.href,
      title: document.title,
      tab_id: state.tabId,
    };

    // Calculate background time if we have a start time
    if (state.backgroundStartTime) {
      const backgroundDuration = Date.now() - state.backgroundStartTime;
      state.background_time = (state.background_time || 0) + backgroundDuration;
      state.backgroundStartTime = null;
    }

    // Update session with focus change
    if (state.sessionId) {
      const updateData = {
        session_id: state.sessionId,
        tab_visibility_log: [focusData],
        is_active: true,
        tab_last_focus: new Date().toISOString(),
        background_time: state.background_time
          ? state.background_time / 1000
          : 0, // Convert to seconds
      };

      sendApiRequest(config.apiEndpoints.updateSession, updateData);
    }

    // Add to activity buffer
    state.activityBuffer.tabVisibility.push(focusData);
  }

  /**
   * Handle window blur
   */
  function handleWindowBlur() {
    state.isActive = false;
    state.backgroundStartTime = Date.now();

    const blurData = {
      action: "focus_lost",
      timestamp: new Date().toISOString(),
      url: window.location.href,
      title: document.title,
      tab_id: state.tabId,
    };

    // Update session with blur change
    if (state.sessionId) {
      const updateData = {
        session_id: state.sessionId,
        tab_visibility_log: [blurData],
        is_active: false,
      };

      sendApiRequest(config.apiEndpoints.updateSession, updateData);
    }

    // Add to activity buffer
    state.activityBuffer.tabVisibility.push(blurData);
  }

  /**
   * Handle before unload
   */
  function handleBeforeUnload(event) {
    // Send final update synchronously
    if (state.sessionId) {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", config.apiEndpoints.updateSession, false); // Synchronous request
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("X-CSRFToken", state.csrfToken);
      xhr.send(
        JSON.stringify({
          session_id: state.sessionId,
          last_activity: new Date().toISOString(),
          is_closing: true,
        }),
      );
    }
  }

  /**
   * Handle page hide (more reliable than beforeunload in some browsers)
   */
  function handlePageHide(event) {
    if (event.persisted) {
      // Page is being cached for bfcache
      return;
    }

    // Similar to beforeunload but using sendBeacon if available
    if (state.sessionId && navigator.sendBeacon) {
      const data = new FormData();
      data.append("session_id", state.sessionId);
      data.append("last_activity", new Date().toISOString());
      data.append("is_closing", "true");
      data.append("csrfmiddlewaretoken", state.csrfToken);

      navigator.sendBeacon(config.apiEndpoints.updateSession, data);
    }
  }

  /**
   * Handle URL change (for SPAs)
   */
  function handleUrlChange() {
    const newUrl = window.location.href;
    const newTitle = document.title;

    // Only process if URL actually changed
    if (newUrl !== state.currentUrl) {
      const oldUrl = state.currentUrl;
      state.currentUrl = newUrl;
      state.currentTitle = newTitle;

      // Track URL frequency
      trackUrlVisit(newUrl, newTitle);

      // Update session with page view
      if (state.sessionId) {
        sendApiRequest(config.apiEndpoints.updateSession, {
          session_id: state.sessionId,
          page_view: {
            url: newUrl,
            title: newTitle,
            referrer: oldUrl,
            timestamp: new Date().toISOString(),
          },
        });
      }
    }
  }

  /**
   * Handle broadcast message from other tabs
   */
  function handleBroadcastMessage(event) {
    const message = event.data;

    if (message && message.type === "new_session") {
      // Another tab created a new session
      log("Received broadcast message:", message);

      // Update parent session ID if needed
      if (!state.parentSessionId && message.parentSessionId) {
        state.parentSessionId = message.parentSessionId;
        localStorage.setItem(
          `${config.storagePrefix}parentSessionId`,
          state.parentSessionId,
        );
        log("Updated parent session ID from broadcast:", state.parentSessionId);
      }

      // Track related tab
      if (message.tabId !== state.tabId) {
        const relatedTab = {
          tab_id: message.tabId,
          first_seen: new Date().toISOString(),
        };

        state.relatedTabs.push(relatedTab);

        // Update session with related tab
        if (state.sessionId) {
          sendApiRequest(config.apiEndpoints.updateSession, {
            session_id: state.sessionId,
            cross_tab_event: {
              source_tab_id: message.tabId,
              event_type: "new_tab",
              timestamp: new Date().toISOString(),
            },
          });
        }
      }
    }
  }

  /**
   * Handle error
   */
  function handleError(event) {
    const errorData = {
      message: event.message,
      source: event.filename,
      line: event.lineno,
      column: event.colno,
      stack: event.error ? event.error.stack : null,
      timestamp: new Date().toISOString(),
    };

    // Update session with error
    if (state.sessionId) {
      sendApiRequest(config.apiEndpoints.updateSession, {
        session_id: state.sessionId,
        error_event: errorData,
      });
    }
  }

  /**
   * Track click event
   */
  function trackClick(event) {
    const target = event.target;
    const clickData = {
      timestamp: new Date().toISOString(),
      x: event.clientX,
      y: event.clientY,
      target_tag: target.tagName.toLowerCase(),
      target_id: target.id || null,
      target_class: target.className || null,
      url: window.location.href,
      page_title: document.title,
    };

    // Add to activity buffer
    state.activityBuffer.clicks.push(clickData);

    // If buffer is getting too large, send update
    if (state.activityBuffer.clicks.length >= 10) {
      console.log("Click buffer full, triggering activity sample");
      sampleActivity();
    }

    // Direct update for immediate feedback
    if (state.sessionId) {
      sendApiRequest(config.apiEndpoints.updateSession, {
        session_id: state.sessionId,
        click: clickData,
      });
    }
  }

  /**
   * Track keyboard event
   */
   function trackKeyboard(event) {
     try {
       // Don't track actual keys for privacy/security reasons
       const keyboardData = {
         timestamp: new Date().toISOString(),
         is_modifier: isModifierKey(event.keyCode),
         input_type: getInputType(event.target),
         url: window.location.href,
         page_title: document.title,
       };

       // Add to activity buffer
       state.activityBuffer.keystrokes.push(keyboardData);

       // If buffer is getting too large, send update
       if (state.activityBuffer.keystrokes.length >= 20) {
         sampleActivity();
       }
     } catch (error) {
       console.error('Error in trackKeyboard:', error);
     }
   }
   function calculateScrollPercentage() {
     try {
       const scrollTop = window.scrollY || document.documentElement.scrollTop;
       const scrollHeight = Math.max(
         document.body.scrollHeight,
         document.documentElement.scrollHeight,
       ) - window.innerHeight;

       return scrollHeight > 0 ? Math.round((scrollTop / scrollHeight) * 100) : 0;
     } catch (error) {
       console.error('Error calculating scroll percentage:', error);
       return 0;
     }
   }

  }


  /**
   * Track scroll event
   */
   function trackScroll() {
     try {
       const scrollData = {
         timestamp: new Date().toISOString(),
         scroll_x: window.scrollX,
         scroll_y: window.scrollY,
         scroll_max_y:
           Math.max(
             document.body.scrollHeight,
             document.documentElement.scrollHeight,
           ) - window.innerHeight,
         scroll_percent: calculateScrollPercentage(),
         url: window.location.href,
         page_title: document.title,
       };

       // Add to activity buffer
       state.activityBuffer.scrolls.push(scrollData);

       // If buffer is getting too large, send update
       if (state.activityBuffer.scrolls.length >= 15) {
         sampleActivity();
       }
     } catch (error) {
       console.error('Error in trackScroll:', error);
     }
   }


  /**
   * Track mouse movement
   */
  function trackMouseMovement(event) {
    const moveData = {
      timestamp: new Date().toISOString(),
      x: event.clientX,
      y: event.clientY,
      url: window.location.href,
      page_title: document.title,
    };

    // Add to activity buffer
    state.activityBuffer.mouseMoves.push(moveData);

    // Only log occasionally to avoid console spam
    if (state.activityBuffer.mouseMoves.length % 10 === 0) {
      console.log(
        `Mouse movements tracked: ${state.activityBuffer.mouseMoves.length}`,
      );
    }

    // If buffer is getting too large, send update
    if (state.activityBuffer.mouseMoves.length >= 50) {
      sampleActivity();
    }
  }

  /**
   * Track URL visit frequency
   */
  function trackUrlVisit(url, title) {
    if (!url) return;

    if (!state.visitedUrls[url]) {
      state.visitedUrls[url] = {
        count: 1,
        first_visit: new Date().toISOString(),
        last_visit: new Date().toISOString(),
        title: title || "",
      };
    } else {
      state.visitedUrls[url].count++;
      state.visitedUrls[url].last_visit = new Date().toISOString();
      if (title) state.visitedUrls[url].title = title;
    }

    // Update session with visited URLs
    if (state.sessionId) {
      const urlData = {};
      urlData[url] = state.visitedUrls[url];

      sendApiRequest(config.apiEndpoints.updateSession, {
        session_id: state.sessionId,
        visited_urls: urlData,
      });
    }
  }

  /**
   * Heartbeat function to check idle status and update session
   */
  function heartbeat() {
    const now = Date.now();
    const idleTime = now - state.lastActivity;

    console.log(
      `Heartbeat check - Idle time: ${idleTime}ms, Threshold: ${config.idleThreshold}ms, Is idle: ${state.isIdle}`,
    );

    // Check if user is idle
    if (!state.isIdle && idleTime >= config.idleThreshold) {
      state.isIdle = true;
      state.idleStartTime = now;

      console.log("User became idle at:", new Date().toISOString());

      // Create idle state change data
      const idleStateChange = {
        action: "idle_start",
        timestamp: new Date().toISOString(),
        duration_ms: 0,
      };

      // Add to idle state changes
      if (!state.activityBuffer.idleStateChanges) {
        state.activityBuffer.idleStateChanges = [];
      }
      state.activityBuffer.idleStateChanges.push(idleStateChange);

      // Update session with idle status change
      if (state.sessionId) {
        sendApiRequest(config.apiEndpoints.updateSession, {
          session_id: state.sessionId,
          is_idle: true,
          idle_state_changes: [idleStateChange],
          idle_start_time: new Date().toISOString(),
        });
      }
    }

    // Check if we should show idle warning
    if (
      state.isIdle &&
      !state.idleWarningShown &&
      now - state.idleStartTime >= config.warningThreshold
    ) {
      showIdleWarning();
      state.idleWarningShown = true;
    }

    // Check if we should auto-logout
    if (
      state.isIdle &&
      now - state.idleStartTime >= config.autoLogoutThreshold
    ) {
      autoLogout();
      return;
    }

    // Regular heartbeat update
    if (state.sessionId) {
      // Calculate session duration
      const sessionDuration = (now - state.sessionStartTime) / 1000; // in seconds

      // Calculate total idle time
      let totalIdleTime = state.total_idle_time || 0;
      if (state.isIdle && state.idleStartTime) {
        const currentIdleDuration = now - state.idleStartTime;
        totalIdleTime += currentIdleDuration;
      }

      // Calculate working time (session duration minus idle time)
      const workingTime = Math.max(
        0,
        (sessionDuration * 1000 - totalIdleTime) / 1000,
      );

      // Calculate focus time (time the tab was visible and active)
      let focusTime = 0;
      if (document.visibilityState === "visible" && state.isActive) {
        focusTime = workingTime; // Simplified calculation
      }

      const heartbeatData = {
        session_id: state.sessionId,
        last_activity: new Date(state.lastActivity).toISOString(),
        is_idle: state.isIdle,
        session_duration: sessionDuration,
        working_time: workingTime,
        focus_time: focusTime,
        total_idle_time: totalIdleTime / 1000, // Convert to seconds
        tab_id: state.tabId,
        tab_visibility: document.visibilityState === "visible",
        tab_last_focus: state.isActive ? new Date().toISOString() : null,
        mouse_movements: state.mouse_movements || 0,
        tab_switches: state.tab_switches || 0,
      };

      sendApiRequest(config.apiEndpoints.updateSession, heartbeatData);
    }
  }

  /**
   * Sample activity data and send to server
   */
  function sampleActivity() {
    // Initialize session start time if not set
    if (!state.sessionStartTime) {
      state.sessionStartTime = Date.now();
    }

    // Calculate productivity and engagement scores
    calculateProductivityScore(state);
    calculateEngagementScore(state);

    if (
      !state.sessionId ||
      Object.values(state.activityBuffer).every((arr) => arr.length === 0)
    ) {
      return;
    }

    // Prepare data to send
    const activityData = {
      session_id: state.sessionId,
      last_activity: new Date().toISOString(),
      tab_id: state.tabId,
      is_active: state.isActive,
      is_idle: state.isIdle,
    };

    // Add click events if any
    if (state.activityBuffer.clicks.length > 0) {
      activityData.clicks = state.activityBuffer.clicks;
      console.log(`Sending ${state.activityBuffer.clicks.length} click events`);
      state.activityBuffer.clicks = [];
    }

    // Add keyboard events if any
    if (state.activityBuffer.keystrokes.length > 0) {
      activityData.keyboard_events = state.activityBuffer.keystrokes;
      console.log(
        `Sending ${state.activityBuffer.keystrokes.length} keyboard events`,
      );
      state.activityBuffer.keystrokes = [];
    }

    // Add scroll events if any
    if (state.activityBuffer.scrolls.length > 0) {
      activityData.scrolls = state.activityBuffer.scrolls;
      console.log(
        `Sending ${state.activityBuffer.scrolls.length} scroll events`,
      );
      state.activityBuffer.scrolls = [];
    }

    // Add mouse movement count if any
    if (state.activityBuffer.mouseMoves.length > 0) {
      activityData.mouse_movements = state.activityBuffer.mouseMoves.length;
      state.mouse_movements =
        (state.mouse_movements || 0) + state.activityBuffer.mouseMoves.length;
      console.log(
        `Sending ${state.activityBuffer.mouseMoves.length} mouse movements, total: ${state.mouse_movements}`,
      );
      state.activityBuffer.mouseMoves = [];
    }

    // Add tab visibility changes if any
    if (state.activityBuffer.tabVisibility.length > 0) {
      activityData.tab_visibility_log = state.activityBuffer.tabVisibility;
      console.log(
        `Sending ${state.activityBuffer.tabVisibility.length} tab visibility changes`,
      );
      state.activityBuffer.tabVisibility = [];
    }

    // Add idle state changes if any
    if (
      state.activityBuffer.idleStateChanges &&
      state.activityBuffer.idleStateChanges.length > 0
    ) {
      activityData.idle_state_changes = state.activityBuffer.idleStateChanges;
      console.log(
        `Sending ${state.activityBuffer.idleStateChanges.length} idle state changes`,
      );
      state.activityBuffer.idleStateChanges = [];
    }

    // Add performance metrics if available
    if (Object.keys(state.performanceMetrics).length > 0) {
      activityData.performance_metrics = state.performanceMetrics;
      console.log("Sending performance metrics");
    }

    // Calculate session metrics
    if (state.sessionStartTime) {
      const now = Date.now();
      activityData.session_duration = (now - state.sessionStartTime) / 1000; // in seconds

      // Calculate working time (session duration minus idle time)
      if (state.isIdle && state.idleStartTime) {
        const idleDuration = (now - state.idleStartTime) / 1000; // in seconds
        activityData.total_idle_time = idleDuration;
        activityData.working_time = Math.max(
          0,
          activityData.session_duration - idleDuration,
        );
      } else {
        activityData.working_time = activityData.session_duration;
      }

      console.log(
        `Session metrics - Duration: ${activityData.session_duration}s, Working time: ${activityData.working_time}s`,
      );
    }

    // Add productivity and engagement scores
    if (state.productivity_score !== null) {
      activityData.productivity_score = state.productivity_score;
      console.log(`Including productivity score: ${state.productivity_score}`);
    }

    if (state.engagement_score !== null) {
      activityData.engagement_score = state.engagement_score;
      console.log(`Including engagement score: ${state.engagement_score}`);
    }

    if (state.session_quality !== null) {
      activityData.session_quality = state.session_quality;
      console.log(`Including session quality: ${state.session_quality}`);
    }

    // Send activity data to server
    console.log("Sending activity data to server:", activityData);
    sendApiRequest(
      config.apiEndpoints.updateSession,
      activityData,
      function (response) {
        if (response && response.success) {
          console.log("Activity data sent successfully");
        } else {
          console.error(
            "Failed to send activity data:",
            response ? response.error : "Unknown error",
          );
        }
      },
    );

    // The calculateProductivityScore and calculateEngagementScore functions are now imported from session_tracker_functions.js

    /**
     * Show idle warning dialog
     */
    function showIdleWarning() {
      // Check if warning already exists
      if (document.getElementById("idle-warning-dialog")) return;

      // Calculate remaining time
      const remainingMinutes = Math.ceil(
        (config.autoLogoutThreshold - (Date.now() - state.idleStartTime)) /
          60000,
      );

      // Create warning dialog
      const dialog = document.createElement("div");
      dialog.id = "idle-warning-dialog";
      dialog.style.position = "fixed";
      dialog.style.top = "20px";
      dialog.style.right = "20px";
      dialog.style.width = "300px";
      dialog.style.padding = "15px";
      dialog.style.backgroundColor = "#f8d7da";
      dialog.style.color = "#721c24";
      dialog.style.border = "1px solid #f5c6cb";
      dialog.style.borderRadius = "4px";
      dialog.style.boxShadow = "0 4px 8px rgba(0,0,0,0.1)";
      dialog.style.zIndex = "9999";

      dialog.innerHTML = `
            <h4 style="margin-top: 0; margin-bottom: 10px;">Session Timeout Warning</h4>
            <p>You have been inactive for a while. Your session will expire in approximately ${remainingMinutes} minute${remainingMinutes !== 1 ? "s" : ""}.</p>
            <p>Click anywhere or press any key to continue.</p>
            <button id="idle-warning-close" style="background-color: #721c24; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;">Dismiss</button>
        `;

      document.body.appendChild(dialog);

      // Add event listener to close button
      document
        .getElementById("idle-warning-close")
        .addEventListener("click", function (e) {
          e.stopPropagation();
          handleUserActivity();
          hideIdleWarning();
        });
    }

    /**
     * Hide idle warning dialog
     */
    function hideIdleWarning() {
      const dialog = document.getElementById("idle-warning-dialog");
      if (dialog) {
        dialog.parentNode.removeChild(dialog);
      }
    }

    /**
     * Auto logout due to inactivity
     */
    function autoLogout() {
      console.log("Auto logout triggered due to inactivity");

      // Calculate final session metrics
      const now = Date.now();
      const sessionDuration = state.sessionStartTime
        ? (now - state.sessionStartTime) / 1000
        : 0; // in seconds
      let totalIdleTime = 0;

      // Calculate total idle time
      if (state.isIdle && state.idleStartTime) {
        const currentIdleDuration = (now - state.idleStartTime) / 1000; // in seconds
        totalIdleTime = state.total_idle_time
          ? state.total_idle_time + currentIdleDuration
          : currentIdleDuration;
      } else if (state.total_idle_time) {
        totalIdleTime = state.total_idle_time;
      }

      // Calculate working time (session duration minus idle time)
      const workingTime = Math.max(0, sessionDuration - totalIdleTime);

      // Calculate final productivity and engagement scores
      calculateProductivityScore(state);
      calculateEngagementScore(state);

      console.log(
        `Final session metrics - Duration: ${sessionDuration}s, Total idle time: ${totalIdleTime}s, Working time: ${workingTime}s`,
      );
      console.log(
        `Final scores - Productivity: ${state.productivity_score}, Engagement: ${state.engagement_score}, Quality: ${state.session_quality}`,
      );

      // End session with final metrics
      if (state.sessionId) {
        sendApiRequest(config.apiEndpoints.endSession, {
          session_id: state.sessionId,
          reason: "auto_logout_inactivity",
          session_duration: sessionDuration,
          total_idle_time: totalIdleTime,
          working_time: workingTime,
          productivity_score: state.productivity_score,
          engagement_score: state.engagement_score,
          session_quality: state.session_quality,
        });
      }

      // Clear timers
      clearInterval(state.heartbeatTimer);
      clearInterval(state.activitySampleTimer);
      clearInterval(state.performanceSampleTimer);

      // Clear storage
      localStorage.removeItem(`${config.storagePrefix}sessionId`);

      // Show logout message
      const logoutMessage = document.createElement("div");
      logoutMessage.style.position = "fixed";
      logoutMessage.style.top = "0";
      logoutMessage.style.left = "0";
      logoutMessage.style.width = "100%";
      logoutMessage.style.height = "100%";
      logoutMessage.style.backgroundColor = "rgba(0,0,0,0.8)";
      logoutMessage.style.color = "white";
      logoutMessage.style.display = "flex";
      logoutMessage.style.flexDirection = "column";
      logoutMessage.style.justifyContent = "center";
      logoutMessage.style.alignItems = "center";
      logoutMessage.style.zIndex = "10000";

      logoutMessage.innerHTML = `
            <div style="background-color: #343a40; padding: 30px; border-radius: 5px; text-align: center; max-width: 500px;">
                <h2 style="margin-top: 0;">Session Expired</h2>
                <p>Your session has expired due to inactivity.</p>
                <p>Please <a href="/login/" style="color: #17a2b8;">log in</a> again to continue.</p>
            </div>
        `;

      document.body.appendChild(logoutMessage);

      // Redirect to login page after a delay
      setTimeout(function () {
        window.location.href = "/login/?session_expired=true";
      }, 3000);
    }

    /**
     * Utility function to get CSRF token
     */
    function getCSRFToken() {
      const tokenElement = document.querySelector(
        'input[name="csrfmiddlewaretoken"]',
      );
      if (tokenElement) return tokenElement.value;

      const cookieValue = document.cookie
        .split("; ")
        .find((row) => row.startsWith("csrftoken="));

      return cookieValue ? cookieValue.split("=")[1] : "";
    }

    /**
     * Utility function to generate UUID
     */
    function generateUUID() {
      return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
        /[xy]/g,
        function (c) {
          const r = (Math.random() * 16) | 0;
          const v = c === "x" ? r : (r & 0x3) | 0x8;
          return v.toString(16);
        },
      );
    }

    /**
     * Utility function to hash a string
     */
    function hashString(str) {
      let hash = 0;
      if (str.length === 0) return hash.toString(16);

      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash = hash & hash; // Convert to 32bit integer
      }

      return Math.abs(hash).toString(16);
    }

    /**
     * Utility function to detect device type
     */
    function detectDeviceType() {
      const ua = navigator.userAgent;
      if (
        /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)
      ) {
        return /iPad|Tablet|Pad/i.test(ua) ? "tablet" : "mobile";
      }
      return "desktop";
    }

    /**
     * Utility function to check if a key is a modifier key
     */
    function isModifierKey(keyCode) {
      return [16, 17, 18, 20, 91, 92, 93].indexOf(keyCode) !== -1; // Shift, Ctrl, Alt, CapsLock, Windows/Command keys
    }

    /**
     * Utility function to get input type
     */
    function getInputType(element) {
      if (!element) return "other";

      const tagName = element.tagName.toLowerCase();
      if (tagName === "input") {
        return element.type || "text";
      }
      if (tagName === "textarea") return "textarea";
      if (tagName === "select") return "select";

      return element.isContentEditable ? "contenteditable" : "other";
    }

    /**
     * Utility function to calculate scroll percentage
     */
     function calculateScrollPercentage() {
       try {
         const scrollTop = window.scrollY || document.documentElement.scrollTop;
         const scrollHeight = Math.max(
           document.body.scrollHeight,
           document.documentElement.scrollHeight,
         ) - window.innerHeight;

         return scrollHeight > 0 ? Math.round((scrollTop / scrollHeight) * 100) : 0;
       } catch (error) {
         console.error('Error calculating scroll percentage:', error);
         return 0;
       }
     }

    }

    /**
     * Utility function to throttle function calls
     */
    function throttle(func, limit) {
      let lastCall = 0;
      return function (...args) {
        const now = Date.now();
        if (now - lastCall >= limit) {
          lastCall = now;
          return func.apply(this, args);
        }
      };
    }

    /**
     * Utility function for logging
     */
    function log(...args) {
      if (config.debug) {
        console.log("[SessionTracker]", ...args);
      }
    }

    // Public API
    return {
      init: init,
      getSessionId: function () {
        return state.sessionId;
      },
      getTabId: function () {
        return state.tabId;
      },
      getParentSessionId: function () {
        return state.parentSessionId;
      },
      isIdle: function () {
        return state.isIdle;
      },
      getIdleTime: function () {
        return state.isIdle
          ? Math.floor((Date.now() - state.idleStartTime) / 1000)
          : 0;
      },
      getRemainingTime: function () {
        if (!state.isIdle) return config.autoLogoutThreshold / 1000;
        const remaining =
          config.autoLogoutThreshold - (Date.now() - state.idleStartTime);
        return Math.max(0, Math.floor(remaining / 1000));
      },
      getDeviceInfo: function () {
        return { ...state.deviceInfo };
      },
      getLocationData: function () {
        return state.locationData;
      },
      getVisitedUrls: function () {
        return { ...state.visitedUrls };
      },
      getPerformanceMetrics: function () {
        return { ...state.performanceMetrics };
      },
      endSession: function () {
        if (state.sessionId) {
          // Calculate final session metrics
          const now = Date.now();
          const sessionDuration = state.sessionStartTime
            ? (now - state.sessionStartTime) / 1000
            : 0; // in seconds
          let totalIdleTime = 0;

          // Calculate total idle time
          if (state.isIdle && state.idleStartTime) {
            const currentIdleDuration = (now - state.idleStartTime) / 1000; // in seconds
            totalIdleTime = state.total_idle_time
              ? state.total_idle_time + currentIdleDuration
              : currentIdleDuration;
          } else if (state.total_idle_time) {
            totalIdleTime = state.total_idle_time;
          }

          // Calculate working time (session duration minus idle time)
          const workingTime = Math.max(0, sessionDuration - totalIdleTime);

          // Calculate final productivity and engagement scores
          calculateProductivityScore(state);
          calculateEngagementScore(state);

          console.log(
            `Manual end session - Final metrics - Duration: ${sessionDuration}s, Total idle time: ${totalIdleTime}s, Working time: ${workingTime}s`,
          );
          console.log(
            `Final scores - Productivity: ${state.productivity_score}, Engagement: ${state.engagement_score}, Quality: ${state.session_quality}`,
          );

          // End session with final metrics
          sendApiRequest(config.apiEndpoints.endSession, {
            session_id: state.sessionId,
            reason: "manual_end",
            session_duration: sessionDuration,
            total_idle_time: totalIdleTime,
            working_time: workingTime,
            productivity_score: state.productivity_score,
            engagement_score: state.engagement_score,
            session_quality: state.session_quality,
          });

          // Clear timers and storage
          clearInterval(state.heartbeatTimer);
          clearInterval(state.activitySampleTimer);
          clearInterval(state.performanceSampleTimer);
          localStorage.removeItem(`${config.storagePrefix}sessionId`);
          state.sessionId = null;
        }
      },
      // For debugging
      getState: function () {
        return config.debug ? { ...state } : null;
      },
      setDebug: function (debug) {
        config.debug = !!debug;
      },
    };
  }

  // Return the SessionTracker object to make it globally available
  return {
    init: init,
    getSessionId: function () {
      return state.sessionId;
    },
    getTabId: function () {
      return state.tabId;
    },
    getParentSessionId: function () {
      return state.parentSessionId;
    },
    isIdle: function () {
      return state.isIdle;
    },
    getIdleTime: function () {
      return state.isIdle
        ? Math.floor((Date.now() - state.idleStartTime) / 1000)
        : 0;
    },
    getRemainingTime: function () {
      if (!state.isIdle) return config.autoLogoutThreshold / 1000;
      const remaining =
        config.autoLogoutThreshold - (Date.now() - state.idleStartTime);
      return Math.max(0, Math.floor(remaining / 1000));
    },
    getDeviceInfo: function () {
      return { ...state.deviceInfo };
    },
    getLocationData: function () {
      return state.locationData;
    },
    getVisitedUrls: function () {
      return { ...state.visitedUrls };
    },
    getPerformanceMetrics: function () {
      return { ...state.performanceMetrics };
    },
    endSession: function () {
      if (state.sessionId) {
        // Calculate final session metrics
        const now = Date.now();
        const sessionDuration = state.sessionStartTime
          ? (now - state.sessionStartTime) / 1000
          : 0; // in seconds
        let totalIdleTime = 0;

        // Calculate total idle time
        if (state.isIdle && state.idleStartTime) {
          const currentIdleDuration = (now - state.idleStartTime) / 1000; // in seconds
          totalIdleTime = state.total_idle_time
            ? state.total_idle_time + currentIdleDuration
            : currentIdleDuration;
        } else if (state.total_idle_time) {
          totalIdleTime = state.total_idle_time;
        }

        // Calculate working time (session duration minus idle time)
        const workingTime = Math.max(0, sessionDuration - totalIdleTime);

        // Calculate final productivity and engagement scores
        calculateProductivityScore(state);
        calculateEngagementScore(state);

        console.log(
          `Manual end session - Final metrics - Duration: ${sessionDuration}s, Total idle time: ${totalIdleTime}s, Working time: ${workingTime}s`,
        );
        console.log(
          `Final scores - Productivity: ${state.productivity_score}, Engagement: ${state.engagement_score}, Quality: ${state.session_quality}`,
        );

        // End session with final metrics
        sendApiRequest(config.apiEndpoints.endSession, {
          session_id: state.sessionId,
          reason: "manual_end",
          session_duration: sessionDuration,
          total_idle_time: totalIdleTime,
          working_time: workingTime,
          productivity_score: state.productivity_score,
          engagement_score: state.engagement_score,
          session_quality: state.session_quality,
        });

        // Clear timers and storage
        clearInterval(state.heartbeatTimer);
        clearInterval(state.activitySampleTimer);
        clearInterval(state.performanceSampleTimer);
        localStorage.removeItem(`${config.storagePrefix}sessionId`);
        state.sessionId = null;
      }
    },
    // For debugging
    getState: function () {
      return config.debug ? { ...state } : null;
    },
    setDebug: function (debug) {
      config.debug = !!debug;
    },
  };
})(); // Close IIFE
