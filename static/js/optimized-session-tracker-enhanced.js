/**
 * Enhanced Session Tracker with Advanced Optimizations
 * Comprehensive session tracking with race condition prevention, enhanced batching, and smart deduplication
 *
 * Features:
 * - Enhanced batch writing with configurable intervals
 * - Advanced request deduplication
 * - Race condition prevention
 * - Location data synchronization
 * - Real-time performance monitoring
 * - Session duration validation
 * - Intelligent retry mechanisms
 */

class EnhancedSessionTracker {
  constructor(options = {}) {
    // Enhanced configuration
    this.config = {
      // Core intervals (optimized for efficiency)
      heartbeatInterval: 45000, // 45 seconds (increased for efficiency)
      batchFlushInterval: 120000, // 2 minutes (optimized for batching)
      activityThrottle: 30000, // 30 seconds (reduced throttling)
      
      // Advanced buffer management
      maxBufferSize: 150, // Increased buffer size
      maxClicksBuffer: 75,
      maxScrollsBuffer: 40,
      maxKeyboardBuffer: 120,
      maxMouseBuffer: 30,
      
      // Enhanced sampling rates
      mouseSampleRate: 0.05, // 5% (reduced for efficiency)
      scrollSampleRate: 0.25, // 25%
      keyboardSampleRate: 0.9, // 90% (increased for accuracy)
      
      // Session management
      sessionTimeout: 35 * 60 * 1000, // 35 minutes
      warningTime: 30 * 60 * 1000, // 30 minutes
      idleThreshold: 3 * 60 * 1000, // 3 minutes
      minSessionDuration: 10000, // 10 seconds minimum
      
      // Advanced retry configuration
      maxRetries: 5,
      retryDelay: 15000, // 15 seconds
      backoffMultiplier: 1.5,
      
      // Enhanced URLs
      heartbeatUrl: "/optimized-heartbeat/",
      batchActivityUrl: "/optimized-batch-activity/",
      sessionStatusUrl: "/optimized-session-status/",
      endSessionUrl: "/optimized-end-session/",
      
      // Advanced features
      enableAdvancedDeduplication: true,
      enableLocationSync: true,
      enablePerformanceMonitoring: true,
      enableSessionValidation: true,
      enableSmartRetries: true,
      enableCompressionDetection: true,
      
      // Performance optimization
      enableRequestCompression: false,
      enableResponseCaching: true,
      maxConcurrentRequests: 3,
      requestTimeout: 30000, // 30 seconds
      
      ...options,
    };

    // Enhanced state management
    this.state = {
      sessionId: null,
      parentSessionId: null,
      tabId: this.generateTabId(),
      userId: null,
      isActive: false,
      isIdle: false,
      isVisible: true,
      isOnline: navigator.onLine,
      
      // Enhanced timing
      sessionStartTime: Date.now(),
      lastActivity: Date.now(),
      lastHeartbeat: 0,
      lastBatchFlush: 0,
      idleStartTime: null,
      lastLocationUpdate: 0,
      
      // Advanced counters
      totalClicks: 0,
      totalScrolls: 0,
      totalKeystrokes: 0,
      totalMouseMoves: 0,
      pageViews: 0,
      tabSwitches: 0,
      duplicateRequestsBlocked: 0,
      
      // Performance metrics
      averageResponseTime: 0,
      totalRequests: 0,
      failedRequests: 0,
      retryCount: 0,
      
      // Security and fingerprinting
      fingerprint: this.generateFingerprint(),
      browser: this.detectBrowser(),
      os: this.detectOS(),
      screenInfo: this.getScreenInfo(),
      
      // Advanced flags
      warningShown: false,
      compressionEnabled: false,
      batchingOptimized: false,
    };

    // Enhanced activity buffers with smart management
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
      location: [],
      errors: [],
    };

    // Advanced request management
    this.requestManager = {
      pendingRequests: new Map(),
      requestQueue: [],
      activeRequests: 0,
      lastRequestId: 0,
    };

    // Enhanced deduplication system
    this.deduplication = {
      requestHashes: new Map(),
      activityHashes: new Map(),
      locationHashes: new Map(),
      cleanupInterval: 60000, // 1 minute
    };

    // Performance monitoring
    this.performance = {
      startTime: performance.now(),
      requests: [],
      activities: [],
      errors: [],
      metrics: {
        avgResponseTime: 0,
        throughput: 0,
        errorRate: 0,
        cacheHitRate: 0,
      },
    };

    // Enhanced retry system
    this.retrySystem = {
      queue: [],
      processing: false,
      strategies: ['immediate', 'exponential', 'linear', 'smart'],
      currentStrategy: 'smart',
    };

    // Location tracking enhancement
    this.locationTracking = {
      watchId: null,
      lastKnownPosition: null,
      accuracy: Infinity,
      updateQueue: [],
      syncInProgress: false,
    };

    // Event listeners registry
    this.listeners = new Map();
    
    // Timers with enhanced management
    this.timers = {
      heartbeat: null,
      batchFlush: null,
      idleCheck: null,
      retry: null,
      cleanup: null,
      performance: null,
      deduplication: null,
    };

    // Initialize enhanced tracker
    this.init();
  }

  generateFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Session fingerprint', 2, 2);
    
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      !!window.sessionStorage,
      !!window.localStorage,
      canvas.toDataURL(),
      navigator.hardwareConcurrency || 'unknown',
      navigator.deviceMemory || 'unknown'
    ].join('|');
    
    return this.hashString(fingerprint);
  }

  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  init() {
    this.log('Initializing Enhanced Session Tracker', 'info');
    
    try {
      // Set up enhanced event listeners
      this.setupEventListeners();
      
      // Initialize session with validation
      this.initializeSession();
      
      // Start enhanced timers
      this.startTimers();
      
      // Initialize location tracking
      if (this.config.enableLocationSync) {
        this.initializeLocationTracking();
      }
      
      // Start performance monitoring
      if (this.config.enablePerformanceMonitoring) {
        this.startPerformanceMonitoring();
      }
      
      // Initialize cleanup systems
      this.startCleanupSystems();
      
      this.log('Enhanced Session Tracker initialized successfully', 'info');
      
    } catch (error) {
      this.log('Error initializing Enhanced Session Tracker: ' + error.message, 'error');
      this.reportError('initialization_error', error);
    }
  }

  initializeSession() {
    // Generate session identifiers
    this.state.parentSessionId = this.generateSessionId();
    
    // Attempt session creation with retry
    this.createSessionWithRetry();
  }

  createSessionWithRetry(attempt = 1) {
    const maxAttempts = 3;
    
    this.createSession()
      .then((response) => {
        if (response.status === 'success') {
          this.state.sessionId = response.session_id;
          this.state.isActive = true;
          this.log(`Session created successfully: ${this.state.sessionId}`, 'info');
          
          // Start activity tracking
          this.startActivityTracking();
        } else {
          throw new Error(response.message || 'Session creation failed');
        }
      })
      .catch((error) => {
        this.log(`Session creation attempt ${attempt} failed: ${error.message}`, 'error');
        
        if (attempt < maxAttempts) {
          const delay = Math.pow(2, attempt - 1) * 1000; // Exponential backoff
          setTimeout(() => {
            this.createSessionWithRetry(attempt + 1);
          }, delay);
        } else {
          this.log('Failed to create session after maximum attempts', 'error');
          this.reportError('session_creation_failed', error);
        }
      });
  }

  createSession() {
    const sessionData = {
      tab_id: this.state.tabId,
      parent_session_id: this.state.parentSessionId,
      session_fingerprint: this.state.fingerprint,
      browser: this.state.browser,
      os: this.state.os,
      screen_resolution: `${screen.width}x${screen.height}`,
      timezone_offset: new Date().getTimezoneOffset(),
      language: navigator.language,
      timestamp: new Date().toISOString(),
    };

    return this.makeEnhancedRequest('/session/create/', sessionData, 'POST');
  }

  makeEnhancedRequest(url, data, method = 'POST', options = {}) {
    return new Promise((resolve, reject) => {
      const requestId = ++this.requestManager.lastRequestId;
      const startTime = performance.now();
      
      // Check for duplicate requests
      if (this.config.enableAdvancedDeduplication) {
        const requestHash = this.generateRequestHash(url, data);
        if (this.deduplication.requestHashes.has(requestHash)) {
          const duplicate = this.deduplication.requestHashes.get(requestHash);
          if (Date.now() - duplicate.timestamp < 5000) { // 5 second window
            this.state.duplicateRequestsBlocked++;
            this.log('Duplicate request blocked', 'debug');
            return resolve(duplicate.response);
          }
        }
      }
      
      // Check concurrent request limit
      if (this.requestManager.activeRequests >= this.config.maxConcurrentRequests) {
        this.requestManager.requestQueue.push({ url, data, method, options, resolve, reject });
        return;
      }
      
      this.requestManager.activeRequests++;
      
      const requestOptions = {
        method: method,
        headers: {
          'Content-Type': 'application/json',
          'X-Tab-ID': this.state.tabId,
          'X-Parent-Session-ID': this.state.parentSessionId,
          'X-Session-Fingerprint': this.state.fingerprint,
          'X-Screen-Resolution': this.state.screenInfo,
          'X-Timezone-Offset': new Date().getTimezoneOffset(),
          'X-Language': navigator.language,
          'X-Request-ID': requestId,
          ...options.headers,
        },
        body: JSON.stringify(data),
        signal: AbortSignal.timeout(this.config.requestTimeout),
      };

      // Add CSRF token
      const csrfToken = this.getCSRFToken();
      if (csrfToken) {
        requestOptions.headers['X-CSRFToken'] = csrfToken;
      }

      const request = fetch(url, requestOptions)
        .then(response => {
          const responseTime = performance.now() - startTime;
          this.updatePerformanceMetrics(responseTime, true);
          
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
          
          return response.json();
        })
        .then(result => {
          // Cache successful response for deduplication
          if (this.config.enableAdvancedDeduplication) {
            const requestHash = this.generateRequestHash(url, data);
            this.deduplication.requestHashes.set(requestHash, {
              response: result,
              timestamp: Date.now(),
            });
          }
          
          resolve(result);
        })
        .catch(error => {
          const responseTime = performance.now() - startTime;
          this.updatePerformanceMetrics(responseTime, false);
          this.reportError('request_failed', error, { url, method });
          reject(error);
        })
        .finally(() => {
          this.requestManager.activeRequests--;
          this.requestManager.pendingRequests.delete(requestId);
          
          // Process queued requests
          if (this.requestManager.requestQueue.length > 0) {
            const nextRequest = this.requestManager.requestQueue.shift();
            this.makeEnhancedRequest(
              nextRequest.url,
              nextRequest.data,
              nextRequest.method,
              nextRequest.options
            ).then(nextRequest.resolve).catch(nextRequest.reject);
          }
        });

      this.requestManager.pendingRequests.set(requestId, request);
    });
  }

  generateRequestHash(url, data) {
    const content = JSON.stringify({ url, data }, Object.keys({ url, data }).sort());
    return this.hashString(content);
  }

  flushBuffersEnhanced(force = false) {
    if (!this.state.isActive) return;

    const now = Date.now();
    if (!force && now - this.state.lastBatchFlush < this.config.batchFlushInterval) {
      return;
    }

    const activities = this.prepareActivitiesForFlush();
    if (activities.length === 0) return;

    // Enhanced deduplication at batch level
    const uniqueActivities = this.deduplicateActivities(activities);
    if (uniqueActivities.length === 0) {
      this.log('All activities were duplicates, skipping flush', 'debug');
      return;
    }

    const batchData = {
      tab_id: this.state.tabId,
      parent_session_id: this.state.parentSessionId,
      session_fingerprint: this.state.fingerprint,
      activities: uniqueActivities,
      timestamp: new Date().toISOString(),
      performance_metrics: this.getPerformanceSnapshot(),
      batch_id: this.generateBatchId(),
    };

    this.makeEnhancedRequest(this.config.batchActivityUrl, batchData)
      .then((response) => {
        this.state.lastBatchFlush = now;
        this.clearBuffers();
        this.log(`Flushed ${uniqueActivities.length} activities successfully`, 'info');
        
        // Update state based on response
        if (response.batch_mode) {
          this.state.batchingOptimized = true;
        }
      })
      .catch((error) => {
        // Enhanced retry with smart strategy
        this.addToRetryQueue('batch_activity', batchData, 'smart');
        this.log('Batch flush failed: ' + error.message, 'error');
      });
  }

  deduplicateActivities(activities) {
    const seen = new Set();
    return activities.filter(activity => {
      const hash = this.generateActivityHash(activity);
      if (seen.has(hash)) {
        return false;
      }
      seen.add(hash);
      return true;
    });
  }

  generateActivityHash(activity) {
    const key = `${activity.type}_${JSON.stringify(activity.data)}_${activity.timestamp}`;
    return this.hashString(key);
  }

  generateBatchId() {
    return `batch_${this.state.tabId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  updatePerformanceMetrics(responseTime, success) {
    this.state.totalRequests++;
    if (success) {
      this.state.averageResponseTime = 
        (this.state.averageResponseTime * (this.state.totalRequests - 1) + responseTime) / this.state.totalRequests;
    } else {
      this.state.failedRequests++;
    }
    
    // Store performance data
    this.performance.requests.push({
      timestamp: Date.now(),
      responseTime,
      success,
    });
    
    // Limit stored performance data
    if (this.performance.requests.length > 100) {
      this.performance.requests = this.performance.requests.slice(-50);
    }
  }

  getPerformanceSnapshot() {
    return {
      averageResponseTime: this.state.averageResponseTime,
      totalRequests: this.state.totalRequests,
      failedRequests: this.state.failedRequests,
      errorRate: this.state.failedRequests / Math.max(this.state.totalRequests, 1),
      duplicatesBlocked: this.state.duplicateRequestsBlocked,
      sessionDuration: Date.now() - this.state.sessionStartTime,
      bufferSizes: this.getBufferSizes(),
    };
  }

  getBufferSizes() {
    const sizes = {};
    for (const [key, buffer] of Object.entries(this.buffers)) {
      sizes[key] = buffer.length;
    }
    return sizes;
  }

  validateSessionDuration() {
    const duration = Date.now() - this.state.sessionStartTime;
    
    if (duration < this.config.minSessionDuration) {
      this.log('Session duration too short, extending minimum time', 'warning');
      return false;
    }
    
    if (duration > this.config.sessionTimeout) {
      this.log('Session exceeded maximum duration, ending session', 'warning');
      this.endSession('timeout');
      return false;
    }
    
    return true;
  }

  addToRetryQueue(type, data, strategy = 'exponential') {
    const retryItem = {
      id: Date.now() + Math.random(),
      type,
      data,
      strategy,
      attempts: 0,
      maxAttempts: this.config.maxRetries,
      nextRetryTime: Date.now() + this.config.retryDelay,
      createdAt: Date.now(),
    };
    
    this.retrySystem.queue.push(retryItem);
    this.processRetryQueue();
  }

  processRetryQueue() {
    if (this.retrySystem.processing) return;
    
    this.retrySystem.processing = true;
    
    const now = Date.now();
    const readyItems = this.retrySystem.queue.filter(item => now >= item.nextRetryTime);
    
    readyItems.forEach(item => {
      if (item.attempts >= item.maxAttempts) {
        this.log(`Max retries exceeded for ${item.type}`, 'error');
        this.removeFromRetryQueue(item.id);
        return;
      }
      
      item.attempts++;
      const delay = this.calculateRetryDelay(item);
      item.nextRetryTime = now + delay;
      
      this.executeRetry(item)
        .then(() => {
          this.removeFromRetryQueue(item.id);
          this.log(`Retry successful for ${item.type}`, 'info');
        })
        .catch((error) => {
          this.log(`Retry failed for ${item.type}: ${error.message}`, 'warning');
        });
    });
    
    this.retrySystem.processing = false;
  }

  calculateRetryDelay(item) {
    switch (item.strategy) {
      case 'immediate':
        return 0;
      case 'linear':
        return this.config.retryDelay * item.attempts;
      case 'exponential':
        return this.config.retryDelay * Math.pow(this.config.backoffMultiplier, item.attempts - 1);
      case 'smart':
        // Smart retry considers error rate and response times
        const errorRate = this.state.failedRequests / Math.max(this.state.totalRequests, 1);
        const multiplier = Math.max(1, errorRate * 5); // Increase delay based on error rate
        return this.config.retryDelay * multiplier * item.attempts;
      default:
        return this.config.retryDelay;
    }
  }

  executeRetry(item) {
    switch (item.type) {
      case 'batch_activity':
        return this.makeEnhancedRequest(this.config.batchActivityUrl, item.data);
      case 'heartbeat':
        return this.makeEnhancedRequest(this.config.heartbeatUrl, item.data);
      default:
        return Promise.reject(new Error(`Unknown retry type: ${item.type}`));
    }
  }

  removeFromRetryQueue(id) {
    this.retrySystem.queue = this.retrySystem.queue.filter(item => item.id !== id);
  }

  reportError(type, error, context = {}) {
    const errorReport = {
      type,
      message: error.message || error,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      sessionId: this.state.sessionId,
      tabId: this.state.tabId,
      url: window.location.href,
      userAgent: navigator.userAgent,
      context,
    };

    this.performance.errors.push(errorReport);
    this.addToBuffer('errors', errorReport);
    
    // Immediate error reporting for critical errors
    if (['session_creation_failed', 'critical_error'].includes(type)) {
      this.makeEnhancedRequest('/session/report-error/', errorReport);
    }
  }

  startCleanupSystems() {
    // Enhanced cleanup system
    this.timers.cleanup = setInterval(() => {
      this.cleanupOldData();
      this.cleanupDeduplicationCaches();
      this.optimizeBuffers();
    }, 300000); // 5 minutes

    // Deduplication cleanup
    this.timers.deduplication = setInterval(() => {
      this.cleanupDeduplicationCaches();
    }, this.deduplication.cleanupInterval);
  }

  cleanupDeduplicationCaches() {
    const now = Date.now();
    const cutoff = now - 300000; // 5 minutes
    
    // Cleanup request hashes
    for (const [hash, data] of this.deduplication.requestHashes.entries()) {
      if (data.timestamp < cutoff) {
        this.deduplication.requestHashes.delete(hash);
      }
    }
    
    // Cleanup activity hashes
    for (const [hash, timestamp] of this.deduplication.activityHashes.entries()) {
      if (timestamp < cutoff) {
        this.deduplication.activityHashes.delete(hash);
      }
    }
  }

  optimizeBuffers() {
    // Smart buffer optimization based on activity patterns
    for (const [key, buffer] of Object.entries(this.buffers)) {
      if (buffer.length > this.config[`max${key.charAt(0).toUpperCase() + key.slice(1)}Buffer`]) {
        const keepCount = Math.floor(this.config[`max${key.charAt(0).toUpperCase() + key.slice(1)}Buffer`] * 0.8);
        this.buffers[key] = buffer.slice(-keepCount);
        this.log(`Optimized ${key} buffer from ${buffer.length} to ${keepCount} items`, 'debug');
      }
    }
  }

  endSession(reason = 'user_action') {
    if (!this.state.isActive) return;
    
    this.log(`Ending session: ${reason}`, 'info');
    
    // Validate session duration
    const duration = Date.now() - this.state.sessionStartTime;
    if (duration < this.config.minSessionDuration) {
      this.log(`Session too short (${duration}ms), extending to minimum duration`, 'warning');
      setTimeout(() => this.endSession(reason), this.config.minSessionDuration - duration);
      return;
    }
    
    // Flush any remaining activities
    this.flushBuffersEnhanced(true);
    
    // Send end session request
    const endData = {
      session_id: this.state.sessionId,
      reason,
      duration: duration,
      performance_summary: this.getPerformanceSnapshot(),
      timestamp: new Date().toISOString(),
    };
    
    this.makeEnhancedRequest(this.config.endSessionUrl, endData);
    
    // Cleanup
    this.cleanup();
    this.state.isActive = false;
  }

  cleanup() {
    // Clear all timers
    Object.values(this.timers).forEach(timer => {
      if (timer) clearInterval(timer);
    });
    
    // Remove event listeners
    this.listeners.forEach((listener, element) => {
      element.removeEventListener(listener.event, listener.handler);
    });
    
    // Clear location tracking
    if (this.locationTracking.watchId) {
      navigator.geolocation.clearWatch(this.locationTracking.watchId);
    }
    
    // Clear caches
    this.deduplication.requestHashes.clear();
    this.deduplication.activityHashes.clear();
    
    this.log('Enhanced Session Tracker cleaned up', 'info');
  }

  // Additional helper methods...
  generateTabId() {
    return `tab_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : null;
  }

  detectBrowser() {
    const ua = navigator.userAgent;
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Edge')) return 'Edge';
    return 'Unknown';
  }

  detectOS() {
    const ua = navigator.userAgent;
    if (ua.includes('Windows')) return 'Windows';
    if (ua.includes('Mac OS')) return 'macOS';
    if (ua.includes('Linux')) return 'Linux';
    if (ua.includes('Android')) return 'Android';
    if (ua.includes('iOS')) return 'iOS';
    return 'Unknown';
  }

  getScreenInfo() {
    return `${screen.width}x${screen.height}@${screen.colorDepth}bit`;
  }

  log(message, level = 'info') {
    if (console && console[level]) {
      console[level](`[EnhancedSessionTracker] ${message}`);
    }
  }
}

// Global instance
window.EnhancedSessionTracker = EnhancedSessionTracker;

// Auto-initialize if DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.sessionTracker = new EnhancedSessionTracker();
  });
} else {
  window.sessionTracker = new EnhancedSessionTracker();
}