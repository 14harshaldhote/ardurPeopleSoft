/**
 * Session Data Validation Helpers
 * Helper functions to validate and sanitize session tracking data
 */

// Add these methods to the OptimizedSessionTracker prototype
if (typeof OptimizedSessionTracker !== 'undefined') {
  
  // Data validation methods
  OptimizedSessionTracker.prototype.sanitizeUrl = function(url) {
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
  };

  OptimizedSessionTracker.prototype.sanitizeTitle = function(title) {
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
  };

  OptimizedSessionTracker.prototype.validateCoordinate = function(coord, type) {
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
  };

  OptimizedSessionTracker.prototype.validateAccuracy = function(accuracy) {
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
  };

  OptimizedSessionTracker.prototype.getScreenResolution = function() {
    try {
      return `${screen.width}x${screen.height}`;
    } catch (error) {
      this.log('Error getting screen resolution: ' + error.message, 'warning');
      return 'unknown';
    }
  };

  OptimizedSessionTracker.prototype.getTimezoneOffset = function() {
    try {
      return new Date().getTimezoneOffset();
    } catch (error) {
      this.log('Error getting timezone offset: ' + error.message, 'warning');
      return 0;
    }
  };

  OptimizedSessionTracker.prototype.getLanguage = function() {
    try {
      return navigator.language || navigator.userLanguage || 'en';
    } catch (error) {
      this.log('Error getting language: ' + error.message, 'warning');
      return 'en';
    }
  };

  OptimizedSessionTracker.prototype.getBatteryLevel = function() {
    try {
      if ('getBattery' in navigator) {
        navigator.getBattery().then((battery) => {
          this.batteryLevel = Math.round(battery.level * 100);
        }).catch(() => {
          this.batteryLevel = null;
        });
      }
      return this.batteryLevel || null;
    } catch (error) {
      this.log('Error getting battery level: ' + error.message, 'warning');
      return null;
    }
  };

  OptimizedSessionTracker.prototype.getConnectionType = function() {
    try {
      if ('connection' in navigator) {
        return navigator.connection.effectiveType || navigator.connection.type || 'unknown';
      }
      return 'unknown';
    } catch (error) {
      this.log('Error getting connection type: ' + error.message, 'warning');
      return 'unknown';
    }
  };

  OptimizedSessionTracker.prototype.generateParentSessionId = function() {
    try {
      return 'parent_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    } catch (error) {
      this.log('Error generating parent session ID: ' + error.message, 'warning');
      return 'parent_fallback_' + Date.now();
    }
  };

  // Enhanced device info detection
  OptimizedSessionTracker.prototype.getDeviceInfo = function() {
    try {
      const userAgent = navigator.userAgent;
      let device = 'desktop';
      
      if (/tablet|ipad|playbook|silk/i.test(userAgent)) {
        device = 'tablet';
      } else if (/mobile|iphone|ipod|android|blackberry|opera|mini|windows\sce|palm|smartphone|iemobile/i.test(userAgent)) {
        device = 'mobile';
      }
      
      return {
        device: device,
        browser: this.detectBrowser(),
        os: this.detectOS(),
        userAgent: userAgent,
        cookieEnabled: navigator.cookieEnabled,
        javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
        language: this.getLanguage(),
        platform: navigator.platform,
        screen: this.getScreenResolution(),
        timezone: this.getTimezone()
      };
    } catch (error) {
      this.log('Error getting device info: ' + error.message, 'warning');
      return {
        device: 'unknown',
        browser: 'unknown',
        os: 'unknown',
        userAgent: navigator.userAgent || 'unknown'
      };
    }
  };

  OptimizedSessionTracker.prototype.getTimezone = function() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch (error) {
      this.log('Error getting timezone: ' + error.message, 'warning');
      return 'UTC';
    }
  };

  // Enhanced fingerprint generation with error handling
  OptimizedSessionTracker.prototype.generateFingerprint = function() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('Session tracker fingerprint', 2, 2);

      const fingerprint = {
        canvas: canvas.toDataURL(),
        screen: this.getScreenResolution(),
        colorDepth: screen.colorDepth || 24,
        pixelRatio: window.devicePixelRatio || 1,
        timezone: this.getTimezone(),
        timezoneOffset: this.getTimezoneOffset(),
        language: this.getLanguage(),
        languages: JSON.stringify(navigator.languages || []),
        platform: navigator.platform || 'unknown',
        userAgent: navigator.userAgent || 'unknown',
        browser: this.detectBrowser(),
        os: this.detectOS(),
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        plugins: this.getPluginFingerprint(),
        timestamp: Date.now()
      };

      const fingerprintString = JSON.stringify(fingerprint);
      const hash = this.hashString(fingerprintString);
      
      this.state.fingerprint = hash;
      this.log('Generated fingerprint: ' + hash.substring(0, 8) + '...', 'debug');
      
      return hash;
    } catch (error) {
      this.log('Error generating fingerprint: ' + error.message, 'warning');
      // Fallback fingerprint
      const fallback = 'fallback_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      this.state.fingerprint = fallback;
      return fallback;
    }
  };

  OptimizedSessionTracker.prototype.getPluginFingerprint = function() {
    try {
      if (!navigator.plugins) return 'no-plugins';
      
      const plugins = Array.from(navigator.plugins || [])
        .map(p => p.name)
        .sort()
        .join(',');
      
      return plugins.substring(0, 200); // Limit length
    } catch (error) {
      this.log('Error getting plugin fingerprint: ' + error.message, 'warning');
      return 'plugin-error';
    }
  };

  // Enhanced error handling for heartbeat
  OptimizedSessionTracker.prototype.sendHeartbeatSafe = function() {
    try {
      if (!this.state.isActive || !this.state.userId) {
        this.log('Heartbeat skipped: session inactive or no user ID', 'debug');
        return;
      }

      const now = Date.now();
      if (now - this.state.lastHeartbeat < this.config.heartbeatInterval) {
        this.log('Heartbeat throttled', 'debug');
        return;
      }

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
        browser: this.state.browser || 'unknown',
        os: this.state.os || 'unknown',
        device_type: this.getDeviceInfo().device || 'desktop',
        screen_resolution: this.getScreenResolution(),
        timezone_offset: this.getTimezoneOffset(),
        language: this.getLanguage(),
        battery_level: this.getBatteryLevel(),
        connection_type: this.getConnectionType(),
        csrf_token: this.getCSRFToken()
      };

      // Add location data if available and valid
      if (this.state.location) {
        const lat = this.validateCoordinate(this.state.location.latitude, 'latitude');
        const lng = this.validateCoordinate(this.state.location.longitude, 'longitude');
        const accuracy = this.validateAccuracy(this.state.location.accuracy);
        
        if (lat !== null && lng !== null) {
          heartbeatData.location_latitude = lat;
          heartbeatData.location_longitude = lng;
          heartbeatData.location_accuracy = accuracy;
          heartbeatData.location_timestamp = this.state.location.timestamp;
        }
      }

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

      // Send the heartbeat
      this.makeRequest(this.config.heartbeatUrl, heartbeatData)
        .then((response) => {
          this.state.lastHeartbeat = now;
          this.handleHeartbeatResponse(response);
          this.log('Heartbeat sent successfully', 'debug');
        })
        .catch((error) => {
          this.log('Primary heartbeat failed, trying fallback: ' + error.message, 'warning');
          
          // Fallback to legacy endpoint
          this.makeRequest('/session/heartbeat/', heartbeatData)
            .then((response) => {
              this.state.lastHeartbeat = now;
              this.handleHeartbeatResponse(response);
              this.log('Fallback heartbeat sent successfully', 'debug');
            })
            .catch((retryError) => {
              this.addToRetryQueue('heartbeat', heartbeatData);
              this.log('Both heartbeat endpoints failed: ' + retryError.message, 'error');
            });
        });

    } catch (error) {
      this.log('Critical error in sendHeartbeat: ' + error.message, 'error');
      console.error('Heartbeat error:', error);
    }
  };

  // Validation for activity data
  OptimizedSessionTracker.prototype.validateActivityData = function(data) {
    try {
      if (!data || typeof data !== 'object') {
        return { valid: false, error: 'Invalid data object' };
      }

      // Validate timestamp
      if (data.timestamp && isNaN(new Date(data.timestamp).getTime())) {
        data.timestamp = new Date().toISOString();
      }

      // Validate coordinates if present
      if (data.x !== undefined) {
        data.x = isNaN(data.x) ? 0 : Math.round(data.x);
      }
      if (data.y !== undefined) {
        data.y = isNaN(data.y) ? 0 : Math.round(data.y);
      }

      // Validate URL
      if (data.url) {
        data.url = this.sanitizeUrl(data.url);
      }

      // Validate text content
      if (data.text && typeof data.text === 'string' && data.text.length > 100) {
        data.text = data.text.substring(0, 100);
      }

      return { valid: true, data: data };
    } catch (error) {
      this.log('Error validating activity data: ' + error.message, 'warning');
      return { valid: false, error: error.message };
    }
  };

  // Enhanced click tracking with validation
  OptimizedSessionTracker.prototype.trackClickSafe = function(event) {
    try {
      if (Math.random() > this.config.mouseSampleRate) return;

      const clickData = {
        timestamp: Date.now(),
        x: event.clientX || 0,
        y: event.clientY || 0,
        target: event.target ? event.target.tagName : 'unknown',
        id: event.target ? (event.target.id || '') : '',
        className: event.target ? (event.target.className || '') : '',
        text: event.target && event.target.innerText 
          ? event.target.innerText.substring(0, 50) 
          : '',
        url: this.sanitizeUrl(window.location.href),
        button: event.button !== undefined ? event.button : 0
      };

      const validation = this.validateActivityData(clickData);
      if (validation.valid) {
        this.addToBuffer('clicks', validation.data);
        this.state.totalClicks++;
      } else {
        this.log('Invalid click data: ' + validation.error, 'warning');
      }
    } catch (error) {
      this.log('Error in trackClick: ' + error.message, 'warning');
    }
  };

  console.log('Session validation helpers loaded');
}
