/**
 * Generate a UUID v4
 */
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * Get CSRF token from meta tag
 */
function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : null;
}

/**
 * Hash a string using a simple algorithm
 */
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString(36);
}

/**
 * Detect device type based on user agent and screen size
 */
function detectDeviceType() {
    const ua = navigator.userAgent;
    if (/(tablet|ipad|playbook|silk)|(android(?!.*mobi))/i.test(ua)) {
        return 'tablet';
    }
    if (/Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/.test(ua)) {
        return 'mobile';
    }
    return 'desktop';
}

/**
 * Calculate productivity score based on user activity
 */
function calculateProductivityScore(state) {
    console.log('Calculating productivity score...');
    
    // Initialize base score
    let score = 50; // Start with neutral score
    
    // Get current session duration in minutes
    const sessionDuration = (Date.now() - state.sessionStartTime) / (1000 * 60);    
    // Calculate idle percentage
    let idleTime = 0;
    if (state.isIdle && state.idleStartTime) {
        idleTime = (Date.now() - state.idleStartTime) / 1000;
    }
    if (state.total_idle_time) {
        idleTime += state.total_idle_time;
    }
    
    const idlePercentage = sessionDuration > 0 ? (idleTime / (sessionDuration * 60)) * 100 : 0;
    
    // Adjust score based on idle time (lower idle time = higher productivity)
    if (idlePercentage < 10) score += 15;
    else if (idlePercentage < 20) score += 10;
    else if (idlePercentage < 30) score += 5;
    else if (idlePercentage > 50) score -= 10;
    else if (idlePercentage > 70) score -= 20;
    
    // Adjust score based on keyboard and mouse activity
    const keyboardCount = state.activityBuffer.keystrokes ? state.activityBuffer.keystrokes.length : 0;
    const clickCount = state.activityBuffer.clicks ? state.activityBuffer.clicks.length : 0;
    const mouseMovements = state.activityBuffer.mouseMoves ? state.activityBuffer.mouseMoves.length : 0;
    
    // More activity generally indicates higher productivity
    const activityLevel = keyboardCount + clickCount + (mouseMovements / 10);
    if (activityLevel > 50) score += 15;
    else if (activityLevel > 30) score += 10;
    else if (activityLevel > 15) score += 5;
    else if (activityLevel < 5 && sessionDuration > 5) score -= 10; // Low activity over long period
    
    // Adjust for tab switching (moderate switching is good, excessive is distracting)
    if (state.tab_switches > 0) {
        const switchRate = state.tab_switches / sessionDuration;
        if (switchRate < 0.5) score += 5; // Focused work
        else if (switchRate > 2) score -= 10; // Too distracted
    }
    
    // Ensure score is within 0-100 range
    score = Math.max(0, Math.min(100, score));
    
    // Update state
    state.productivity_score = score;
    
    // Determine session quality based on score
    if (score >= 80) state.session_quality = 'excellent';
    else if (score >= 60) state.session_quality = 'good';
    else if (score >= 40) state.session_quality = 'average';
    else if (score >= 20) state.session_quality = 'poor';
    else state.session_quality = 'very_poor';
    
    return score;
}

/**
 * Calculate engagement score based on user interaction patterns
 */
function calculateEngagementScore(state) {
    
    // Initialize base score
    let score = 50; // Start with neutral score
    
    // Get current session duration in minutes
    const sessionDuration = (Date.now() - state.sessionStartTime) / (1000 * 60);
    
    // Adjust score based on session duration (longer sessions may indicate higher engagement)
    if (sessionDuration > 30) score += 10;
    else if (sessionDuration > 15) score += 5;
    else if (sessionDuration < 2) score -= 10; // Very short sessions may indicate low engagement
    
    // Adjust score based on scroll depth and frequency
    const scrollCount = state.activityBuffer.scrolls ? state.activityBuffer.scrolls.length : 0;
    let maxScrollPercent = 0;
    
    if (state.activityBuffer.scrolls && state.activityBuffer.scrolls.length > 0) {
        // Find maximum scroll percentage
        state.activityBuffer.scrolls.forEach(scroll => {
            if (scroll.scroll_percent && scroll.scroll_percent > maxScrollPercent) {
                maxScrollPercent = scroll.scroll_percent;
            }
        });
    }
    
    // Higher scroll depth indicates more content consumption
    if (maxScrollPercent > 80) score += 15;
    else if (maxScrollPercent > 50) score += 10;
    else if (maxScrollPercent > 30) score += 5;
    else if (maxScrollPercent < 10 && sessionDuration > 5) score -= 10; // Low scroll over long period
    
    // Adjust for click frequency (indicates interaction)
    const clickCount = state.activityBuffer.clicks ? state.activityBuffer.clicks.length : 0;
    const clickRate = sessionDuration > 0 ? clickCount / sessionDuration : 0;
    
    if (clickRate > 2) score += 15; // Very interactive
    else if (clickRate > 1) score += 10;
    else if (clickRate > 0.5) score += 5;
    else if (clickRate < 0.1 && sessionDuration > 5) score -= 10; // Very low interaction
    
    // Adjust for background time (less background time = more engagement)
    const backgroundTimeMinutes = state.background_time / (1000 * 60);
    const backgroundPercentage = sessionDuration > 0 ? (backgroundTimeMinutes / sessionDuration) * 100 : 0;
    
    if (backgroundPercentage < 10) score += 10;
    else if (backgroundPercentage > 50) score -= 15;
    else if (backgroundPercentage > 30) score -= 10;
    
    // Ensure score is within 0-100 range
    score = Math.max(0, Math.min(100, score));
    
    // Update state
    state.engagement_score = score;
    
    console.log(`Engagement score: ${score}`);
    return score;
}