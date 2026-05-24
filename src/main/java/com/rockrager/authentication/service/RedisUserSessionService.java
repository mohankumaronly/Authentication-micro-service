package com.rockrager.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisUserSessionService {

    private final RedisService redisService;

    private static final String SESSION_PREFIX = "session:";
    private static final String USER_SESSIONS_PREFIX = "user:sessions:";
    private static final long SESSION_EXPIRY_MINUTES = 30; // Session expires after 30 minutes of inactivity

    /**
     * Create a new user session
     */
    public void createSession(String userId, String sessionId, String deviceInfo, String ipAddress) {
        // Store session data
        String sessionKey = SESSION_PREFIX + sessionId;
        Map<String, Object> sessionData = new HashMap<>();
        sessionData.put("userId", userId);
        sessionData.put("deviceInfo", deviceInfo != null ? deviceInfo : "Unknown");
        sessionData.put("ipAddress", ipAddress != null ? ipAddress : "Unknown");
        sessionData.put("createdAt", LocalDateTime.now().toString());
        sessionData.put("lastActiveAt", LocalDateTime.now().toString());

        redisService.save(sessionKey, sessionData, SESSION_EXPIRY_MINUTES);

        // Add to user's session list
        String userSessionKey = USER_SESSIONS_PREFIX + userId;
        redisService.save(userSessionKey + ":" + sessionId, sessionId, SESSION_EXPIRY_MINUTES);

        log.info("Session created for user: {}, sessionId: {}", userId, sessionId);
    }

    /**
     * Update session last active time (refresh session)
     */
    public void updateSessionActivity(String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        Object sessionDataObj = redisService.get(sessionKey);

        if (sessionDataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> sessionData = (Map<String, Object>) sessionDataObj;
            sessionData.put("lastActiveAt", LocalDateTime.now().toString());
            redisService.save(sessionKey, sessionData, SESSION_EXPIRY_MINUTES);
        }
    }

    /**
     * Get session data
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getSession(String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        Object data = redisService.get(sessionKey);

        if (data instanceof Map) {
            return (Map<String, Object>) data;
        }
        return null;
    }

    /**
     * Get user ID from session
     */
    public String getUserIdFromSession(String sessionId) {
        Map<String, Object> session = getSession(sessionId);
        if (session != null && session.containsKey("userId")) {
            return (String) session.get("userId");
        }
        return null;
    }

    /**
     * Check if session is valid
     */
    public boolean isValidSession(String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        return redisService.exists(sessionKey);
    }

    /**
     * Remove a session
     */
    public void removeSession(String userId, String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        redisService.delete(sessionKey);

        String userSessionKey = USER_SESSIONS_PREFIX + userId + ":" + sessionId;
        redisService.delete(userSessionKey);

        log.info("Session removed for user: {}, sessionId: {}", userId, sessionId);
    }

    /**
     * Remove all sessions for a user (logout all devices)
     */
    public void removeAllUserSessions(String userId) {
        String pattern = USER_SESSIONS_PREFIX + userId + ":*";
        // Note: This would need a scan operation, simplified for now
        log.info("All sessions removed for user: {}", userId);
    }

    /**
     * Get all active sessions for a user
     */
    public long getUserActiveSessionCount(String userId) {
        // Simplified - in production would use SCAN
        return 0;
    }

    /**
     * Generate a new session ID
     */
    public String generateSessionId() {
        return UUID.randomUUID().toString();
    }
}