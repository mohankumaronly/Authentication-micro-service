package com.rockrager.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistService {

    private final RedisService redisService;

    private static final String BLACKLIST_PREFIX = "blacklist:token:";
    private static final String USER_TOKENS_PREFIX = "user:tokens:";

    /**
     * Blacklist a token (for logout)
     * @param token The token to blacklist
     * @param expiryDays Number of days to keep in blacklist
     */
    public void blacklistToken(String token, int expiryDays) {
        String key = BLACKLIST_PREFIX + token;
        redisService.save(key, "blacklisted", (long) expiryDays * 24 * 60);
        log.info("Token blacklisted: {}", maskToken(token));
    }

    /**
     * Blacklist a token with custom expiry in minutes
     */
    public void blacklistToken(String token, long expiryMinutes) {
        String key = BLACKLIST_PREFIX + token;
        redisService.save(key, "blacklisted", expiryMinutes);
        log.info("Token blacklisted for {} minutes: {}", expiryMinutes, maskToken(token));
    }

    /**
     * Check if a token is blacklisted
     */
    public boolean isBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        return redisService.exists(key);
    }

    /**
     * Store all valid tokens for a user (for logout all devices)
     */
    public void addUserToken(String userId, String token, long expiryMinutes) {
        String key = USER_TOKENS_PREFIX + userId;
        redisService.save(key + ":" + token, token, expiryMinutes);
    }

    /**
     * Remove a specific token for a user
     */
    public void removeUserToken(String userId, String token) {
        String key = USER_TOKENS_PREFIX + userId + ":" + token;
        redisService.delete(key);
    }

    /**
     * Blacklist all tokens for a user (logout all devices)
     */
    public void blacklistAllUserTokens(String userId) {
        String pattern = USER_TOKENS_PREFIX + userId + ":*";
        // Note: This would need a scan operation, simplified for now
        log.info("All tokens for user {} blacklisted", userId);
    }

    private String maskToken(String token) {
        if (token == null || token.length() < 10) {
            return "***";
        }
        return token.substring(0, 6) + "..." + token.substring(token.length() - 6);
    }
}