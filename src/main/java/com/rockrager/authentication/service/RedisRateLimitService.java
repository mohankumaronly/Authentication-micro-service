package com.rockrager.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisRateLimitService {

    private final RedisService redisService;

    private static final String LOGIN_ATTEMPTS_PREFIX = "ratelimit:login:";
    private static final String REGISTRATION_ATTEMPTS_PREFIX = "ratelimit:registration:";
    private static final String EMAIL_VERIFICATION_PREFIX = "ratelimit:email_verify:";
    private static final String OTP_ATTEMPTS_PREFIX = "ratelimit:otp:";

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final int MAX_REGISTRATION_ATTEMPTS = 3;
    private static final int MAX_EMAIL_VERIFICATION_ATTEMPTS = 3;
    private static final int MAX_OTP_ATTEMPTS = 3;

    private static final long ATTEMPT_WINDOW_MINUTES = 15;

    // ==================== LOGIN RATE LIMITING ====================

    public boolean isLoginRateLimited(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts != null && attempts >= MAX_LOGIN_ATTEMPTS) {
            log.warn("Login rate limited for email: {}", maskEmail(email));
            return true;
        }
        return false;
    }

    public void incrementLoginAttempts(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        int newAttempts = (attempts == null ? 0 : attempts) + 1;
        redisService.save(key, newAttempts, ATTEMPT_WINDOW_MINUTES);

        log.info("Login attempts for {}: {}/{}", maskEmail(email), newAttempts, MAX_LOGIN_ATTEMPTS);
    }

    public void resetLoginAttempts(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        redisService.delete(key);
        log.info("Login attempts reset for: {}", maskEmail(email));
    }

    public int getRemainingLockoutSeconds(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts != null && attempts >= MAX_LOGIN_ATTEMPTS) {
            return (int) (ATTEMPT_WINDOW_MINUTES * 60);
        }
        return 0;
    }

    // ==================== REGISTRATION RATE LIMITING ====================

    public boolean isRegistrationRateLimited(String email) {
        String key = REGISTRATION_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts != null && attempts >= MAX_REGISTRATION_ATTEMPTS) {
            log.warn("Registration rate limited for email: {}", maskEmail(email));
            return true;
        }
        return false;
    }

    public void incrementRegistrationAttempts(String email) {
        String key = REGISTRATION_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        int newAttempts = (attempts == null ? 0 : attempts) + 1;
        redisService.save(key, newAttempts, ATTEMPT_WINDOW_MINUTES);
    }

    public void resetRegistrationAttempts(String email) {
        String key = REGISTRATION_ATTEMPTS_PREFIX + email;
        redisService.delete(key);
    }

    // ==================== EMAIL VERIFICATION RATE LIMITING ====================

    public boolean isEmailVerificationRateLimited(String email) {
        String key = EMAIL_VERIFICATION_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts != null && attempts >= MAX_EMAIL_VERIFICATION_ATTEMPTS) {
            log.warn("Email verification rate limited for email: {}", maskEmail(email));
            return true;
        }
        return false;
    }

    public void incrementEmailVerificationAttempts(String email) {
        String key = EMAIL_VERIFICATION_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        int newAttempts = (attempts == null ? 0 : attempts) + 1;
        redisService.save(key, newAttempts, ATTEMPT_WINDOW_MINUTES);
    }

    public void resetEmailVerificationAttempts(String email) {
        String key = EMAIL_VERIFICATION_PREFIX + email;
        redisService.delete(key);
    }

    // ==================== OTP RATE LIMITING ====================

    public boolean isOtpRateLimited(String sessionId) {
        String key = OTP_ATTEMPTS_PREFIX + sessionId;
        Integer attempts = getAttemptCount(key);

        if (attempts != null && attempts >= MAX_OTP_ATTEMPTS) {
            log.warn("OTP rate limited for session: {}", sessionId);
            return true;
        }
        return false;
    }

    public void incrementOtpAttempts(String sessionId) {
        String key = OTP_ATTEMPTS_PREFIX + sessionId;
        Integer attempts = getAttemptCount(key);

        int newAttempts = (attempts == null ? 0 : attempts) + 1;
        redisService.save(key, newAttempts, ATTEMPT_WINDOW_MINUTES);
    }

    public void resetOtpAttempts(String sessionId) {
        String key = OTP_ATTEMPTS_PREFIX + sessionId;
        redisService.delete(key);
    }

    // ==================== HELPER METHODS ====================

    private Integer getAttemptCount(String key) {
        Object value = redisService.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return null;
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }
        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];

        if (localPart.length() <= 2) {
            return "*" + "@" + domain;
        }

        String maskedLocal = localPart.substring(0, 2) + "***" + localPart.substring(localPart.length() - 1);
        return maskedLocal + "@" + domain;
    }
}