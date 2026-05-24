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

    private static final long LOCKOUT_MINUTES = 15;
    private static final long ATTEMPT_WINDOW_MINUTES = 15;

    // ==================== LOGIN RATE LIMITING ====================

    /**
     * Check if login is rate limited for an email
     */
    public boolean isLoginRateLimited(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts >= MAX_LOGIN_ATTEMPTS) {
            log.warn("Login rate limited for email: {}", maskEmail(email));
            return true;
        }
        return false;
    }

    /**
     * Increment login attempts for an email
     */
    public void incrementLoginAttempts(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts == null) {
            redisService.save(key, 1, ATTEMPT_WINDOW_MINUTES);
        } else {
            redisService.save(key, attempts + 1, ATTEMPT_WINDOW_MINUTES);
        }

        log.info("Login attempts for {}: {}/{}", maskEmail(email), attempts + 1, MAX_LOGIN_ATTEMPTS);
    }

    /**
     * Reset login attempts after successful login
     */
    public void resetLoginAttempts(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        redisService.delete(key);
        log.info("Login attempts reset for: {}", maskEmail(email));
    }

    /**
     * Get remaining lockout seconds for an email
     */
    public int getRemainingLockoutSeconds(String email) {
        String key = LOGIN_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts != null && attempts >= MAX_LOGIN_ATTEMPTS) {
            return (int) (ATTEMPT_WINDOW_MINUTES * 60);
        }
        return 0;
    }

    // ==================== REGISTRATION RATE LIMITING ====================

    /**
     * Check if registration is rate limited for an email
     */
    public boolean isRegistrationRateLimited(String email) {
        String key = REGISTRATION_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts >= MAX_REGISTRATION_ATTEMPTS) {
            log.warn("Registration rate limited for email: {}", maskEmail(email));
            return true;
        }
        return false;
    }

    /**
     * Increment registration attempts for an email
     */
    public void incrementRegistrationAttempts(String email) {
        String key = REGISTRATION_ATTEMPTS_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts == null) {
            redisService.save(key, 1, ATTEMPT_WINDOW_MINUTES);
        } else {
            redisService.save(key, attempts + 1, ATTEMPT_WINDOW_MINUTES);
        }
    }

    /**
     * Reset registration attempts
     */
    public void resetRegistrationAttempts(String email) {
        String key = REGISTRATION_ATTEMPTS_PREFIX + email;
        redisService.delete(key);
    }

    // ==================== EMAIL VERIFICATION RATE LIMITING ====================

    /**
     * Check if email verification is rate limited
     */
    public boolean isEmailVerificationRateLimited(String email) {
        String key = EMAIL_VERIFICATION_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts >= MAX_EMAIL_VERIFICATION_ATTEMPTS) {
            log.warn("Email verification rate limited for email: {}", maskEmail(email));
            return true;
        }
        return false;
    }

    /**
     * Increment email verification attempts
     */
    public void incrementEmailVerificationAttempts(String email) {
        String key = EMAIL_VERIFICATION_PREFIX + email;
        Integer attempts = getAttemptCount(key);

        if (attempts == null) {
            redisService.save(key, 1, ATTEMPT_WINDOW_MINUTES);
        } else {
            redisService.save(key, attempts + 1, ATTEMPT_WINDOW_MINUTES);
        }
    }

    /**
     * Reset email verification attempts
     */
    public void resetEmailVerificationAttempts(String email) {
        String key = EMAIL_VERIFICATION_PREFIX + email;
        redisService.delete(key);
    }

    // ==================== OTP RATE LIMITING ====================

    /**
     * Check if OTP verification is rate limited for a session
     */
    public boolean isOtpRateLimited(String sessionId) {
        String key = OTP_ATTEMPTS_PREFIX + sessionId;
        Integer attempts = getAttemptCount(key);

        if (attempts >= MAX_OTP_ATTEMPTS) {
            log.warn("OTP rate limited for session: {}", sessionId);
            return true;
        }
        return false;
    }

    /**
     * Increment OTP verification attempts
     */
    public void incrementOtpAttempts(String sessionId) {
        String key = OTP_ATTEMPTS_PREFIX + sessionId;
        Integer attempts = getAttemptCount(key);

        if (attempts == null) {
            redisService.save(key, 1, ATTEMPT_WINDOW_MINUTES);
        } else {
            redisService.save(key, attempts + 1, ATTEMPT_WINDOW_MINUTES);
        }
    }

    /**
     * Reset OTP attempts after successful verification
     */
    public void resetOtpAttempts(String sessionId) {
        String key = OTP_ATTEMPTS_PREFIX + sessionId;
        redisService.delete(key);
    }

    // ==================== HELPER METHODS ====================

    private Integer getAttemptCount(String key) {
        Object value = redisService.get(key);
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