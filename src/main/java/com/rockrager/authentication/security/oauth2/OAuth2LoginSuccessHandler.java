package com.rockrager.authentication.security.oauth2;

import com.rockrager.authentication.entity.AuthProvider;
import com.rockrager.authentication.entity.User;
import com.rockrager.authentication.entity.UserSession;
import com.rockrager.authentication.repository.UserRepository;
import com.rockrager.authentication.repository.UserSessionRepository;
import com.rockrager.authentication.security.jwt.JwtService;
import com.rockrager.authentication.service.DeviceInfoService;
import com.rockrager.authentication.service.EmailService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.HashMap;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserSessionRepository userSessionRepository;
    private final DeviceInfoService deviceInfoService;
    private final EmailService emailService;

    @Value("${app.frontend.url:https://prompt2page.onrender.com}")
    private String frontendUrl;

    @Value("${rate.limit.enabled:true}")
    private boolean rateLimitEnabled;

    @Value("${rate.limit.attempts:3}")
    private int maxAttempts;

    @Value("${rate.limit.duration-minutes:15}")
    private int durationMinutes;

    @Value("${rate.limit.block-duration-minutes:60}")
    private int blockDurationMinutes;

    private static class RateLimitInfo {
        int attempts;
        long firstAttemptTime;
        long blockUntil;

        RateLimitInfo(int attempts, long firstAttemptTime) {
            this.attempts = attempts;
            this.firstAttemptTime = firstAttemptTime;
            this.blockUntil = 0;
        }
    }

    private final ConcurrentHashMap<String, RateLimitInfo> rateLimitCache = new ConcurrentHashMap<>();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");
        String googleId = oAuth2User.getAttribute("sub");

        String issuer = oAuth2User.getAttribute("iss");
        if (issuer != null && !"https://accounts.google.com".equals(issuer)) {
            log.error("Invalid token issuer for user: {}, issuer: {}", email, issuer);
            response.sendRedirect(frontendUrl + "/auth/login?error=invalid_google_auth");
            return;
        }

        int rateLimitStatus = checkRateLimit(email);
        if (rateLimitStatus == 2) {
            log.warn("User is blocked for Google OAuth: {}", email);
            response.sendRedirect(frontendUrl + "/auth/login?error=account_blocked");
            return;
        }
        if (rateLimitStatus == 1) {
            log.warn("Rate limit active for Google OAuth: {}", email);
            response.sendRedirect(frontendUrl + "/auth/login?error=rate_limit_active");
            return;
        }

        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        String deviceInfo = deviceInfoService.getDeviceSummary(userAgent);
        String location = deviceInfoService.getLocationFromIp(ipAddress);

        boolean isNewUser = !userRepository.findByEmail(email).isPresent();

        User user;

        if (isNewUser) {
            user = User.builder()
                    .firstName(firstName != null ? firstName : "Google")
                    .lastName(lastName != null ? lastName : "User")
                    .email(email)
                    .password("")
                    .emailVerified(true)
                    .otpEnabled(false)
                    .role("USER")
                    .googleId(googleId)
                    .authProvider(AuthProvider.GOOGLE)
                    .loginCount(0)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();
            user = userRepository.save(user);
            log.info("Created new Google user: {} with ID: {}", email, user.getId());

            sendWelcomeEmail(user, ipAddress, location, deviceInfo);

        } else {
            user = userRepository.findByEmail(email).get();
            log.info("Existing user found: {} with login count: {}", email, user.getLoginCount());

            if (user.getAuthProvider() == AuthProvider.LOCAL && user.getGoogleId() == null) {
                user.setGoogleId(googleId);
                log.info("Linked Google account to existing local user: {}", email);
            }

            user.setLoginCount(user.getLoginCount() + 1);

            boolean isNewDevice = checkIfNewDevice(user, ipAddress, deviceInfo);
            boolean isNewLocation = checkIfNewLocation(user, location);

            user = userRepository.save(user);
            log.info("Updated user: {} - new login count: {}", email, user.getLoginCount());

            sendLoginNotificationEmail(user, ipAddress, location, deviceInfo, isNewDevice, isNewLocation);
        }

        // ✅ FIXED: Generate session ID and use enhanced JWT methods
        String sessionId = UUID.randomUUID().toString();

        String accessToken = jwtService.generateAccessToken(
                user.getEmail(),
                user.getId(),
                user.getRole(),
                sessionId
        );
        String refreshToken = jwtService.generateRefreshToken(
                user.getEmail(),
                user.getId(),
                sessionId
        );

        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        user.setLastLoginDevice(deviceInfo);
        user.setLastLoginLocation(location);
        userRepository.save(user);

        UserSession session = UserSession.builder()
                .user(user)
                .sessionId(sessionId)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .location(location)
                .loginAt(LocalDateTime.now())
                .active(true)
                .build();
        userSessionRepository.save(session);
        log.info("User session created for: {}", email);

        setCookie(response, "accessToken", accessToken, 900);
        setCookie(response, "refreshToken", refreshToken, 604800);

        log.info("Google login successful for user: {} from IP: {}, Device: {}", email, ipAddress, deviceInfo);

        recordSuccessfulAttempt(email);

        response.sendRedirect(frontendUrl + "/auth/oauth2/callback?success=true&token=" + accessToken);
    }

    private int checkRateLimit(String email) {
        if (!rateLimitEnabled) return 0;

        RateLimitInfo info = rateLimitCache.get(email);
        if (info == null) {
            return 0;
        }

        long now = System.currentTimeMillis();

        if (info.blockUntil > 0 && now < info.blockUntil) {
            long minutesLeft = (info.blockUntil - now) / 60000;
            long secondsLeft = ((info.blockUntil - now) / 1000) % 60;
            log.warn("User {} is blocked for {} minutes and {} seconds", email, minutesLeft, secondsLeft);
            return 2;
        }

        if (now - info.firstAttemptTime > durationMinutes * 60000L) {
            rateLimitCache.remove(email);
            log.info("Rate limit window expired for user: {}", email);
            return 0;
        }

        if (info.attempts >= maxAttempts) {
            info.blockUntil = now + (blockDurationMinutes * 60000L);
            long blockMinutes = blockDurationMinutes;
            log.warn("User {} exceeded {} attempts, blocked for {} minutes",
                    email, maxAttempts, blockMinutes);
            return 2;
        }

        long waitSeconds = (info.firstAttemptTime + (durationMinutes * 60000L) - now) / 1000;
        log.info("User {} has {} attempts left (total {}/{}), wait {} seconds",
                email, maxAttempts - info.attempts, info.attempts, maxAttempts, waitSeconds);
        return 1;
    }

    public void recordFailedAttempt(String email) {
        if (!rateLimitEnabled) return;

        long now = System.currentTimeMillis();
        RateLimitInfo info = rateLimitCache.get(email);

        if (info == null) {
            info = new RateLimitInfo(1, now);
            rateLimitCache.put(email, info);
            log.info("First failed attempt recorded for {}: 1/{}", email, maxAttempts);
        } else if (info.blockUntil == 0 || now > info.blockUntil) {
            info.attempts++;
            log.info("Failed attempt #{} recorded for {}: {}/{}",
                    info.attempts, email, info.attempts, maxAttempts);
        }
    }

    private void recordSuccessfulAttempt(String email) {
        rateLimitCache.remove(email);
        log.info("Successful login for {}, rate limit reset", email);
    }

    public Map<String, Object> getRateLimitStatus(String email) {
        Map<String, Object> status = new HashMap<>();
        RateLimitInfo info = rateLimitCache.get(email);

        if (info == null) {
            status.put("status", "active");
            status.put("message", "No rate limit restrictions");
            status.put("attempts", 0);
            status.put("maxAttempts", maxAttempts);
        } else if (info.blockUntil > 0 && System.currentTimeMillis() < info.blockUntil) {
            long remainingMillis = info.blockUntil - System.currentTimeMillis();
            status.put("status", "blocked");
            status.put("message", "Account is temporarily blocked");
            status.put("remainingSeconds", remainingMillis / 1000);
            status.put("remainingMinutes", remainingMillis / 60000);
        } else {
            long elapsed = System.currentTimeMillis() - info.firstAttemptTime;
            long windowRemaining = Math.max(0, durationMinutes * 60000L - elapsed);
            status.put("status", "cooling");
            status.put("message", "Rate limit active");
            status.put("attempts", info.attempts);
            status.put("maxAttempts", maxAttempts);
            status.put("remainingSeconds", windowRemaining / 1000);
            status.put("remainingMinutes", windowRemaining / 60000);
        }

        return status;
    }

    public void resetRateLimit(String email) {
        rateLimitCache.remove(email);
        log.info("Rate limit manually reset for user: {}", email);
    }

    private void sendWelcomeEmail(User user, String ipAddress, String location, String deviceInfo) {
        try {
            String loginTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String createdAt = user.getCreatedAt() != null ?
                    user.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) : loginTime;

            String htmlContent = String.format("""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <h2 style="color: #4CAF50;">Welcome %s %s! 🎉</h2>
                        <p>Thank you for joining RockRager Authentication using Google!</p>
                        <h3>Account Details:</h3>
                        <ul>
                            <li><strong>Email:</strong> %s</li>
                            <li><strong>Login Method:</strong> Google Account</li>
                        </ul>
                        <h3>First Login Information:</h3>
                        <ul>
                            <li><strong>Time:</strong> %s</li>
                            <li><strong>IP Address:</strong> %s</li>
                            <li><strong>Location:</strong> %s</li>
                            <li><strong>Device:</strong> %s</li>
                        </ul>
                        <p>You can also set a password later to enable email/password login.</p>
                        <p>If you didn't create this account, please contact support.</p>
                        <hr>
                        <p style="color: #666;">Best regards,<br>RockRager Team</p>
                    </div>
                </body>
                </html>
                """,
                    user.getFirstName(), user.getLastName(),
                    user.getEmail(),
                    loginTime, ipAddress, location, deviceInfo
            );

            emailService.sendGoogleWelcomeEmail(user.getEmail(), user.getFirstName(), htmlContent);
            log.info("Welcome email sent to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", user.getEmail(), e);
        }
    }

    private void sendLoginNotificationEmail(User user, String ipAddress, String location, String deviceInfo,
                                            boolean isNewDevice, boolean isNewLocation) {
        try {
            String warningMessage = "";
            if (isNewDevice || isNewLocation) {
                StringBuilder warning = new StringBuilder();
                warning.append("<div style='background-color:#fff3cd;border:1px solid #ffc107;padding:10px;border-radius:5px;margin:10px 0;'>");
                warning.append("<strong>⚠️ Security Alert:</strong> This login appears to be from a ");
                if (isNewDevice) warning.append("new device");
                if (isNewDevice && isNewLocation) warning.append(" and ");
                if (isNewLocation) warning.append("new location");
                warning.append(" that you haven't used before.</div>");
                warningMessage = warning.toString();
            }

            String loginTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            String htmlContent = String.format("""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <h2 style="color: #2196F3;">New Google Login Detected</h2>
                        <p>Hello %s %s,</p>
                        <p>We detected a new login using <strong>Google Authentication</strong>.</p>
                        %s
                        <h3>Login Details:</h3>
                        <ul>
                            <li><strong>Time:</strong> %s</li>
                            <li><strong>IP Address:</strong> %s</li>
                            <li><strong>Location:</strong> %s</li>
                            <li><strong>Device:</strong> %s</li>
                        </ul>
                        <p><strong>Login Count:</strong> %d</p>
                        <p><strong>If this wasn't you:</strong> Please click here to secure your account.</p>
                        <hr>
                        <p style="color: #666;">Best regards,<br>RockRager Team</p>
                    </div>
                </body>
                </html>
                """,
                    user.getFirstName(), user.getLastName(),
                    warningMessage,
                    loginTime, ipAddress, location, deviceInfo,
                    user.getLoginCount()
            );

            emailService.sendGoogleLoginEmail(user.getEmail(), user.getFirstName(), htmlContent);
            log.info("Login notification email sent to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send login notification email to: {}", user.getEmail(), e);
        }
    }

    private boolean checkIfNewDevice(User user, String ipAddress, String deviceInfo) {
        try {
            return !userSessionRepository.existsByUserAndDeviceInfoAndIpAddress(user, deviceInfo, ipAddress);
        } catch (Exception e) {
            log.warn("Error checking new device, assuming new device: {}", e.getMessage());
            return true;
        }
    }

    private boolean checkIfNewLocation(User user, String location) {
        try {
            return !userSessionRepository.existsByUserAndLocation(user, location);
        } catch (Exception e) {
            log.warn("Error checking new location, assuming new location: {}", e.getMessage());
            return true;
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String remoteAddr = request.getRemoteAddr();
        if ("0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            remoteAddr = "127.0.0.1";
        }
        return remoteAddr;
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        boolean isSecure = System.getenv("COOKIE_SECURE") != null
                ? Boolean.parseBoolean(System.getenv("COOKIE_SECURE"))
                : false;
        cookie.setSecure(isSecure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
        log.debug("Cookie set: {} - MaxAge: {} seconds, Secure: {}", name, maxAgeSeconds, isSecure);
    }
}