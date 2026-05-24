package com.rockrager.authentication.service;

import com.rockrager.authentication.dto.request.LoginRequest;
import com.rockrager.authentication.dto.request.OtpVerificationRequest;
import com.rockrager.authentication.dto.request.RegisterRequest;
import com.rockrager.authentication.dto.response.AuthResponse;
import com.rockrager.authentication.entity.*;
import com.rockrager.authentication.repository.*;
import com.rockrager.authentication.security.jwt.JwtService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final OtpCodeRepository otpCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final OtpService otpService;
    private final DeviceInfoService deviceInfoService;
    private final UserSessionRepository userSessionRepository;

    // Redis services
    private final RedisService redisService;
    private final RedisTokenBlacklistService tokenBlacklistService;
    private final RedisRateLimitService rateLimitService;
    private final RedisUserCacheService userCacheService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .emailVerified(false)
                .role("USER")
                .loginCount(0)
                .otpEnabled(true)
                .authProvider(AuthProvider.LOCAL)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        User savedUser = userRepository.save(user);
        log.info("User saved with ID: {}", savedUser.getId());

        String sessionId = UUID.randomUUID().toString();

        String accessToken = jwtService.generateAccessToken(
                savedUser.getEmail(),
                savedUser.getId(),
                savedUser.getRole(),
                sessionId
        );
        String refreshToken = jwtService.generateRefreshToken(
                savedUser.getEmail(),
                savedUser.getId(),
                sessionId
        );

        refreshTokenRepository.deleteByUser(savedUser);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(savedUser)
                .token(refreshToken)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        UserSession userSession = UserSession.builder()
                .user(savedUser)
                .sessionId(sessionId)
                .loginAt(LocalDateTime.now())
                .active(true)
                .build();
        userSessionRepository.save(userSession);

        String verificationToken = UUID.randomUUID().toString();

        EmailVerificationToken emailVerificationTokenEntity = EmailVerificationToken.builder()
                .token(verificationToken)
                .user(savedUser)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .build();

        emailVerificationTokenRepository.save(emailVerificationTokenEntity);

        // Cache the user
        userCacheService.cacheUser(savedUser);

        try {
            emailService.sendVerificationEmail(
                    savedUser.getEmail(),
                    savedUser.getFirstName(),
                    verificationToken
            );
            log.info("Verification email sent to: {}", savedUser.getEmail());
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", savedUser.getEmail(), e);
        }

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message("User registered successfully. Please check your email for verification link.")
                .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("Login attempt for email: {}", maskEmail(request.getEmail()));

        // Check rate limiting
        if (rateLimitService.isLoginRateLimited(request.getEmail())) {
            int remainingSeconds = rateLimitService.getRemainingLockoutSeconds(request.getEmail());
            throw new RuntimeException("Too many failed attempts. Please try again after " + remainingSeconds + " seconds.");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            rateLimitService.incrementLoginAttempts(request.getEmail());
            throw new RuntimeException("Invalid email or password");
        }

        // Reset login attempts on successful password
        rateLimitService.resetLoginAttempts(request.getEmail());

        if (!user.isEmailVerified()) {
            throw new RuntimeException("Please verify your email first. Check your inbox for verification link.");
        }

        boolean isFirstTimeLogin = user.getLoginCount() == 0;

        if (isFirstTimeLogin) {
            log.info("First time login for user: {}", user.getEmail());

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

            refreshTokenRepository.deleteByUser(user);
            RefreshToken refreshTokenEntity = RefreshToken.builder()
                    .user(user)
                    .token(refreshToken)
                    .expiresAt(LocalDateTime.now().plusDays(7))
                    .revoked(false)
                    .build();
            refreshTokenRepository.save(refreshTokenEntity);

            UserSession userSession = UserSession.builder()
                    .user(user)
                    .sessionId(sessionId)
                    .loginAt(LocalDateTime.now())
                    .active(true)
                    .deviceInfo(request.getDeviceInfo())
                    .ipAddress(request.getIpAddress())
                    .build();
            userSessionRepository.save(userSession);

            user.setLoginCount(1);
            user.setLastLoginAt(LocalDateTime.now());
            user.setLastLoginDevice(request.getDeviceInfo());
            user.setLastLoginIp(request.getIpAddress());
            userRepository.save(user);

            // Update cache
            userCacheService.cacheUser(user);

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .message("Login successful")
                    .build();
        } else {
            log.info("Returning user - sending OTP for: {}", user.getEmail());

            otpCodeRepository.deleteByUserAndUsedFalse(user);

            String sessionId = UUID.randomUUID().toString();

            String otpCode = otpService.generateAndSendOtp(
                    user,
                    sessionId,
                    request.getDeviceInfo(),
                    request.getIpAddress()
            );

            // Store OTP in Redis as well (for faster access)
            redisService.save("otp:" + sessionId, otpCode, 5);

            log.info("OTP sent to user: {} for session: {}", user.getEmail(), sessionId);

            return AuthResponse.builder()
                    .requiresOtp(true)
                    .sessionId(sessionId)
                    .email(maskEmail(user.getEmail()))
                    .message("OTP sent to your email. Please verify to complete login.")
                    .expiresIn((long) otpService.getOtpExpirySeconds())
                    .build();
        }
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {

        // Check if token is blacklisted
        if (tokenBlacklistService.isBlacklisted(refreshToken)) {
            throw new RuntimeException("Token has been revoked");
        }

        RefreshToken storedToken = refreshTokenRepository
                .findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (storedToken.isRevoked()) {
            tokenBlacklistService.blacklistToken(refreshToken, 7);
            throw new RuntimeException("Refresh token revoked");
        }

        if (storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(storedToken);
            throw new RuntimeException("Refresh token expired");
        }

        User user = storedToken.getUser();

        String sessionId = UUID.randomUUID().toString();

        String newAccessToken = jwtService.generateAccessToken(
                user.getEmail(),
                user.getId(),
                user.getRole(),
                sessionId
        );

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .message("Access token refreshed")
                .build();
    }

    @Transactional
    public String logout(String refreshToken) {

        // Blacklist the refresh token
        tokenBlacklistService.blacklistToken(refreshToken, 7);

        RefreshToken token = refreshTokenRepository
                .findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        token.setRevoked(true);
        refreshTokenRepository.save(token);

        return "Logout successful";
    }

    @Transactional
    public String verifyEmail(String token) {
        EmailVerificationToken verificationToken = emailVerificationTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            emailVerificationTokenRepository.delete(verificationToken);
            throw new RuntimeException("Verification token expired. Please register again.");
        }

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        // Update cache
        userCacheService.cacheUser(user);

        emailVerificationTokenRepository.delete(verificationToken);

        log.info("Email verified successfully for user: {} ({})", user.getEmail(), user.getFirstName());

        sendWelcomeEmailWithRetry(user.getEmail(), user.getFirstName(), 3);

        return "Email verified successfully. You can now login.";
    }

    private void sendWelcomeEmailWithRetry(String email, String firstName, int maxRetries) {
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                emailService.sendWelcomeEmail(email, firstName);
                log.info("Welcome email sent successfully to: {} on attempt {}", email, attempt);
                return;
            } catch (Exception e) {
                log.warn("Failed to send welcome email to: {} on attempt {}/{}", email, attempt, maxRetries, e);
                if (attempt == maxRetries) {
                    log.error("Failed to send welcome email to: {} after {} attempts", email, maxRetries);
                    storeFailedEmailNotification(email, firstName, "WELCOME");
                }
                try {
                    Thread.sleep(1000 * attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private void storeFailedEmailNotification(String email, String firstName, String emailType) {
        log.info("Storing failed email notification for: {} of type: {}", email, emailType);
    }

    @Transactional
    public String forgotPassword(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

        passwordResetTokenRepository.findByToken(email).ifPresent(existingToken ->
                passwordResetTokenRepository.delete(existingToken)
        );

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .build();

        passwordResetTokenRepository.save(resetToken);

        try {
            emailService.sendPasswordResetEmail(
                    user.getEmail(),
                    user.getFirstName(),
                    token
            );
            log.info("Password reset email sent to: {} ({})", user.getEmail(), user.getFirstName());
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", user.getEmail(), e);
            throw new RuntimeException("Failed to send password reset email. Please try again.");
        }

        return "Password reset instructions sent to your email. Please check your inbox.";
    }

    @Transactional
    public String resetPassword(String token, String newPassword) {

        PasswordResetToken resetToken = passwordResetTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid or expired reset token"));

        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            passwordResetTokenRepository.delete(resetToken);
            throw new RuntimeException("Reset token has expired. Please request a new one.");
        }

        User user = resetToken.getUser();

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Update cache
        userCacheService.cacheUser(user);

        passwordResetTokenRepository.delete(resetToken);

        refreshTokenRepository.deleteByUser(user);

        log.info("Password reset successful for user: {}", user.getEmail());

        return "Password reset successful. Please login with your new password.";
    }

    @Transactional
    public AuthResponse verifyOtpAndLogin(OtpVerificationRequest request) {
        log.info("Verifying OTP for session: {}", request.getSessionId());

        // Check rate limiting
        if (rateLimitService.isOtpRateLimited(request.getSessionId())) {
            throw new RuntimeException("Too many OTP attempts. Please request a new OTP.");
        }

        boolean isValid = otpService.validateOtp(request.getSessionId(), request.getOtpCode());
        if (!isValid) {
            rateLimitService.incrementOtpAttempts(request.getSessionId());
            throw new RuntimeException("Invalid or expired OTP. Please try again.");
        }

        // Reset OTP attempts on success
        rateLimitService.resetOtpAttempts(request.getSessionId());

        OtpCode otpRecord = otpService.getOtpRecord(request.getSessionId())
                .orElseThrow(() -> new RuntimeException("Session not found"));

        // Get user by ID to avoid Hibernate proxy issues
        User user = userRepository.findById(otpRecord.getUser().getId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Extract values early to avoid any lazy loading issues
        String userEmail = user.getEmail();
        UUID userId = user.getId();
        String userRole = user.getRole();
        String userFirstName = user.getFirstName();
        String userLastName = user.getLastName();
        String deviceInfo = otpRecord.getDeviceInfo();
        String ipAddress = otpRecord.getIpAddress();

        String sessionId = UUID.randomUUID().toString();
        String accessToken = jwtService.generateAccessToken(
                userEmail,
                userId,
                userRole,
                sessionId
        );
        String refreshToken = jwtService.generateRefreshToken(
                userEmail,
                userId,
                sessionId
        );

        refreshTokenRepository.deleteByUser(user);
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        UserSession userSession = UserSession.builder()
                .user(user)
                .sessionId(sessionId)
                .loginAt(LocalDateTime.now())
                .active(true)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .build();
        userSessionRepository.save(userSession);

        try {
            String location = deviceInfoService.getLocationFromIp(ipAddress);
            user.setLastLoginLocation(location);
            userSession.setLocation(location);
        } catch (Exception e) {
            log.warn("Could not get location for IP: {}", ipAddress);
        }

        user.setLoginCount(user.getLoginCount() + 1);
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginDevice(deviceInfo);
        user.setLastLoginIp(ipAddress);
        userRepository.save(user);

        // Update cache
        userCacheService.cacheUser(user);

        // Clean up Redis OTP
        redisService.delete("otp:" + request.getSessionId());

        // Send notification email using primitive values, NOT the user proxy or otpRecord
        try {
            sendLoginNotificationEmail(userEmail, userFirstName, userLastName, deviceInfo, ipAddress);
        } catch (Exception e) {
            log.error("Failed to send login notification email to: {}", userEmail, e);
        }

        otpService.cleanupExpiredOtps(user);

        log.info("User logged in successfully: {} from IP: {}", userEmail, ipAddress);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message("Login successful")
                .build();
    }

    private void sendLoginNotificationEmail(String email, String firstName, String lastName, String deviceInfo, String ipAddress) {
        String subject = "New Login Detected - RockRager Authentication";
        String location = "Unknown Location";
        String loginTime = LocalDateTime.now().toString();

        String body = String.format("""
        Hello %s %s,
        
        We detected a new login to your account.
        
        Login Details:
        • Time: %s
        • IP Address: %s
        • Location: %s
        • Device: %s
        
        If this was you, you can ignore this email.
        
        If this wasn't you, please reset your password immediately and contact support.
        
        Best regards,
        RockRager Team
        """,
                firstName,
                lastName,
                loginTime,
                ipAddress != null ? ipAddress : "Unknown IP",
                location,
                deviceInfo != null ? deviceInfo : "Unknown Device"
        );

        try {
            emailService.sendLoginNotificationEmail(email, firstName, subject, body);
        } catch (Exception e) {
            log.error("Failed to send login notification", e);
        }
    }

    private void sendLoginNotificationEmail(String email, String firstName, String lastName, OtpCode otpRecord) {
        String subject = "New Login Detected - RockRager Authentication";

        String deviceInfo = otpRecord.getDeviceInfo() != null ? otpRecord.getDeviceInfo() : "Unknown Device";
        String ipAddress = otpRecord.getIpAddress() != null ? otpRecord.getIpAddress() : "Unknown IP";
        String location = "Unknown Location";
        String loginTime = LocalDateTime.now().toString();

        String body = String.format("""
        Hello %s %s,
        
        We detected a new login to your account.
        
        Login Details:
        • Time: %s
        • IP Address: %s
        • Location: %s
        • Device: %s
        
        If this was you, you can ignore this email.
        
        If this wasn't you, please reset your password immediately and contact support.
        
        Best regards,
        RockRager Team
        """,
                firstName,
                lastName,
                loginTime,
                ipAddress,
                location,
                deviceInfo
        );

        try {
            emailService.sendLoginNotificationEmail(email, firstName, subject, body);
        } catch (Exception e) {
            log.error("Failed to send login notification", e);
        }
    }

    private void sendLoginNotificationEmail(User user, OtpCode otpRecord) {
        String subject = "New Login Detected - RockRager Authentication";

        String deviceInfo = otpRecord.getDeviceInfo() != null ? otpRecord.getDeviceInfo() : "Unknown Device";
        String ipAddress = otpRecord.getIpAddress() != null ? otpRecord.getIpAddress() : "Unknown IP";
        String location = user.getLastLoginLocation() != null ? user.getLastLoginLocation() : "Unknown Location";
        String loginTime = LocalDateTime.now().toString();

        String body = String.format("""
        Hello %s %s,
        
        We detected a new login to your account.
        
        Login Details:
        • Time: %s
        • IP Address: %s
        • Location: %s
        • Device: %s
        
        If this was you, you can ignore this email.
        
        If this wasn't you, please reset your password immediately and contact support.
        
        Best regards,
        RockRager Team
        """,
                user.getFirstName(),
                user.getLastName(),
                loginTime,
                ipAddress,
                location,
                deviceInfo
        );

        try {
            emailService.sendLoginNotificationEmail(user.getEmail(), user.getFirstName(), subject, body);
        } catch (Exception e) {
            log.error("Failed to send login notification", e);
            throw e;
        }
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