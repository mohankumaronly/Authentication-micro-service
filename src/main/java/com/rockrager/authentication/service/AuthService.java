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
import java.util.Optional;
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

    // New Redis services
    private final RedisService redisService;
    private final RedisTokenBlacklistService tokenBlacklistService;
    private final RedisUserSessionService userSessionService;
    private final RedisRateLimitService rateLimitService;
    private final RedisUserCacheService userCacheService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registration attempt for email: {}", request.getEmail());

        // Check rate limiting for registration
        if (rateLimitService.isRegistrationRateLimited(request.getEmail())) {
            throw new RuntimeException("Too many registration attempts. Please try again after 15 minutes.");
        }

        // Check if user already exists and is verified
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());

        if (existingUser.isPresent()) {
            User user = existingUser.get();

            // If email is already verified, throw error
            if (user.isEmailVerified()) {
                throw new RuntimeException("Email already registered. Please login.");
            }

            // If email is not verified, delete the pending user and allow re-registration
            if (!user.isEmailVerified() && user.isPendingVerification()) {
                log.info("Deleting pending user with unverified email: {}", request.getEmail());
                userRepository.delete(user);
                // Also clean up any Redis verification data
                redisService.delete("email_verification:" + request.getEmail());
            }
        }

        // Check if there's a pending verification in Redis
        String redisKey = "email_verification:" + request.getEmail();
        EmailVerificationCode existingCode = (EmailVerificationCode) redisService.get(redisKey);

        if (existingCode != null) {
            log.info("Resending verification code to: {}", request.getEmail());
            // Resend the code
            sendVerificationCode(request.getEmail(), request.getFirstName(), request.getLastName(), request.getPassword());
            throw new RuntimeException("A verification code has been sent to your email. Please check and verify.");
        }

        // Increment registration attempt counter
        rateLimitService.incrementRegistrationAttempts(request.getEmail());

        // Send verification code via email
        sendVerificationCode(request.getEmail(), request.getFirstName(), request.getLastName(), request.getPassword());

        return AuthResponse.builder()
                .message("Verification code sent to your email. Please check and verify to complete registration.")
                .email(maskEmail(request.getEmail()))
                .build();
    }

    private void sendVerificationCode(String email, String firstName, String lastName, String password) {
        // Generate 6-digit verification code
        String verificationCode = String.format("%06d", new java.util.Random().nextInt(999999));

        // Store in Redis with 5 minutes expiry
        EmailVerificationCode verificationData = EmailVerificationCode.builder()
                .id(email)
                .email(email)
                .code(verificationCode)
                .firstName(firstName)
                .lastName(lastName)
                .password(passwordEncoder.encode(password))
                .createdAt(LocalDateTime.now())
                .attempts(0)
                .build();

        redisService.save("email_verification:" + email, verificationData, 5);

        // Send email with verification code
        try {
            emailService.sendEmailVerificationCode(email, firstName, verificationCode);
            log.info("Verification code sent to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send verification code to: {}", email, e);
            throw new RuntimeException("Failed to send verification email. Please try again.");
        }
    }

    @Transactional
    public AuthResponse verifyEmailAndCompleteRegistration(String email, String code) {
        log.info("Verifying email for: {}", email);

        // Check rate limiting
        if (rateLimitService.isEmailVerificationRateLimited(email)) {
            throw new RuntimeException("Too many verification attempts. Please try again after 15 minutes.");
        }

        // Get verification data from Redis
        String redisKey = "email_verification:" + email;
        EmailVerificationCode verificationData = (EmailVerificationCode) redisService.get(redisKey);

        if (verificationData == null) {
            throw new RuntimeException("Verification code expired or not found. Please register again.");
        }

        // Check attempts
        if (verificationData.isMaxAttemptsReached()) {
            redisService.delete(redisKey);
            throw new RuntimeException("Too many failed attempts. Please register again.");
        }

        // Verify code
        if (!verificationData.getCode().equals(code)) {
            verificationData.incrementAttempts();
            redisService.save(redisKey, verificationData, 5);
            rateLimitService.incrementEmailVerificationAttempts(email);
            throw new RuntimeException("Invalid verification code. Please try again.");
        }

        // Code is valid - create the user in database
        User user = User.builder()
                .firstName(verificationData.getFirstName())
                .lastName(verificationData.getLastName())
                .email(verificationData.getEmail())
                .password(verificationData.getPassword())
                .emailVerified(true)
                .pendingVerification(false)
                .role("USER")
                .loginCount(0)
                .otpEnabled(true)
                .authProvider(AuthProvider.LOCAL)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User registered and verified successfully: {}", savedUser.getEmail());

        // Clean up Redis
        redisService.delete(redisKey);

        // Send welcome email
        try {
            emailService.sendWelcomeEmail(savedUser.getEmail(), savedUser.getFirstName());
        } catch (Exception e) {
            log.warn("Failed to send welcome email to: {}", savedUser.getEmail(), e);
        }

        // Generate tokens for auto-login
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

        // Store session in Redis
        userSessionService.createSession(savedUser.getId().toString(), sessionId, "Registration", "System");

        // Save refresh token in database
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(savedUser)
                .token(refreshToken)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        // Cache user data
        userCacheService.cacheUser(savedUser);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message("Email verified and registration completed successfully!")
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

            // Store in Redis session
            userSessionService.createSession(user.getId().toString(), sessionId, request.getDeviceInfo(), request.getIpAddress());

            refreshTokenRepository.deleteByUser(user);
            RefreshToken refreshTokenEntity = RefreshToken.builder()
                    .user(user)
                    .token(refreshToken)
                    .expiresAt(LocalDateTime.now().plusDays(7))
                    .revoked(false)
                    .build();
            refreshTokenRepository.save(refreshTokenEntity);

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

            // Store OTP in Redis
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

        // Get the token and revoke it in database
        RefreshToken token = refreshTokenRepository
                .findByToken(refreshToken)
                .orElse(null);

        if (token != null) {
            token.setRevoked(true);
            refreshTokenRepository.save(token);

            // Remove user session from Redis
            userSessionService.removeSession(token.getUser().getId().toString(), refreshToken);
        }

        return "Logout successful";
    }

    @Transactional
    public AuthResponse verifyOtpAndLogin(OtpVerificationRequest request) {
        log.info("Verifying OTP for session: {}", request.getSessionId());

        // Check OTP from Redis
        String storedOtp = (String) redisService.get("otp:" + request.getSessionId());

        if (storedOtp == null) {
            throw new RuntimeException("OTP expired or not found. Please request a new OTP.");
        }

        if (!storedOtp.equals(request.getOtpCode())) {
            throw new RuntimeException("Invalid OTP. Please try again.");
        }

        // OTP is valid - get the user from the session
        OtpCode otpRecord = otpService.getOtpRecord(request.getSessionId())
                .orElseThrow(() -> new RuntimeException("Session not found"));

        User user = otpRecord.getUser();

        // Clean up OTP from Redis
        redisService.delete("otp:" + request.getSessionId());

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

        // Store session in Redis
        userSessionService.createSession(user.getId().toString(), sessionId, otpRecord.getDeviceInfo(), otpRecord.getIpAddress());

        refreshTokenRepository.deleteByUser(user);
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        user.setLoginCount(user.getLoginCount() + 1);
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginDevice(otpRecord.getDeviceInfo());
        user.setLastLoginIp(otpRecord.getIpAddress());
        userRepository.save(user);

        // Update cache
        userCacheService.cacheUser(user);

        otpService.cleanupExpiredOtps(user);

        log.info("User logged in successfully: {} from IP: {}", user.getEmail(), otpRecord.getIpAddress());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message("Login successful")
                .build();
    }

    // Keep existing methods: forgotPassword, resetPassword, maskEmail, etc.
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