package com.rockrager.authentication.service;

import com.rockrager.authentication.dto.request.LoginRequest;
import com.rockrager.authentication.dto.request.RegisterRequest;
import com.rockrager.authentication.dto.response.AuthResponse;
import com.rockrager.authentication.dto.response.LoginInitiateResponse;
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

        // Generate session ID for this user session
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

        // Save user session
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

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        if (!user.isEmailVerified()) {
            throw new RuntimeException("Please verify your email first. Check your inbox for verification link.");
        }

        boolean hasLoggedInBefore = user.getLoginCount() > 0;

        log.info("User login attempt for: {}, Login count: {}, hasLoggedInBefore: {}",
                user.getEmail(), user.getLoginCount(), hasLoggedInBefore);

        if (hasLoggedInBefore) {
            log.info("Existing user - returning requiresOtp: true for: {}", user.getEmail());

            String maskedEmail = maskEmail(user.getEmail());

            return AuthResponse.builder()
                    .requiresOtp(true)
                    .message("Please verify your identity")
                    .email(maskedEmail)
                    .build();
        } else {
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

            user.setLoginCount(user.getLoginCount() + 1);
            user.setLastLoginAt(LocalDateTime.now());
            user.setLastLoginDevice(request.getDeviceInfo());
            user.setLastLoginIp(request.getIpAddress());
            userRepository.save(user);

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .message("Login successful")
                    .build();
        }
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {

        RefreshToken storedToken = refreshTokenRepository
                .findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (storedToken.isRevoked()) {
            throw new RuntimeException("Refresh token revoked");
        }

        if (storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(storedToken);
            throw new RuntimeException("Refresh token expired");
        }

        User user = storedToken.getUser();

        // Create new session ID for refreshed token
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

        passwordResetTokenRepository.delete(resetToken);

        refreshTokenRepository.deleteByUser(user);

        log.info("Password reset successful for user: {}", user.getEmail());

        return "Password reset successful. Please login with your new password.";
    }

    @Transactional
    public LoginInitiateResponse initiateLogin(LoginRequest request) {
        log.info("INITIATE LOGIN - START");

        String originalEmail = request.getEmail();
        log.info("Original email for lookup: {}", originalEmail);

        log.info("Request password length: {}", request.getPassword() != null ? request.getPassword().length() : 0);
        log.info("Request device info: {}", request.getDeviceInfo());
        log.info("Request IP address: {}", request.getIpAddress());

        log.info("Searching for user with email: {}", originalEmail);
        User user = userRepository.findByEmail(originalEmail)
                .orElseThrow(() -> {
                    log.error("User not found with email: {}", originalEmail);
                    return new RuntimeException("Invalid email or password");
                });

        log.info("User found - ID: {}, Email: {}, Login Count: {}, Auth Provider: {}",
                user.getId(), user.getEmail(), user.getLoginCount(), user.getAuthProvider());

        if (user.getAuthProvider() == AuthProvider.GOOGLE && (user.getPassword() == null || user.getPassword().isEmpty())) {
            log.warn("User {} is Google-only account with no password", user.getEmail());
            throw new RuntimeException("This account uses Google login. Please sign in with Google.");
        }

        if (user.getGoogleId() != null && user.getAuthProvider() == AuthProvider.LOCAL) {
            log.info("User with linked Google account logging in with password: {}", request.getEmail());
        }

        log.info("Validating password...");
        boolean passwordMatches = passwordEncoder.matches(request.getPassword(), user.getPassword());
        log.info("Password matches: {}", passwordMatches);

        if (!passwordMatches) {
            log.error("Password mismatch for user: {}", originalEmail);
            throw new RuntimeException("Invalid email or password");
        }
        log.info("Password validated successfully");

        log.info("Checking email verification status...");
        if (!user.isEmailVerified()) {
            log.warn("User {} has not verified email", user.getEmail());
            throw new RuntimeException("Please verify your email first. Check your inbox for verification link.");
        }
        log.info("Email is verified");

        otpCodeRepository.deleteByUserAndUsedFalse(user);
        log.info("Cleared any existing unused OTPs for user: {}", user.getEmail());

        String sessionId = UUID.randomUUID().toString();
        log.info("Generated session ID: {}", sessionId);

        log.info("Generating and sending OTP...");
        String otpCode = otpService.generateAndSendOtp(
                user,
                sessionId,
                request.getDeviceInfo(),
                request.getIpAddress()
        );
        log.info("OTP generated and sent - Code: {}", otpCode);

        log.info("OTP sent to user: {} for session: {}", user.getEmail(), sessionId);

        String maskedEmail = maskEmail(user.getEmail());
        log.info("Masked email for response: {}", maskedEmail);

        log.info("INITIATE LOGIN - SUCCESS");

        return LoginInitiateResponse.builder()
                .sessionId(sessionId)
                .otpRequired(true)
                .message("OTP sent to your email address")
                .otpSentTo(maskedEmail)
                .expiresIn((long) otpService.getOtpExpirySeconds())
                .build();
    }

    @Transactional
    public AuthResponse verifyOtpAndLogin(com.rockrager.authentication.dto.request.OtpVerificationRequest request) {
        log.info("Verifying OTP for session: {}", request.getSessionId());

        boolean isValid = otpService.validateOtp(request.getSessionId(), request.getOtpCode());

        if (!isValid) {
            throw new RuntimeException("Invalid or expired OTP. Please try again.");
        }

        com.rockrager.authentication.entity.OtpCode otpRecord = otpService.getOtpRecord(request.getSessionId())
                .orElseThrow(() -> new RuntimeException("Session not found"));

        User user = otpRecord.getUser();

        if (user.getAuthProvider() == AuthProvider.GOOGLE && (user.getPassword() == null || user.getPassword().isEmpty())) {
            throw new RuntimeException("This account uses Google login. Please sign in with Google.");
        }

        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(otpRecord.getIpAddress());
        user.setLastLoginDevice(otpRecord.getDeviceInfo());

        user.setLoginCount(user.getLoginCount() + 1);

        try {
            String location = deviceInfoService.getLocationFromIp(otpRecord.getIpAddress());
            user.setLastLoginLocation(location);
        } catch (Exception e) {
            log.warn("Could not get location for IP: {}", otpRecord.getIpAddress());
            user.setLastLoginLocation("Unknown");
        }

        userRepository.save(user);

        // Generate new session ID for this login
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

        // Save user session
        UserSession userSession = UserSession.builder()
                .user(user)
                .sessionId(sessionId)
                .loginAt(LocalDateTime.now())
                .active(true)
                .deviceInfo(otpRecord.getDeviceInfo())
                .ipAddress(otpRecord.getIpAddress())
                .location(user.getLastLoginLocation())
                .build();
        userSessionRepository.save(userSession);

        try {
            sendLoginNotificationEmail(user, otpRecord);
        } catch (Exception e) {
            log.error("Failed to send login notification email to: {}", user.getEmail(), e);
        }

        otpService.cleanupExpiredOtps(user);

        log.info("User logged in successfully: {} from IP: {}", user.getEmail(), otpRecord.getIpAddress());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message("Login successful")
                .build();
    }

    private void sendLoginNotificationEmail(User user, com.rockrager.authentication.entity.OtpCode otpRecord) {
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