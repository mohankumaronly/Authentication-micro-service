package com.rockrager.authentication.controller;

import com.rockrager.authentication.dto.request.*;
import com.rockrager.authentication.dto.response.AuthResponse;
import com.rockrager.authentication.repository.UserRepository;
import com.rockrager.authentication.service.AuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import com.rockrager.authentication.entity.User;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    @Value("${cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${cookie.same-site:Strict}")
    private String cookieSameSite;

    @Value("${cookie.refresh-token-max-age:604800}")
    private int refreshTokenMaxAge;

    private void setAuthCookies(HttpServletResponse response, AuthResponse authResponse) {
        if (authResponse.getAccessToken() != null) {
            Cookie accessTokenCookie = new Cookie("accessToken", authResponse.getAccessToken());
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setSecure(cookieSecure);
            accessTokenCookie.setPath("/");
            accessTokenCookie.setMaxAge(86400);
            accessTokenCookie.setAttribute("SameSite", cookieSameSite);
            response.addCookie(accessTokenCookie);
        }

        if (authResponse.getRefreshToken() != null) {
            Cookie refreshTokenCookie = new Cookie("refreshToken", authResponse.getRefreshToken());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(cookieSecure);
            refreshTokenCookie.setPath("/api/auth");
            refreshTokenCookie.setMaxAge(refreshTokenMaxAge);
            refreshTokenCookie.setAttribute("SameSite", cookieSameSite);
            response.addCookie(refreshTokenCookie);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.register(request);
        setAuthCookies(response, authResponse);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/verify-email-code")
    public ResponseEntity<AuthResponse> verifyEmailCode(
            @RequestParam String email,
            @RequestParam String code,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.verifyEmailAndCompleteRegistration(email, code);
        setAuthCookies(response, authResponse);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/resend-verification-code")
    public ResponseEntity<Map<String, String>> resendVerificationCode(
            @RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }

        String result = authService.resendVerificationCode(email);
        return ResponseEntity.ok(Map.of("message", result));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {

        String userAgent = httpRequest.getHeader("User-Agent");
        String clientIp = getClientIpAddress(httpRequest);

        if (request.getDeviceInfo() == null) {
            request.setDeviceInfo(userAgent);
        }
        if (request.getIpAddress() == null) {
            request.setIpAddress(clientIp);
        }

        AuthResponse authResponse = authService.login(request);

        if (authResponse.getRequiresOtp() != null && authResponse.getRequiresOtp()) {
            return ResponseEntity.ok(authResponse);
        }

        setAuthCookies(response, authResponse);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtpAndLogin(
            @Valid @RequestBody OtpVerificationRequest request,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.verifyOtpAndLogin(request);
        setAuthCookies(response, authResponse);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = extractRefreshTokenFromCookies(request);

        if (refreshToken == null) {
            return ResponseEntity.badRequest().build();
        }

        AuthResponse authResponse = authService.refreshToken(refreshToken);
        setAuthCookies(response, authResponse);

        authResponse.setRefreshToken(null);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = extractRefreshTokenFromCookies(request);

        if (refreshToken == null) {
            return ResponseEntity.badRequest().body("No refresh token found");
        }

        String result = authService.logout(refreshToken);

        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setPath("/api/auth");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/verify-email")
    @Deprecated
    public ResponseEntity<String> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request) {
        log.warn("Deprecated verify-email endpoint called. Please use /verify-email-code instead.");
        return ResponseEntity.badRequest().body("This endpoint is deprecated. Please use the verification code sent to your email.");
    }

    @GetMapping("/verify-email")
    @Deprecated
    public ResponseEntity<String> verifyEmailWithParam(
            @RequestParam String token) {
        log.warn("Deprecated verify-email endpoint called. Please use /verify-email-code instead.");
        return ResponseEntity.badRequest().body("This endpoint is deprecated. Please use the verification code sent to your email.");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        return ResponseEntity.ok(authService.forgotPassword(request.getEmail()));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(
                request.getToken(),
                request.getNewPassword()
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("message", "Not authenticated"));
        }

        String email = authentication.getName();
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found"));
        }

        return ResponseEntity.ok(Map.of(
                "user", Map.of(
                        "id", user.getId(),
                        "firstName", user.getFirstName(),
                        "lastName", user.getLastName(),
                        "email", user.getEmail(),
                        "emailVerified", user.isEmailVerified(),
                        "createdAt", user.getCreatedAt(),
                        "lastLoginAt", user.getLastLoginAt()
                )
        ));
    }

    private String extractRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }
        return ipAddress;
    }
}