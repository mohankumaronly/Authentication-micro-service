package com.rockrager.authentication.service;

import com.rockrager.authentication.utils.EmailTemplateBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailTemplateService {

    private final EmailTemplateBuilder templateBuilder;

    public String buildVerificationEmailTemplate(String userName, String verificationLink) {
        try {
            return templateBuilder.buildVerificationEmail(userName, verificationLink);
        } catch (Exception e) {
            log.error("Failed to build verification email template for user: {}", userName, e);
            return buildFallbackVerificationTemplate(verificationLink);
        }
    }

    public String buildPasswordResetEmailTemplate(String userName, String resetLink) {
        try {
            return templateBuilder.buildPasswordResetEmail(userName, resetLink);
        } catch (Exception e) {
            log.error("Failed to build password reset email template for user: {}", userName, e);
            return buildFallbackResetTemplate(resetLink);
        }
    }

    public String buildWelcomeEmailTemplate(String userName) {
        try {
            return templateBuilder.buildWelcomeEmail(userName);
        } catch (Exception e) {
            log.error("Failed to build welcome email template for user: {}", userName, e);
            return buildFallbackWelcomeTemplate(userName);
        }
    }

    public String buildOtpEmailTemplate(String userName, String otpCode, int expiryMinutes) {
        try {
            return templateBuilder.buildOtpEmail(userName, otpCode, expiryMinutes);
        } catch (Exception e) {
            log.error("Failed to build OTP email template for user: {}", userName, e);
            return buildFallbackOtpTemplate(otpCode, expiryMinutes);
        }
    }

    private String buildFallbackOtpTemplate(String otpCode, int expiryMinutes) {
        return String.format("""
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; }
                    .otp-code { font-size: 32px; font-weight: bold; color: #4F46E5; padding: 10px; background: #F3F4F6; display: inline-block; letter-spacing: 5px; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Your Login OTP</h2>
                    <p>Hello,</p>
                    <p>Your login OTP code is:</p>
                    <div class="otp-code">%s</div>
                    <p>This code will expire in <strong>%d minutes</strong>.</p>
                    <p>Please enter this code to complete your login.</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">If you didn't attempt to login, please ignore this email and secure your account.</p>
                    <p style="color: #666; font-size: 12px;">Best regards,<br>RockRager Team</p>
                </div>
            </body>
            </html>
            """, otpCode, expiryMinutes);
    }

    private String buildFallbackVerificationTemplate(String verificationLink) {
        return String.format("""
            <html>
            <body>
                <h2>Verify Your Email</h2>
                <p>Please click the link below to verify your email address:</p>
                <a href="%s">%s</a>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn't create an account, please ignore this email.</p>
            </body>
            </html>
            """, verificationLink, verificationLink);
    }

    private String buildFallbackResetTemplate(String resetLink) {
        return String.format("""
            <html>
            <body>
                <h2>Reset Your Password</h2>
                <p>Click the link below to reset your password:</p>
                <a href="%s">%s</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
            </html>
            """, resetLink, resetLink);
    }

    private String buildFallbackWelcomeTemplate(String userName) {
        return String.format("""
            <html>
            <body>
                <h2>Welcome to RockRager!</h2>
                <p>Hello %s,</p>
                <p>Your account has been successfully verified!</p>
                <p>You can now log in to your account.</p>
            </body>
            </html>
            """, userName);
    }

    public String buildLoginNotificationTemplate(String userName, String notificationBody) {
        return String.format("""
        <html>
        <body>
            <h2>New Login Detected</h2>
            <p>Hello %s,</p>
            <pre>%s</pre>
            <p>Best regards,<br>RockRager Team</p>
        </body>
        </html>
        """, userName, notificationBody);
    }

    public String buildEmailVerificationCodeTemplate(String userName, String verificationCode) {
        try {
            return templateBuilder.buildEmailVerificationCode(userName, verificationCode);
        } catch (Exception e) {
            log.error("Failed to build email verification code template for user: {}", userName, e);
            return buildFallbackVerificationCodeTemplate(verificationCode);
        }
    }

    private String buildFallbackVerificationCodeTemplate(String verificationCode) {
        return String.format("""
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; }
                    .code { font-size: 36px; font-weight: bold; color: #4CAF50; padding: 10px; background: #F3F4F6; display: inline-block; letter-spacing: 5px; font-family: monospace; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Email Verification</h2>
                    <p>Hello,</p>
                    <p>Thank you for registering. Please use the verification code below:</p>
                    <div class="code">%s</div>
                    <p>This code will expire in <strong>5 minutes</strong>.</p>
                    <p>If you didn't create an account, please ignore this email.</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">Best regards,<br>RockRager Team</p>
                </div>
            </body>
            </html>
            """, verificationCode);
    }
}