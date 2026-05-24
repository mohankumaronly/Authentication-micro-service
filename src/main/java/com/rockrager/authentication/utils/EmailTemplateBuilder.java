package com.rockrager.authentication.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class EmailTemplateBuilder {

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.name:RockRager Authentication}")
    private String appName;

    @Value("${app.support-email:support@rockrager.com}")
    private String supportEmail;

    public String buildVerificationEmail(String userName, String verificationLink) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "verificationLink", verificationLink,
                "appName", appName,
                "supportEmail", supportEmail,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getEmailLayout(
                "Verify Your Email Address",
                buildVerificationContent(variables),
                "warning",
                verificationLink
        );
    }

    public String buildPasswordResetEmail(String userName, String resetLink) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "resetLink", resetLink,
                "appName", appName,
                "supportEmail", supportEmail,
                "baseUrl", baseUrl,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getEmailLayout(
                "Reset Your Password",
                buildPasswordResetContent(variables),
                "security",
                resetLink
        );
    }

    public String buildWelcomeEmail(String userName) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "appName", appName,
                "supportEmail", supportEmail,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getEmailLayout(
                "Welcome to " + appName,
                buildWelcomeContent(variables),
                "success",
                null
        );
    }

    private String getEmailLayout(String title, String content, String type, String buttonLink) {
        String buttonHtml = "";
        if (buttonLink != null) {
            buttonHtml = String.format("""
                <div style="text-align: center; margin: 30px 0;">
                    <a href="%s" class="button" style="display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; text-decoration: none; border-radius: 6px; font-weight: 600;">%s</a>
                </div>
                """, buttonLink, title.equals("Verify Your Email Address") ? "Verify Email" : "Reset Password");
        }

        String typeColor = switch (type) {
            case "warning" -> "#ffc107";
            case "success" -> "#28a745";
            case "security" -> "#17a2b8";
            default -> "#667eea";
        };

        return String.format("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>%s</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        background-color: #f4f4f5;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        max-width: 600px;
                        margin: 20px auto;
                        background: #ffffff;
                        border-radius: 12px;
                        overflow: hidden;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }
                    .header {
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        color: white;
                        padding: 30px 20px;
                        text-align: center;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                        font-weight: 600;
                    }
                    .content {
                        padding: 40px 30px;
                    }
                    .content p {
                        margin: 15px 0;
                    }
                    .button {
                        display: inline-block;
                        padding: 12px 30px;
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        color: white !important;
                        text-decoration: none;
                        border-radius: 6px;
                        font-weight: 600;
                        text-align: center;
                    }
                    .info-box {
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                        margin: 20px 0;
                        word-break: break-all;
                        font-family: monospace;
                        font-size: 14px;
                    }
                    .warning-box {
                        background: #fff3cd;
                        border-left: 4px solid #ffc107;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .security-box {
                        background: #d1ecf1;
                        border-left: 4px solid #17a2b8;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .success-box {
                        background: #d4edda;
                        border-left: 4px solid #28a745;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .footer {
                        background: #f8f9fa;
                        padding: 20px;
                        text-align: center;
                        font-size: 12px;
                        color: #6c757d;
                        border-top: 1px solid #e9ecef;
                    }
                    .footer a {
                        color: #667eea;
                        text-decoration: none;
                    }
                    @media (max-width: 600px) {
                        .container {
                            margin: 10px;
                        }
                        .content {
                            padding: 20px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>%s</h1>
                    </div>
                    <div class="content">
                        %s
                        %s
                    </div>
                    <div class="footer">
                        <p>© %%s %s. All rights reserved.</p>
                        <p>Need help? <a href="mailto:%%s">Contact Support</a></p>
                        <p>This is an automated message, please do not reply to this email.</p>
                    </div>
                </div>
            </body>
            </html>
            """, title, title, content, buttonHtml, "%s", "%s");
    }

    private String buildVerificationContent(Map<String, String> vars) {
        return String.format("""
            <p>Hello <strong>%s</strong>,</p>
            <p>Thank you for registering with <strong>%s</strong>!</p>
            <p>Please verify your email address to get started:</p>
            
            <div class="info-box">
                <a href="%s" style="color: #667eea;">%s</a>
            </div>
            
            <div class="warning-box">
                ⏰ This verification link will expire in <strong>24 hours</strong> for security reasons.
            </div>
            
            <div class="warning-box">
                ⚠️ If you didn't create an account with %s, please ignore this email or 
                <a href="mailto:%s">contact our support team</a>.
            </div>
            """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("verificationLink"),
                vars.get("verificationLink"),
                vars.get("appName"),
                vars.get("supportEmail")
        );
    }

    private String buildPasswordResetContent(Map<String, String> vars) {
        return String.format("""
            <p>Hello <strong>%s</strong>,</p>
            <p>We received a request to reset your password for your <strong>%s</strong> account.</p>
            <p>Click the link below to create a new password:</p>
            
            <div class="info-box">
                <a href="%s" style="color: #667eea;">%s</a>
            </div>
            
            <div class="warning-box">
                ⏰ This password reset link will expire in <strong>1 hour</strong> for security reasons.
            </div>
            
            <div class="security-box">
                🔒 If you didn't request a password reset, please ignore this email or 
                <a href="mailto:%s">contact support immediately</a> if you suspect unauthorized access.
            </div>
            """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("resetLink"),
                vars.get("resetLink"),
                vars.get("supportEmail")
        );
    }

    private String buildWelcomeContent(Map<String, String> vars) {
        return String.format("""
            <p>Hello <strong>%s</strong>,</p>
            <p>Welcome to <strong>%s</strong>! We're thrilled to have you on board.</p>
            
            <div class="success-box">
                ✅ Your account has been successfully created and verified!
            </div>
            
            <p>Here's what you can do next:</p>
            <ul>
                <li>Log in to your account</li>
                <li>Update your profile information</li>
                <li>Explore our features</li>
            </ul>
            
            <p>If you have any questions or need assistance, feel free to <a href="mailto:%s">reach out to our support team</a>.</p>
            """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("supportEmail")
        );
    }

    public String buildOtpEmail(String userName, String otpCode, int expiryMinutes) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "otpCode", otpCode,
                "expiryMinutes", String.valueOf(expiryMinutes),
                "appName", appName,
                "supportEmail", supportEmail,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getOtpEmailLayout(
                "Your Login OTP - " + appName,
                buildOtpContent(variables),
                "otp"
        );
    }

    private String getOtpEmailLayout(String title, String content, String type) {
        String typeColor = switch (type) {
            case "otp" -> "#4F46E5";
            case "warning" -> "#ffc107";
            case "success" -> "#28a745";
            case "security" -> "#17a2b8";
            default -> "#667eea";
        };

        return String.format("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>%s</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f4f4f5;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 600px;
                    margin: 20px auto;
                    background: #ffffff;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                .header {
                    background: linear-gradient(135deg, #4F46E5 0%%, #7C3AED 100%%);
                    color: white;
                    padding: 30px 20px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 24px;
                    font-weight: 600;
                }
                .content {
                    padding: 40px 30px;
                }
                .content p {
                    margin: 15px 0;
                }
                .otp-code {
                    font-size: 48px;
                    font-weight: bold;
                    color: #4F46E5;
                    padding: 20px;
                    background: #F3F4F6;
                    display: inline-block;
                    letter-spacing: 8px;
                    border-radius: 8px;
                    font-family: monospace;
                    text-align: center;
                    width: 100%%;
                    box-sizing: border-box;
                }
                .otp-container {
                    text-align: center;
                    margin: 30px 0;
                }
                .info-box {
                    background: #F3F4F6;
                    padding: 15px;
                    border-radius: 6px;
                    margin: 20px 0;
                    text-align: center;
                }
                .warning-box {
                    background: #FEF3C7;
                    border-left: 4px solid #F59E0B;
                    padding: 12px;
                    margin: 20px 0;
                    font-size: 14px;
                }
                .footer {
                    background: #F9FAFB;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6B7280;
                    border-top: 1px solid #E5E7EB;
                }
                .footer a {
                    color: #4F46E5;
                    text-decoration: none;
                }
                @media (max-width: 600px) {
                    .container {
                        margin: 10px;
                    }
                    .content {
                        padding: 20px;
                    }
                    .otp-code {
                        font-size: 32px;
                        letter-spacing: 4px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 %s</h1>
                </div>
                <div class="content">
                    %s
                </div>
                <div class="footer">
                    <p>© %%s %s. All rights reserved.</p>
                    <p>Need help? <a href="mailto:%%s">Contact Support</a></p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """, title, title, content, "%s", "%s");
    }

    private String buildOtpContent(Map<String, String> vars) {
        return String.format("""
        <p>Hello <strong>%s</strong>,</p>
        <p>You've requested to log in to your <strong>%s</strong> account.</p>
        <p>Please use the following One-Time Password (OTP) to complete your login:</p>
        
        <div class="otp-container">
            <div class="otp-code">%s</div>
        </div>
        
        <div class="info-box">
            ⏰ This OTP is valid for <strong>%s minutes</strong>.
        </div>
        
        <div class="warning-box">
            ⚠️ For security reasons, never share this OTP with anyone.
        </div>
        
        <p>If you didn't attempt to log in, please ignore this email and consider securing your account.</p>
        """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("otpCode"),
                vars.get("expiryMinutes")
        );
    }

    public String buildEmailVerificationCode(String userName, String verificationCode) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "verificationCode", verificationCode,
                "appName", appName,
                "supportEmail", supportEmail,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getVerificationCodeEmailLayout(
                "Verify Your Email - " + appName,
                buildVerificationCodeContent(variables),
                "verification"
        );
    }

    private String getVerificationCodeEmailLayout(String title, String content, String type) {
        return String.format("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>%s</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f4f4f5;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 600px;
                    margin: 20px auto;
                    background: #ffffff;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                .header {
                    background: linear-gradient(135deg, #22C55E 0%%, #16A34A 100%%);
                    color: white;
                    padding: 30px 20px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 24px;
                    font-weight: 600;
                }
                .content {
                    padding: 40px 30px;
                }
                .content p {
                    margin: 15px 0;
                }
                .verification-code {
                    font-size: 48px;
                    font-weight: bold;
                    color: #22C55E;
                    padding: 20px;
                    background: #F0FDF4;
                    display: inline-block;
                    letter-spacing: 8px;
                    border-radius: 8px;
                    font-family: monospace;
                    text-align: center;
                    width: 100%%;
                    box-sizing: border-box;
                }
                .code-container {
                    text-align: center;
                    margin: 30px 0;
                }
                .info-box {
                    background: #F3F4F6;
                    padding: 15px;
                    border-radius: 6px;
                    margin: 20px 0;
                    text-align: center;
                }
                .warning-box {
                    background: #FEF3C7;
                    border-left: 4px solid #F59E0B;
                    padding: 12px;
                    margin: 20px 0;
                    font-size: 14px;
                }
                .footer {
                    background: #F9FAFB;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #6B7280;
                    border-top: 1px solid #E5E7EB;
                }
                .footer a {
                    color: #22C55E;
                    text-decoration: none;
                }
                @media (max-width: 600px) {
                    .container {
                        margin: 10px;
                    }
                    .content {
                        padding: 20px;
                    }
                    .verification-code {
                        font-size: 32px;
                        letter-spacing: 4px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📧 %s</h1>
                </div>
                <div class="content">
                    %s
                </div>
                <div class="footer">
                    <p>© %%s %s. All rights reserved.</p>
                    <p>Need help? <a href="mailto:%%s">Contact Support</a></p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """, title, title, content, "%s", "%s");
    }

    private String buildVerificationCodeContent(Map<String, String> vars) {
        return String.format("""
        <p>Hello <strong>%s</strong>,</p>
        <p>Thank you for registering with <strong>%s</strong>!</p>
        <p>Please use the verification code below to complete your registration:</p>
        
        <div class="code-container">
            <div class="verification-code">%s</div>
        </div>
        
        <div class="info-box">
            ⏰ This verification code is valid for <strong>5 minutes</strong>.
        </div>
        
        <div class="warning-box">
            ⚠️ If you didn't create an account with %s, please ignore this email.
        </div>
        
        <p>Enter this code on the verification page to activate your account.</p>
        """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("verificationCode"),
                vars.get("appName")
        );
    }
}