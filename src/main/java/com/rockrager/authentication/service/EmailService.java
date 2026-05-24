package com.rockrager.authentication.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final EmailTemplateService emailTemplateService;

    @Value("${mail.from.address:}")
    private String fromAddress;

    @Value("${mail.from.name:}")
    private String fromName;

    @Value("${mail.html.enabled:true}")
    private boolean htmlEmailEnabled;

    @Value("${app.base-url}")
    private String baseUrl;

    @Async
    public void sendVerificationEmail(String to, String userName, String token) {
        log.info("Sending verification email to: {}", to);

        try {
            String verificationLink = baseUrl + "/api/auth/verify-email?token=" + token;
            String subject = "Verify Your Email - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildVerificationEmailTemplate(userName, verificationLink);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextVerificationContent(verificationLink);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Verification email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", to, e);
            throw new RuntimeException("Unable to send verification email", e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String to, String userName, String token) {
        log.info("Sending password reset email to: {}", to);

        try {
            String resetLink = baseUrl + "/api/auth/reset-password?token=" + token;
            String subject = "Reset Your Password - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildPasswordResetEmailTemplate(userName, resetLink);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextResetContent(resetLink);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Password reset email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", to, e);
            throw new RuntimeException("Unable to send password reset email", e);
        }
    }

    @Async
    public void sendWelcomeEmail(String to, String userName) {
        log.info("Sending welcome email to: {}", to);

        try {
            String subject = "Welcome to RockRager Authentication!";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildWelcomeEmailTemplate(userName);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextWelcomeContent(userName);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Welcome email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", to, e);
        }
    }

    private void sendPlainTextEmail(String to, String subject, String body) {
        try {
            log.debug("Preparing plain text email - To: {}, Subject: {}", to, subject);
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            message.setFrom(getSafeFromAddress());
            mailSender.send(message);
            log.debug("Plain text email sent - To: {}, Subject: {}", to, subject);
        } catch (MailException e) {
            log.error("Plain text email delivery failed - To: {}", to, e);
            throw new RuntimeException("Failed to send plain text email", e);
        }
    }

    public void sendHtmlEmail(String to, String subject, String htmlBody) {
        try {
            log.debug("Preparing HTML email - To: {}, Subject: {}", to, subject);
            log.debug("HTML Body length: {} characters", htmlBody != null ? htmlBody.length() : 0);

            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlBody, true);
            setFromAddressSafe(helper);

            log.debug("Sending HTML email via mailSender...");
            mailSender.send(mimeMessage);
            log.debug("HTML email sent - To: {}, Subject: {}", to, subject);
        } catch (MessagingException | MailException e) {
            log.error("HTML email delivery failed - To: {}", to, e);
            throw new RuntimeException("Failed to send HTML email: " + e.getMessage(), e);
        }
    }

    private void setFromAddressSafe(MimeMessageHelper helper) throws MessagingException {
        String safeFromAddress = getSafeFromAddress();
        log.debug("Setting from address: {}", safeFromAddress);

        if (safeFromAddress == null || safeFromAddress.trim().isEmpty()) {
            log.warn("No from address configured, using default");
            helper.setFrom("noreply@localhost");
            return;
        }

        if (fromName != null && !fromName.trim().isEmpty() && !fromName.equals(fromAddress)) {
            try {
                log.debug("Setting from name: {}", fromName);
                helper.setFrom(safeFromAddress, sanitizeDisplayName(fromName));
            } catch (Exception e) {
                log.warn("Failed to set from name, using email only: {}", e.getMessage());
                helper.setFrom(safeFromAddress);
            }
        } else {
            helper.setFrom(safeFromAddress);
        }
    }

    private String getSafeFromAddress() {
        String address = fromAddress;
        if (address == null || address.trim().isEmpty()) {
            log.warn("No mail.from.address configured, using default");
            return "noreply@rockrager.com";
        }
        if (address.contains("<") && address.contains(">")) {
            int start = address.indexOf("<");
            int end = address.indexOf(">");
            if (start < end && start > 0) {
                address = address.substring(start + 1, end);
            }
        }
        log.debug("Safe from address: {}", address);
        return address.trim();
    }

    private String sanitizeDisplayName(String name) {
        if (name == null) return "";
        return name.replaceAll("[<>\\[\\]()]", "").trim();
    }

    private String buildPlainTextVerificationContent(String verificationLink) {
        return String.format("""
            Please verify your email address by clicking the link below:
            %s
            
            This link will expire in 24 hours.
            
            If you didn't create an account, please ignore this email.
            
            Best regards,
            RockRager Team
            """, verificationLink);
    }

    private String buildPlainTextResetContent(String resetLink) {
        return String.format("""
            Click the link below to reset your password:
            %s
            
            This link will expire in 1 hour.
            
            If you didn't request a password reset, please ignore this email.
            
            Best regards,
            RockRager Team
            """, resetLink);
    }

    private String buildPlainTextWelcomeContent(String userName) {
        return String.format("""
            Hello %s,
            
            Welcome to RockRager Authentication!
            
            Your account has been successfully verified.
            
            You can now log in to your account.
            
            Best regards,
            RockRager Team
            """, userName);
    }

    @Async
    public void sendOtpEmail(String to, String userName, String otpCode, int expiryMinutes) {
        log.info("Sending OTP email to: {}", to);

        try {
            String subject = "Your Login OTP - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildOtpEmailTemplate(userName, otpCode, expiryMinutes);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextOtpContent(otpCode, expiryMinutes);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("OTP email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send OTP email to: {}", to, e);
            throw new RuntimeException("Unable to send OTP email: " + e.getMessage(), e);
        }
    }

    private String buildPlainTextOtpContent(String otpCode, int expiryMinutes) {
        return String.format("""
        Hello,
        
        Your login OTP code is: %s
        
        This code will expire in %d minutes.
        
        Please enter this code to complete your login.
        
        If you didn't attempt to login, please ignore this email and secure your account.
        
        Best regards,
        RockRager Team
        """, otpCode, expiryMinutes);
    }

    @Async
    public void sendLoginNotificationEmail(String to, String userName, String subject, String body) {
        log.info("Sending login notification email to: {}", to);

        try {
            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildLoginNotificationTemplate(userName, body);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                sendPlainTextEmail(to, subject, body);
            }
            log.info("Login notification email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send login notification email to: {}", to, e);
        }
    }

    @Async
    public void sendGoogleLoginEmail(String to, String userName, String htmlContent) {
        log.info("Sending Google login email to: {}", to);
        try {
            String subject = "New Google Login Detected - RockRager Authentication";
            sendHtmlEmail(to, subject, htmlContent);
            log.info("Google login email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send Google login email to: {}", to, e);
        }
    }

    @Async
    public void sendGoogleWelcomeEmail(String to, String userName, String htmlContent) {
        log.info("Sending Google welcome email to: {}", to);
        try {
            String subject = "Welcome to RockRager Authentication!";
            sendHtmlEmail(to, subject, htmlContent);
            log.info("Google welcome email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send Google welcome email to: {}", to, e);
        }
    }

    @Async
    public void sendEmailVerificationCode(String to, String firstName, String verificationCode) {
        log.info("Sending email verification code to: {}", to);

        try {
            String subject = "Verify Your Email - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildEmailVerificationCodeTemplate(firstName, verificationCode);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextVerificationCodeContent(verificationCode);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Email verification code sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send email verification code to: {}", to, e);
            throw new RuntimeException("Unable to send verification code email", e);
        }
    }

    private String buildPlainTextVerificationCodeContent(String verificationCode) {
        return String.format("""
            Your email verification code is: %s
            
            This code will expire in 5 minutes.
            
            Please enter this code to complete your registration.
            
            If you didn't create an account, please ignore this email.
            
            Best regards,
            RockRager Team
            """, verificationCode);
    }
}