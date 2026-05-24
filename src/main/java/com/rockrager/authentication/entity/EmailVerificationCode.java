package com.rockrager.authentication.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "email_verification", timeToLive = 300) // 5 minutes expiry
public class EmailVerificationCode {

    @Id
    private String id;

    @Indexed
    private String email;

    private String code;

    private String firstName;

    private String lastName;

    private String password;

    private LocalDateTime createdAt;

    private int attempts;

    public boolean isExpired() {
        return createdAt.plusMinutes(5).isBefore(LocalDateTime.now());
    }

    public void incrementAttempts() {
        this.attempts++;
    }

    public boolean isMaxAttemptsReached() {
        return attempts >= 3;
    }
}