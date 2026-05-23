package com.rockrager.authentication.dto.response;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String message;
    private Boolean requiresOtp;
    private String email;
    private String sessionId;
    private Long expiresIn;
}