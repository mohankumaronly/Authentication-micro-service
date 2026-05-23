package com.rockrager.authentication.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private Key getSigningKey() {
        byte[] keyBytes = secretKey.getBytes();
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret key must be at least 32 characters long");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // ========== ENHANCED TOKEN GENERATION ==========

    public String generateAccessToken(String email, UUID userId, String role, String sessionId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString());
        claims.put("role", role);
        claims.put("sessionId", sessionId);
        claims.put("serviceAccess", Arrays.asList("auth-service", "payment-service", "chat-service"));
        claims.put("permissions", getPermissionsForRole(role));
        claims.put("tokenType", "access");
        claims.put("iss", "auth-service");
        claims.put("aud", Arrays.asList("payment-service", "chat-service", "auth-service"));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date())
                .setId(UUID.randomUUID().toString())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(String email, UUID userId, String sessionId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString());
        claims.put("sessionId", sessionId);
        claims.put("tokenType", "refresh");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date())
                .setId(UUID.randomUUID().toString())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private List<String> getPermissionsForRole(String role) {
        switch (role.toUpperCase()) {
            case "ADMIN":
                return Arrays.asList("read:all", "write:all", "delete:all", "access:payment", "access:chat");
            case "PREMIUM_USER":
                return Arrays.asList("read:profile", "write:profile", "access:payment", "access:chat", "premium:content");
            case "USER":
            default:
                return Arrays.asList("read:profile", "write:profile", "access:chat");
        }
    }

    // ========== ENHANCED TOKEN VALIDATION FOR MICROSERVICES ==========

    public boolean validateTokenForService(String token, String serviceName) {
        try {
            Claims claims = extractAllClaims(token);

            // Check if token is expired
            if (claims.getExpiration().before(new Date())) {
                return false;
            }

            // Check if service has access
            List<String> serviceAccess = claims.get("serviceAccess", List.class);
            if (serviceAccess == null || !serviceAccess.contains(serviceName)) {
                return false;
            }

            // Check token type (must be access token for APIs)
            String tokenType = claims.get("tokenType", String.class);
            if (!"access".equals(tokenType)) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean validateTokenForServiceWithPermission(String token, String serviceName, String requiredPermission) {
        try {
            if (!validateTokenForService(token, serviceName)) {
                return false;
            }

            Claims claims = extractAllClaims(token);
            List<String> permissions = claims.get("permissions", List.class);

            return permissions != null && permissions.contains(requiredPermission);
        } catch (Exception e) {
            return false;
        }
    }

    // ========== EXTRACT CLAIMS FOR OTHER SERVICES ==========

    public UUID extractUserId(String token) {
        String userIdStr = extractClaim(token, claims -> claims.get("userId", String.class));
        return userIdStr != null ? UUID.fromString(userIdStr) : null;
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    public String extractSessionId(String token) {
        return extractClaim(token, claims -> claims.get("sessionId", String.class));
    }

    public List<String> extractServiceAccess(String token) {
        return extractClaim(token, claims -> claims.get("serviceAccess", List.class));
    }

    public List<String> extractPermissions(String token) {
        return extractClaim(token, claims -> claims.get("permissions", List.class));
    }

    public String extractTokenId(String token) {
        return extractClaim(token, Claims::getId);
    }

    public String extractIssuer(String token) {
        return extractClaim(token, Claims::getIssuer);
    }

    public List<String> extractAudience(String token) {
        return extractClaim(token, claims -> claims.get("aud", List.class));
    }

    // ========== STANDARD METHODS ==========

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        final Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, String email) {
        if (token == null || email == null) {
            return false;
        }

        try {
            final String extractedEmail = extractEmail(token);
            return extractedEmail.equals(email) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    // ========== HELPER FOR OTHER SERVICES ==========

    public Map<String, Object> getTokenInfo(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Map<String, Object> info = new HashMap<>();
            info.put("valid", true);
            info.put("email", claims.getSubject());
            info.put("userId", claims.get("userId"));
            info.put("role", claims.get("role"));
            info.put("sessionId", claims.get("sessionId"));
            info.put("serviceAccess", claims.get("serviceAccess"));
            info.put("permissions", claims.get("permissions"));
            info.put("expiry", claims.getExpiration());
            return info;
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("valid", false);
            error.put("error", e.getMessage());
            return error;
        }
    }
}