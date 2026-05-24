package com.rockrager.authentication.service;

import com.rockrager.authentication.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisUserCacheService {

    private final RedisService redisService;
    private final com.rockrager.authentication.repository.UserRepository userRepository;

    private static final String USER_CACHE_PREFIX = "user:cache:";
    private static final String USER_EMAIL_CACHE_PREFIX = "user:email:";
    private static final long CACHE_EXPIRY_MINUTES = 60;

    /**
     * Cache a user by ID
     */
    public void cacheUser(User user) {
        if (user == null || user.getId() == null) {
            return;
        }

        // Create a serializable copy of the user (detach from Hibernate proxy)
        User serializableUser = new User();
        serializableUser.setId(user.getId());
        serializableUser.setFirstName(user.getFirstName());
        serializableUser.setLastName(user.getLastName());
        serializableUser.setEmail(user.getEmail());
        serializableUser.setPassword(user.getPassword());
        serializableUser.setEmailVerified(user.isEmailVerified());
        serializableUser.setPendingVerification(user.isPendingVerification());
        serializableUser.setRole(user.getRole());
        serializableUser.setOtpEnabled(user.isOtpEnabled());
        serializableUser.setLastLoginAt(user.getLastLoginAt());
        serializableUser.setLoginCount(user.getLoginCount());
        serializableUser.setLastLoginIp(user.getLastLoginIp());
        serializableUser.setLastLoginDevice(user.getLastLoginDevice());
        serializableUser.setLastLoginLocation(user.getLastLoginLocation());
        serializableUser.setGoogleId(user.getGoogleId());
        serializableUser.setAuthProvider(user.getAuthProvider());
        serializableUser.setCreatedAt(user.getCreatedAt());
        serializableUser.setUpdatedAt(user.getUpdatedAt());

        String idKey = USER_CACHE_PREFIX + user.getId();
        String emailKey = USER_EMAIL_CACHE_PREFIX + user.getEmail();

        redisService.save(idKey, serializableUser, CACHE_EXPIRY_MINUTES);
        redisService.save(emailKey, serializableUser, CACHE_EXPIRY_MINUTES);

        log.debug("User cached: {}", user.getEmail());
    }

    /**
     * Get user by ID from cache (fallback to database)
     */
    public Optional<User> getUserById(UUID userId) {
        String key = USER_CACHE_PREFIX + userId;
        Object cachedUser = redisService.get(key);

        if (cachedUser instanceof User) {
            log.debug("User found in cache: {}", userId);
            return Optional.of((User) cachedUser);
        }

        // Fallback to database
        Optional<User> user = userRepository.findById(userId);
        user.ifPresent(this::cacheUser);
        return user;
    }

    /**
     * Get user by email from cache (fallback to database)
     */
    public Optional<User> getUserByEmail(String email) {
        String key = USER_EMAIL_CACHE_PREFIX + email;
        Object cachedUser = redisService.get(key);

        if (cachedUser instanceof User) {
            log.debug("User found in cache by email: {}", email);
            return Optional.of((User) cachedUser);
        }

        // Fallback to database
        Optional<User> user = userRepository.findByEmail(email);
        user.ifPresent(this::cacheUser);
        return user;
    }

    /**
     * Update user in cache
     */
    public void updateUserInCache(User user) {
        if (user == null || user.getId() == null) {
            return;
        }

        // Remove old cache entries first
        evictUser(user.getId(), user.getEmail());

        // Add updated user to cache
        cacheUser(user);

        log.debug("User updated in cache: {}", user.getEmail());
    }

    /**
     * Remove user from cache
     */
    public void evictUser(UUID userId, String email) {
        String idKey = USER_CACHE_PREFIX + userId;
        String emailKey = USER_EMAIL_CACHE_PREFIX + email;

        redisService.delete(idKey);
        redisService.delete(emailKey);

        log.debug("User evicted from cache: {}", email);
    }

    /**
     * Remove user from cache by ID only
     */
    public void evictUserById(UUID userId) {
        String idKey = USER_CACHE_PREFIX + userId;
        redisService.delete(idKey);
        log.debug("User evicted from cache by ID: {}", userId);
    }

    /**
     * Check if user exists in cache
     */
    public boolean isUserCached(UUID userId) {
        String key = USER_CACHE_PREFIX + userId;
        return redisService.exists(key);
    }

    /**
     * Get cache expiry time in minutes
     */
    public long getCacheExpiryMinutes() {
        return CACHE_EXPIRY_MINUTES;
    }
}