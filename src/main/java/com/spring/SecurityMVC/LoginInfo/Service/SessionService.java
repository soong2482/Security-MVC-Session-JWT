package com.spring.SecurityMVC.LoginInfo.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class SessionService {
    @Value("${spring.session.store}")
    private String SESSION_PREFIX;

    private long REFRESH_TOKEN_EXPIRATION;
    private final RedisTemplate<String, String> redisTemplate;

    public SessionService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    public boolean isSessionValid(String sessionId) {
        if (sessionId != null && !sessionId.isEmpty()) {
            return redisTemplate.hasKey(SESSION_PREFIX + sessionId);
        } else {
            return false;
        }
    }

    public void invalidateSession(String sessionId) {
        if (sessionId != null && !sessionId.isEmpty()) {
            redisTemplate.delete(SESSION_PREFIX + sessionId);
        } else {
            throw new IllegalArgumentException("Session ID cannot be null or empty");
        }
    }
}
