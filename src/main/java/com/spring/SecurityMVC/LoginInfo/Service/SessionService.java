package com.spring.SecurityMVC.LoginInfo.Service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class SessionService {
    @Value("${spring.session.prefix}")
    private String SESSION_PREFIX;

    private long REFRESH_TOKEN_EXPIRATION;
    private final RedisTemplate<String, String> redisTemplate;

    public SessionService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String createNewSession(HttpServletRequest request, String username, List<String> roles) {
        HttpSession session = request.getSession(true);
        session.setMaxInactiveInterval(1800);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        session.setAttribute("username", username);
        session.setAttribute("roles", roles);

        return session.getId();
    }

    public boolean isSessionValid(String sessionId) {
        if (sessionId != null && !sessionId.isEmpty()) {
            return redisTemplate.hasKey(SESSION_PREFIX + sessionId);
        } else {
            return false;
        }
    }

    public void invalidateSession(HttpServletRequest request,String sessionId) {
        if (sessionId != null && !sessionId.isEmpty()) {
            HttpSession session = request.getSession(true);
            session.invalidate();

        } else {
            throw new IllegalArgumentException("Session ID cannot be null or empty");
        }
    }
}