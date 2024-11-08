package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.DeleteSessionRequest;

import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class SessionService {
    @Value("${spring.session.prefix}")
    private String SESSION_PREFIX;

    private final RedisTemplate<String, String> redisTemplate;

    public SessionService(RedisTemplate<String, String> redisTemplate) {

        this.redisTemplate = redisTemplate;
    }

    public void createNewSession(HttpServletRequest request, String username, List<String> roles) {
        HttpSession session = request.getSession(true);
        session.setMaxInactiveInterval(1800);
        session.setAttribute("username", username);
        session.setAttribute("roles", roles);


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new CustomExceptions.AuthenticationFailedException("Authentication is not present or invalid.");
        }
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());


        String key = "user_session:" + username;
        redisTemplate.opsForValue().set(key, session.getId(), 1800, TimeUnit.SECONDS);
    }


    public boolean isSessionValid(String sessionId) {
        if (!StringUtils.isBlank(sessionId)) {
            return redisTemplate.hasKey(SESSION_PREFIX + sessionId);
        } else {
            return false;
        }
    }

    public void invalidateSession(HttpSession session, String username) {
        if (username != null && !username.isEmpty()) {
            String key = "user_session:" + username;
            redisTemplate.delete(key);
            session.invalidate();
        } else {
            throw new CustomExceptions.SessionException("Session ID cannot be null or empty");
        }
    }

    public String deleteSessionByUsername(DeleteSessionRequest deleteSessionRequest, HttpServletResponse httpServletResponse) {

        String username = deleteSessionRequest.getUsername();
        String code = deleteSessionRequest.getCode();
        String adminname = deleteSessionRequest.getAdminname();
        if (StringUtils.isBlank(username) || StringUtils.isBlank(code) || StringUtils.isBlank(adminname)) {
            throw new CustomExceptions.MissingRequestBodyException("Body must not be empty");
        }
        if (!redisTemplate.hasKey("user_session:" + username)) {
            throw new CustomExceptions.SessionException(username + ": already delete session");
        }
        String sessionId = redisTemplate.opsForValue().get("user_session:" + username);

        if (!redisTemplate.delete("user_session:" + username)) {
            throw new CustomExceptions.SessionException(username + ": already delete session");
        }
        if (!redisTemplate.delete("refreshToken:" + username)) {
            throw new CustomExceptions.TokenException(username + ": already expired RefreshToken");
        }
        if (!redisTemplate.delete("finger-print:" + username)) {
            throw new CustomExceptions.TokenException(username + ": already delete finger-print");
        }
        if (redisTemplate.hasKey(SESSION_PREFIX + sessionId)) {
            redisTemplate.expire(SESSION_PREFIX + sessionId, 1, TimeUnit.SECONDS);
        } else {
            throw new CustomExceptions.SessionException(username + ": already expired session");
        }
        log.info("Admin:" + adminname + "delete for user session:" + username + "Delete Code:" + code);
        return username + ":Delete Success";
    }


}