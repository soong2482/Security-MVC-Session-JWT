package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.UsernameRequest;

import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;

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

    public void invalidateSession(HttpSession session,String username) {
        if (username != null && !username.isEmpty()) {
            String key = "user_session:"+username;
            redisTemplate.delete(key);
            session.invalidate();
        } else {
            throw new CustomExceptions.SessionException("Session ID cannot be null or empty");
        }
    }
    public ResponseEntity<String> deleteSessionByUsername(UsernameRequest usernameRequest, HttpServletResponse httpServletResponse) {
        String username = usernameRequest.getUsername();
        String code = usernameRequest.getCode();
        String adminname = usernameRequest.getAdminname();
        String sessionId = redisTemplate.opsForValue().get("user_session:" + username);
        redisTemplate.expire(SESSION_PREFIX+sessionId, 1,  TimeUnit.SECONDS);
        redisTemplate.delete("user_session:"+username);
        redisTemplate.delete("refreshToken:"+username);
        return ResponseEntity.ok().body("Delete Success");
    }




}