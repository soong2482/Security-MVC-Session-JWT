package com.spring.SecurityMVC.SpringSecurity.CustomHandler;

import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
public class CustomFailedHandler implements AuthenticationFailureHandler {
    private final RefreshTokenService refreshTokenService;
    private final SessionService sessionService;

    public CustomFailedHandler(RefreshTokenService refreshTokenService, SessionService sessionService) {
        this.refreshTokenService = refreshTokenService;
        this.sessionService = sessionService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String clientIP = request.getRemoteAddr();
        String requestURI = request.getRequestURI();
        String errorMessage = exception.getMessage();


        log.warn("Authentication failed from IP: {} on API: {} with exception: {}", clientIP, requestURI, errorMessage);
    }
}
