package com.spring.SecurityMVC.SpringSecurity.CustomHandler;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
public class CustomFailedHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        String clientIP = request.getRemoteAddr();
        String requestURI = request.getRequestURI();
        String errorMessage = exception.getMessage();



        log.warn("Authentication failed from IP: {} on API: {} with exception: {}", clientIP, requestURI, errorMessage);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(exception.getMessage());
    }
}
