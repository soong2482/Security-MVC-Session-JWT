package com.spring.SecurityMVC.SpringSecurity.CustomHandler;

import com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter.CustomAuthenticationFilter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import java.io.IOException;

@Slf4j
public class CustomFailedHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        log.warn("Authentication failed for user: {} with exception: {}", session.getAttribute("username"), exception.getMessage());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
