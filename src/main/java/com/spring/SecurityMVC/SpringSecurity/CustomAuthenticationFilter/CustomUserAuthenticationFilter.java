package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomFailedHandler;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomSuccessHandler;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class CustomUserAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final CustomSuccessHandler successHandler;
    private final CustomFailedHandler failureHandler;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final SessionService sessionService;

    public CustomUserAuthenticationFilter(CustomSuccessHandler successHandler, CustomFailedHandler failureHandler, RefreshTokenService refreshTokenService, JwtService jwtService, SessionService sessionService) {
        super(new AntPathRequestMatcher("/Security/User/**"));
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.sessionService = sessionService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
        List<String> authoritiesObj =jwtService.getRolesFromToken(accessToken);
        if (authoritiesObj == null) {
            throw new AuthenticationException("No roles found in session") {};
        }
        String sessionId = jwtService.getSessionIdFromToken(accessToken);
        if (sessionId == null || !sessionService.isSessionValid(sessionId)) {
            throw new AuthenticationException("User is not authenticated(Session is not valid)") {};
        }

        List<SimpleGrantedAuthority> authorities = authoritiesObj.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        boolean isUser = false;
        for (GrantedAuthority authority : authorities) {
            if ("ROLE_USER".equals(authority.getAuthority())) {
                isUser = true;
                break;
            }
        }

        if (!isUser) {
            throw new AuthenticationException("User does not have USER privileges") {};
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                jwtService.getUsernameFromToken(accessToken),
                null,
                authorities
        );

        return authRequest;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
