package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter;

import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomFailedHandler;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomSuccessHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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

public class CustomUserAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final CustomSuccessHandler successHandler;
    private final CustomFailedHandler failureHandler;

    public CustomUserAuthenticationFilter(CustomSuccessHandler successHandler, CustomFailedHandler failureHandler) {
        super(new AntPathRequestMatcher("/Security/User/**"));
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("username") == null) {
            throw new AuthenticationException("User is not authenticated") {};
        }

        List<?> authoritiesObj = (List<?>) session.getAttribute("roles");
        if (authoritiesObj == null) {
            throw new AuthenticationException("No roles found in session") {};
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        for (Object authorityObj : authoritiesObj) {
            if (authorityObj instanceof GrantedAuthority) {
                authorities.add((GrantedAuthority) authorityObj);
            } else if (authorityObj instanceof String) {
                authorities.add(new SimpleGrantedAuthority((String) authorityObj));
            } else {
                throw new AuthenticationException("Invalid authority type in session") {};
            }
        }

        boolean isSuperAdmin = false;
        for (GrantedAuthority authority : authorities) {
            if ("ROLE_USER".equals(authority.getAuthority())) {
                isSuperAdmin = true;
                break;
            }
        }

        if (!isSuperAdmin) {
            throw new AuthenticationException("User does not have USER privileges") {};
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                session.getAttribute("username"),
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
