package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomFailedHandler;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomSuccessHandler;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class CustomAuthenticationJwtFilter extends AbstractAuthenticationProcessingFilter {
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CustomFailedHandler failureHandler;
    private final CustomSuccessHandler successHandler;

    public CustomAuthenticationJwtFilter(JwtService jwtService, RefreshTokenService refreshTokenService, CustomFailedHandler failureHandler, CustomSuccessHandler successHandler) {
        super(new AntPathRequestMatcher("/Security/Data/**"));
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.failureHandler = failureHandler;
        this.successHandler = successHandler;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

            String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
            if (accessToken == null) {
                throw new AuthenticationException("Access token is missing") {};
            }

            if (!jwtService.validateToken(accessToken)) {
                throw new AuthenticationException("Access token is not valid") {};
            }

            Claims claims = jwtService.getClaimsFromToken(accessToken);
            String username = claims.getSubject();
             List<String> roles = (List<String>) claims.get("roles", List.class);

            if (username == null) {
                throw new AuthenticationException("User is not authenticated (username is not valid)") {};
            }

            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

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
