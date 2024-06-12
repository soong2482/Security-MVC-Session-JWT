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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class CustomJWTAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CustomFailedHandler failureHandler;
    private final CustomSuccessHandler successHandler;

    public CustomJWTAuthenticationFilter(JwtService jwtService, RefreshTokenService refreshTokenService, CustomFailedHandler failureHandler, CustomSuccessHandler successHandler) {
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.failureHandler = failureHandler;
        this.successHandler = successHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String requestURI = request.getRequestURI();
            if ("/Security/Login".equals(requestURI) || "/Security/Logout".equals(requestURI)) {
                filterChain.doFilter(request, response);
                return;
            }

            Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
            if (existingAuth == null || !existingAuth.isAuthenticated()) {
                throw new CustomExceptions.AuthenticationFailedException("User is not authenticated");
            }

            String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
            if (accessToken == null) {
                throw new CustomExceptions.AuthenticationFailedException("Access token is missing");
            }

            if (!jwtService.validateToken(accessToken)) {
                throw new CustomExceptions.AuthenticationFailedException("Access token is not valid");
            }

            Claims claims = jwtService.getClaimsFromToken(accessToken);
            String username = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);

            if (username == null) {
                throw new CustomExceptions.AuthenticationFailedException("User is not authenticated (username is not valid)");
            }

            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities
            );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);

            successHandler.onAuthenticationSuccess(request, response, authToken);

            filterChain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            failureHandler.onAuthenticationFailure(request, response, ex);
        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
            failureHandler.onAuthenticationFailure(request, response, new BadCredentialsException(ex.getMessage(), ex));
        }
    }
}
