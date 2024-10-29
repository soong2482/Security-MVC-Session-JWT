package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter;

import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomFailedHandler;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomSuccessHandler;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
public class CustomAuthenticationJwtFilter extends AbstractAuthenticationProcessingFilter {

    private final CustomSuccessHandler successHandler;
    private final CustomFailedHandler failureHandler;
    private final UtilSecurityService utilSecurityService;

    public CustomAuthenticationJwtFilter(CustomSuccessHandler successHandler, CustomFailedHandler failureHandler, UtilSecurityService utilSecurityService) {
        super(new AntPathRequestMatcher("/Security/Data/**"));
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.utilSecurityService = utilSecurityService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws CustomExceptions.TokenException, IOException, ServletException {
        String accessToken = utilSecurityService.getAccessTokenFromCookies(request);
        HttpSession session = request.getSession(false);

        utilSecurityService.validateAuthentication(accessToken, session);

        Claims claims = utilSecurityService.getAllClaimsFromToken(accessToken);

        List<SimpleGrantedAuthority> authorities = utilSecurityService.getRolesFromToken(claims).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());


        return new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
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