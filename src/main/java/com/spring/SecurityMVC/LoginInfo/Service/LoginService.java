package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class LoginService {
    @Value("${spring.Refresh.token.Expiration}")
    private long REFRESH_TOKEN_EXPIRATION;

    @Value("${spring.Access.token.Expiration}")
    private long ACCESS_TOKEN_EXPIRATION;

    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final SessionService sessionservice;

    @Autowired
    public LoginService(AuthenticationManager authenticationManager, UserMapper userMapper, JwtService jwtService, RefreshTokenService refreshTokenService, SessionService sessionservice) {

        this.authenticationManager = authenticationManager;
        this.userMapper = userMapper;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.sessionservice = sessionservice;
    }
    public ResponseEntity<String> login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
            if (accessToken == null) {
                throw new CustomExceptions.AuthenticationFailedException("Access token is missing");
            }

            if(!jwtService.validateToken(accessToken)){
                throw new CustomExceptions.AuthenticationFailedException("Access token is not valid");
            }

            String sessionId = jwtService.getSessionIdFromToken(accessToken);
            if (sessionId == null || !sessionservice.isSessionValid(sessionId)) {
                throw new CustomExceptions.AuthenticationFailedException("Session is not valid");
            }

            String refreshToken = refreshTokenService.getRefreshTokenFromCookies(request);
            if (refreshToken == null) {
                throw new CustomExceptions.AuthenticationFailedException("Refresh token is missing");
            }

            String username = jwtService.getUsernameFromToken(accessToken);
            if (username == null) {
                throw new CustomExceptions.AuthenticationFailedException("Username extraction from refresh token failed");
            }

            if (!jwtService.validateRefreshToken(refreshToken, username)) {
                throw new CustomExceptions.AuthenticationFailedException("Refresh token is not valid");
            }

            List<String> roles;
            try {
                roles = jwtService.getRolesFromToken(accessToken);
            } catch (Exception e) {
                throw new CustomExceptions.AuthenticationFailedException("Failed to extract roles from access token");
            }

            try {
                sessionservice.invalidateSession(sessionId);

            } catch (Exception e) {
                throw new CustomExceptions.AuthenticationFailedException("Failed to invalidate the existing session");
            }

            String newSessionId;
            try {
                newSessionId = sessionservice.createNewSession(request, username, roles);
            } catch (Exception e) {
                throw new CustomExceptions.AuthenticationFailedException("Failed to create new session");
            }

            String newAccessToken;
            try {
                newAccessToken = jwtService.generateAccessToken(username, roles, newSessionId);
            } catch (Exception e) {
                throw new CustomExceptions.AuthenticationFailedException("Failed to generate new access token");
            }

            if (newAccessToken == null) {
                throw new CustomExceptions.AuthenticationFailedException("New access token generation returned null");
            }
            ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", newAccessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(ACCESS_TOKEN_EXPIRATION)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            return ResponseEntity.ok().build();
        }
        else {
            try {
                Authentication authenticationRequest =
                        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
                Authentication authenticationResponse =
                        this.authenticationManager.authenticate(authenticationRequest);
                SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
                Collection<? extends GrantedAuthority> authorities = authenticationResponse.getAuthorities();

                HttpSession session = request.getSession(true);
                session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
                session.setAttribute("username", loginRequest.getUsername());
                session.setAttribute("roles", authorities);
                session.setMaxInactiveInterval((int)ACCESS_TOKEN_EXPIRATION/100);

                String username = loginRequest.getUsername();
                List<String> roles = authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
                String accessToken = jwtService.generateAccessToken(username, roles,session.getId());
                String refreshToken = jwtService.generateRefreshToken(username);

                refreshTokenService.saveRefreshToken(username, refreshToken);
                ResponseCookie refreshTokenCookie = ResponseCookie.from("Refresh-Token", refreshToken)
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(REFRESH_TOKEN_EXPIRATION)
                        .build();
                ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", accessToken)
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(ACCESS_TOKEN_EXPIRATION)
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
                response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
                return ResponseEntity.ok().build();
            } catch (Exception ex) {
                throw new CustomExceptions.AuthenticationFailedException("Authentication failed: " + ex.getMessage());
            }
        }
    }

    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
        if (accessToken == null) {
            throw new CustomExceptions.AuthenticationFailedException("Access token is missing");
        }

        if(!jwtService.validateToken(accessToken)){
            throw new CustomExceptions.AuthenticationFailedException("Access token is not valid");
        }

        String refreshToken = refreshTokenService.getRefreshTokenFromCookies(request);
        if (refreshToken == null) {
            throw new CustomExceptions.AuthenticationFailedException("Refresh token is missing");
        }

        String username = jwtService.getUsernameFromToken(accessToken);
        if (username == null) {
            throw new CustomExceptions.AuthenticationFailedException("Username extraction from refresh token failed");
        }

        if (!jwtService.validateRefreshToken(refreshToken, username)) {
            throw new CustomExceptions.AuthenticationFailedException("Refresh token is not valid");
        }

        String sessionId = jwtService.getSessionIdFromToken(accessToken);
        if (sessionId == null || !sessionservice.isSessionValid(sessionId)) {
            throw new CustomExceptions.AuthenticationFailedException("Session is not valid");
        }

        try{
            refreshTokenService.deleteRefreshToken(username);
            sessionservice.invalidateSession(sessionId);
            ResponseCookie refreshTokenCookie = ResponseCookie.from("Refresh-Token", null)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();
            ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", null)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new CustomExceptions.LogoutFailedException("Logout failed {}", username+":"+e);
        }
        }


}
