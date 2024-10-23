package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SignUpInfo.Service.EmailService;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
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
import java.util.List;
import java.util.Optional;

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
    private final UtilService utilService;
    @Autowired
    public LoginService(AuthenticationManager authenticationManager, UserMapper userMapper, JwtService jwtService, RefreshTokenService refreshTokenService, SessionService sessionservice, UtilService utilService) {
        this.authenticationManager = authenticationManager;
        this.userMapper = userMapper;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.sessionservice = sessionservice;
        this.utilService = utilService;
    }

    // 공통 토큰 검증 메서드 (Access Token 유효성 검증 제외)
    private String extractUsernameWithoutAccessTokenValidation(HttpServletRequest request) {
        String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
        if (accessToken == null) {
            throw new CustomExceptions.AuthenticationFailedException("Access token is missing");
        }

        String username = jwtService.getUsernameFromToken(accessToken);
        if (username == null) {
            throw new CustomExceptions.AuthenticationFailedException("Username extraction from access token failed");
        }

        String sessionId = jwtService.getSessionIdFromToken(accessToken);
        if (sessionId == null || !sessionservice.isSessionValid(sessionId)) {
            throw new CustomExceptions.AuthenticationFailedException("Session is not valid");
        }

        return username;
    }

    private void validateRefreshToken(HttpServletRequest request, String username) {
        String refreshToken = refreshTokenService.getRefreshTokenFromCookies(request);
        if (refreshToken == null) {
            throw new CustomExceptions.AuthenticationFailedException("Refresh token is missing");
        }

        if (!jwtService.validateRefreshToken(refreshToken, username)) {
            throw new CustomExceptions.AuthenticationFailedException("Refresh token is not valid");
        }
    }

    public ResponseEntity<String> login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            // 갱신형 로그인에서는 Access Token 검증을 무시하고 진행

            String username = extractUsernameWithoutAccessTokenValidation(request);
            validateRefreshToken(request, username);

            List<String> roles;
            try {
                String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
                roles = jwtService.getRolesFromToken(accessToken);
            } catch (Exception e) {
                throw new CustomExceptions.AuthenticationFailedException("Failed to extract roles from access token");
            }

            String sessionId = jwtService.getSessionIdFromToken(refreshTokenService.getAccessTokenFromCookies(request));
            sessionservice.invalidateSession(request, sessionId);

            String newSessionId = sessionservice.createNewSession(request, username, roles);
            String newAccessToken = jwtService.generateAccessToken(username, roles, newSessionId);

            ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", newAccessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(ACCESS_TOKEN_EXPIRATION)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            return ResponseEntity.ok().build();
        } else {
            try {
                Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
                Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);
                SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
                String username = loginRequest.getUsername();
                HttpSession session = request.getSession(true);
                session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
                session.setAttribute("username",username);
                session.setMaxInactiveInterval(1800);


                List<String> roles = authenticationResponse.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();

                String accessToken = jwtService.generateAccessToken(username, roles, session.getId());
                String refreshToken = jwtService.generateRefreshToken(username);
                refreshTokenService.saveRefreshToken(username, refreshToken);
                String ip = utilService.getClientIP(request);

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
                if(!utilService.compareHash(username,ip)){
                    userMapper.UpdateIP(username,ip);
                    return ResponseEntity.ok().body("IP : Change");
                }
                return ResponseEntity.ok().build();
            } catch (Exception ex) {
                throw new CustomExceptions.AuthenticationFailedException("Authentication failed: " + ex.getMessage());
            }
        }
    }

    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String username = extractUsernameWithoutAccessTokenValidation(request);
        validateRefreshToken(request, username);

        try {
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

            SecurityContextHolder.clearContext();
            refreshTokenService.deleteRefreshToken(username);
            String sessionId = jwtService.getSessionIdFromToken(refreshTokenService.getAccessTokenFromCookies(request));
            sessionservice.invalidateSession(request, sessionId);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new CustomExceptions.LogoutFailedException("Logout failed: " + username + ": " + e.getMessage());
        }
    }
}
