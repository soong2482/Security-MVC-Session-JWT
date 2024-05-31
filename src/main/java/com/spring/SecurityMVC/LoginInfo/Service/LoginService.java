package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
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

import java.util.Collection;
import java.util.List;

@Service
public class LoginService {
    @Value("${spring.Refresh.token.Expiration}")
    private long REFRESH_TOKEN_EXPIRATION;

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
            String accessToken = request.getHeader("Authorization");
            if (accessToken != null && jwtService.validateToken(accessToken)) {
                String sessionId = jwtService.getSessionIdFromToken(accessToken);
                if (sessionservice.isSessionValid(sessionId)) {
                    return ResponseEntity.ok().build();
                } else {
                    throw new CustomExceptions.AuthenticationFailedException("Session is not valid");
                }
            } else {
                throw new CustomExceptions.AuthenticationFailedException("User is not authenticated");
            }
        }  else {
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
                session.setMaxInactiveInterval(600);

                String username = loginRequest.getUsername();
                List<String> roles = authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
                String accessToken = jwtService.generateAccessToken(username, roles,session.getId());
                String refreshToken = jwtService.generateRefreshToken(username);

                refreshTokenService.saveRefreshToken(username, refreshToken);
                ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                        .httpOnly(true)
                        .secure(true) // HTTPS를 사용할 경우에만 true로 설정
                        .path("/")
                        .maxAge(REFRESH_TOKEN_EXPIRATION)
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
                return ResponseEntity.ok(accessToken);
            } catch (Exception ex) {
                throw new CustomExceptions.AuthenticationFailedException("Authentication failed: " + ex.getMessage());
            }
        }
    }

    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            return ResponseEntity.ok().build();
        } else {
            throw new CustomExceptions.AuthenticationFailedException("User is not authenticated");
        }
    }
}
