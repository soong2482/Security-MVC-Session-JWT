package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import io.jsonwebtoken.Claims;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

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

    public String getAccessToken(HttpServletRequest request) {
        String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
        if (StringUtils.isBlank(accessToken)) {
            throw new CustomExceptions.TokenException("Access token is missing");
        }
        return accessToken;
    }


    public Claims validationAccessToken(String accessToken) {
        if (StringUtils.isBlank(accessToken)) {
            throw new CustomExceptions.TokenException("Access token is missing");
        }
        Claims claims = jwtService.getAllClaimsFromToken(accessToken);
        String username = claims.getSubject();
        if (StringUtils.isBlank(username)) {
            throw new CustomExceptions.AuthenticationFailedException("Username extraction from access token failed");
        }
        String sessionId = claims.get("SessionId", String.class);
        if (StringUtils.isBlank(sessionId)) {
            throw new CustomExceptions.SessionException("Session is not valid");
        }
        if (!jwtService.validateToken(claims.getId())) {
            String refreshToken = refreshTokenService.getRefreshToken(username);
            if (StringUtils.isBlank(refreshToken)) {
                throw new CustomExceptions.TokenException("Refresh token is missing");
            }
            if (!jwtService.validateRefreshToken(refreshToken, username)) {
                throw new CustomExceptions.TokenException("Refresh token is not valid");
            }
        }

        return claims;
    }


    public ResponseEntity<String> login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            SecurityContextHolder.getContext().getAuthentication();

            HttpSession session = request.getSession(false);

            String accessToken = getAccessToken(request);
            Claims claims = validationAccessToken(accessToken);

            String username = claims.getSubject();

            List<String> roles = jwtService.getRolesFromToken(claims);

            if (roles.isEmpty()) {
                throw new CustomExceptions.TokenException("Failed to extract roles from access token");
            }

            sessionservice.invalidateSession(session, username);
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
            Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

            Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

            SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

            String username = loginRequest.getUsername();

            List<String> roles = authenticationResponse.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String sessionID = sessionservice.createNewSession(request, username, roles);
            String accessToken = jwtService.generateAccessToken(username, roles, sessionID);
            String refreshToken = jwtService.generateRefreshToken(username);

            refreshTokenService.saveRefreshToken(username, refreshToken);
            String ip = utilService.getClientIP(request);
            ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(ACCESS_TOKEN_EXPIRATION)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            if (!utilService.compareHash(username, ip)) {
                userMapper.UpdateIP(username, ip);
                return ResponseEntity.ok().body("IP : Change"+username);
            }
            return ResponseEntity.ok().build();
        }
    }

    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        String accessToken = getAccessToken(request);
        Claims claims = validationAccessToken(accessToken);
        String username = claims.getSubject();
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

        refreshTokenService.deleteRefreshToken(username);
        sessionservice.invalidateSession(session, username);
        SecurityContextHolder.clearContext();

        return ResponseEntity.ok().build();
    }
}
