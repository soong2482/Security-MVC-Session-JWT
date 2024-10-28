package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import io.jsonwebtoken.Claims;
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
    public String getAccessToken(HttpServletRequest request){
        String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
        if (accessToken == null || !accessToken.isEmpty()) {
            throw new CustomExceptions.AuthenticationFailedException("Access token is missing");
        }
        return accessToken;
    }


    public String[] validationAccessToken(String accessToken){
        if (accessToken == null || !accessToken.isEmpty()) {
            throw new CustomExceptions.AuthenticationFailedException("Access token is missing");
        }
        Claims claims =jwtService.getClaimsFromToken(accessToken);
        String username = claims.getSubject();
        if (username == null || !username.isEmpty()) {
            throw new CustomExceptions.AuthenticationFailedException("Username extraction from access token failed");
        }
        String sessionId = claims.get("SessionId", String.class);
        if (sessionId == null || !sessionservice.isSessionValid(sessionId)) {
            throw new CustomExceptions.AuthenticationFailedException("Session is not valid");
        }
        if(!jwtService.validateToken(claims.getId())){
            String refreshToken = refreshTokenService.getRefreshToken(username);
            if (refreshToken == null) {
                throw new CustomExceptions.AuthenticationFailedException("Refresh token is missing");
            }
            if (!jwtService.validateRefreshToken(refreshToken, username)) {
                throw new CustomExceptions.AuthenticationFailedException("Refresh token is not valid");
            }


        }

        return new String[]{username,sessionId};
    }


    public ResponseEntity<String> login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            SecurityContextHolder.getContext().getAuthentication();

            String accessToken =getAccessToken(request);
            String[] claimsList = validationAccessToken(accessToken);

            String username = claimsList[0];
            String sessionId = claimsList[1];

            List<String> roles = jwtService.getRolesFromToken(accessToken);

            if(roles.isEmpty()) {
               throw new CustomExceptions.AuthenticationFailedException("Failed to extract roles from access token");
            }

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
        }
 else {
            try {
                Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

                Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

                SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

                String username = loginRequest.getUsername();

                List<String> roles = authenticationResponse.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();

                String sessionID = sessionservice.createNewSession(request,username,roles);
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
        String[] claimsList = extractUsernameWithoutTokenValidation(request);
        String username = claimsList[0];
        String sessionId = claimsList[1];

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
            sessionservice.invalidateSession(request, sessionId);
            SecurityContextHolder.clearContext();
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new CustomExceptions.LogoutFailedException("Logout failed: " + username + ": " + e.getMessage());
        }
    }
}
