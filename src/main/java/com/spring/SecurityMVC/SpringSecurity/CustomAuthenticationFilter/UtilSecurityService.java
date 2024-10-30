package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;

import javax.management.relation.Role;
import java.util.List;

@Service
public class UtilSecurityService {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final SessionService sessionService;

    public UtilSecurityService(JwtService jwtService, RefreshTokenService refreshTokenService, SessionService sessionService) {
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.sessionService = sessionService;
    }

    public String getAccessTokenFromCookies(HttpServletRequest request){
        return refreshTokenService.getAccessTokenFromCookies(request);
    }
    public List<String> getRolesFromToken(Claims claims){
        return jwtService.getRolesFromToken(claims);
    }
    public Claims getAllClaimsFromToken(String accessToken){
        return jwtService.getAllClaimsFromToken(accessToken);
    }
    public void validateAuthentication(String accessToken, HttpSession session) throws CustomExceptions.SessionException, CustomExceptions.TokenException {
        validateSession(session);
        validateTokenAndRefreshIfNeeded(accessToken);
        validateRolesInToken(accessToken);
    }


    private void validateTokenAndRefreshIfNeeded(String accessToken) throws CustomExceptions.TokenException, CustomExceptions.TokenException {
        if (StringUtils.isBlank(accessToken)) {
            throw new CustomExceptions.TokenException("Access token is missing");
        }
        try {
            jwtService.validateToken(accessToken);
        } catch (JwtException AccessException) {
            throw new CustomExceptions.TokenException("Access token is Expired");
        }
    }

    private String retrieveAndValidateRefreshToken(String username) throws CustomExceptions.TokenException {
        String refreshToken = refreshTokenService.getRefreshToken(username);
        if (StringUtils.isBlank(refreshToken)) {
            throw new CustomExceptions.TokenException("Refresh token is missing for user: " + username);
        }
        return refreshToken;
    }

    private void validateRefreshToken(String refreshToken, String username) throws CustomExceptions.TokenException {
        if (!jwtService.validateRefreshToken(refreshToken, username)) {
            throw new CustomExceptions.TokenException("Invalid refresh token for user: " + username);
        }
    }

    private void validateRolesInToken(String accessToken) throws CustomExceptions.TokenException {
        Claims claims = jwtService.getAllClaimsFromToken(accessToken);
        List<String> roles = jwtService.getRolesFromToken(claims);
        if (roles == null || roles.isEmpty()) {
            throw new CustomExceptions.TokenException("No roles found in token");
        }
    }

    private void validateSession(HttpSession session) throws CustomExceptions.SessionException {
        String sessionId = session.getId();
        if (StringUtils.isBlank(sessionId) || !sessionService.isSessionValid(sessionId)) {
            throw new CustomExceptions.SessionException("Session is not valid: " + sessionId);
        }
    }

}