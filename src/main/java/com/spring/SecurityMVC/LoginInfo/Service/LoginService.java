package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import com.spring.SecurityMVC.UserInfo.Service.UserDetailsService;
import io.jsonwebtoken.Claims;;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
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


    public Claims validationAccessToken(String accessToken,HttpSession session) {
        String username = (String) session.getAttribute("username");

        if (StringUtils.isBlank(username)) {
            throw new CustomExceptions.AuthenticationFailedException("Username extraction from Session failed. Null Session");
        }
        Claims claims = null;
        try {
            claims = jwtService.getAllClaimsFromToken(accessToken);
        } catch (JwtException AccessException) {
            String refreshToken = refreshTokenService.getRefreshToken(username);
            if (StringUtils.isBlank(refreshToken)) {
                throw new CustomExceptions.TokenException("Refresh token is missing");
            }
            if (!jwtService.validateRefreshToken(refreshToken, username)) {
                throw new CustomExceptions.TokenException("Refresh token is not valid");
            }
            if(!jwtService.validateToken(refreshToken)){
                throw new CustomExceptions.TokenException("Token expired. Please login again");
            }
            List<String> roles =userMapper.FindByRoles(username);
            claims = Jwts.claims();
            claims.setSubject(username);
            claims.put("roles", roles);
        }
        return claims;

    }
    public ResponseEntity<String> authlogin(HttpServletRequest request,HttpServletResponse response){
        SecurityContextHolder.getContext().getAuthentication();

        HttpSession session = request.getSession(false);

        String accessToken = getAccessToken(request);
        Claims claims = validationAccessToken(accessToken,session);

        String username = (String) session.getAttribute("username");

        List<String> roles = jwtService.getRolesFromToken(claims);

        if (roles.isEmpty()) {
            throw new CustomExceptions.TokenException("Failed to extract roles from access token");
        }
        sessionservice.invalidateSession(session, username);
        sessionservice.createNewSession(request, username, roles);
        String newAccessToken = jwtService.generateAccessToken(username, roles);


        ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", newAccessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(ACCESS_TOKEN_EXPIRATION)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

        return ResponseEntity.ok().build();
    }

    public ResponseEntity<String> login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null || loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
            throw new CustomExceptions.InvalidRequestException("Invalid request: Login data is missing.");
        }

        Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

        String username = loginRequest.getUsername();

        List<String> roles = authenticationResponse.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        sessionservice.createNewSession(request, username, roles);
        String accessToken = jwtService.generateAccessToken(username, roles);
        String refreshToken = jwtService.generateRefreshToken(username);

        refreshTokenService.saveRefreshToken(username, refreshToken);
        ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(ACCESS_TOKEN_EXPIRATION)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        String ip = utilService.getClientIP(request);
        if (!utilService.compareHash(username, ip)) {
            userMapper.UpdateIP(username, ip);
            return ResponseEntity.ok("IP changed for user: " + username);
        }
        return ResponseEntity.ok().build();

    }

    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        String username = (String) session.getAttribute("username");
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
