package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.JwtInfo.Service.JwtService;
import com.spring.SecurityMVC.JwtInfo.Service.RefreshTokenService;
import com.spring.SecurityMVC.LoginInfo.Domain.AuthLoginRequest;
import com.spring.SecurityMVC.LoginInfo.Domain.AuthLogoutRequest;
import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
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
import java.util.concurrent.TimeUnit;


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
    private final RedisTemplate redisTemplate;
    @Autowired
    public LoginService(AuthenticationManager authenticationManager, UserMapper userMapper, JwtService jwtService, RefreshTokenService refreshTokenService, SessionService sessionservice, UtilService utilService, RedisTemplate redisTemplate) {
        this.authenticationManager = authenticationManager;
        this.userMapper = userMapper;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.sessionservice = sessionservice;
        this.utilService = utilService;
        this.redisTemplate = redisTemplate;
    }

    public String getAccessToken(HttpServletRequest request) {
        String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
        if (StringUtils.isBlank(accessToken)) {
            throw new CustomExceptions.MissingRequestBodyException("Access token is missing");
        }
        return accessToken;
    }


    public Claims validationAccessToken(String accessToken,HttpSession session,String fingerprint,String username) {
        if(session==null){;
            String key = "finger-print:" + username;
            if(!fingerprint.equals(redisTemplate.opsForValue().get(key))){
                throw new CustomExceptions.AuthenticationFailedException("Finger Data not equals original Data");
            }
        }else {
            username = (String) session.getAttribute("username");
        }
        if (StringUtils.isBlank(username)) {
            throw new CustomExceptions.AuthenticationFailedException("Username extraction from Session failed. Null Session");
        }
        Claims claims = null;
        try {
            claims = jwtService.getAllClaimsFromToken(accessToken);
        } catch (JwtException AccessException) {
            String refreshToken = refreshTokenService.getRefreshToken(username);
            if (StringUtils.isBlank(refreshToken)) {
                throw new CustomExceptions.MissingRequestBodyException("Refresh token is missing");
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
    public String authlogin(AuthLoginRequest authLoginRequest,HttpServletRequest request, HttpServletResponse response){
        SecurityContextHolder.getContext().getAuthentication();
        String username = "";
        username = utilService.getUserNameFromCookies(request);
        if(StringUtils.isBlank(username)){
            throw new CustomExceptions.MissingRequestBodyException("Username is missing");
        }

        String accessToken = getAccessToken(request);
        HttpSession session = request.getSession(false);
        Claims claims = validationAccessToken(accessToken,session,authLoginRequest.getFingerprint(),username);
        List<String> roles = jwtService.getRolesFromToken(claims);

        if (roles.isEmpty()) {
            throw new CustomExceptions.TokenException("Failed to extract roles from access token");
        }
        if(session!=null){
            sessionservice.invalidateSession(session, username);
        }
        sessionservice.createNewSession(request, username, roles);
        String newAccessToken = jwtService.generateAccessToken(username, roles);


        ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", newAccessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(ACCESS_TOKEN_EXPIRATION)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

        return "Token and Session Refreshed Successful";
    }



    public String login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null || loginRequest.getUsername() == null || loginRequest.getPassword() == null || loginRequest.getFingerprint()==null) {
            throw new CustomExceptions.InvalidRequestException("Invalid request: Login data is missing.");
        }
        HttpSession session = request.getSession(false);
        if(session!=null){
            request.getSession().invalidate();
            SecurityContextHolder.clearContext();
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

        redisTemplate.opsForValue().set("finger-print:"+username, loginRequest.getFingerprint(), 60 * 60 * 24 * 7, TimeUnit.SECONDS);

        ResponseCookie accessTokenCookie = ResponseCookie.from("Access-Token", accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(ACCESS_TOKEN_EXPIRATION)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

        ResponseCookie userNameCookie = ResponseCookie.from("username",username)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(REFRESH_TOKEN_EXPIRATION)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, userNameCookie.toString());

        String ip = utilService.getClientIP(request);
        if (!utilService.compareHash(username, ip)) {
            userMapper.UpdateIP(username, ip);
            return "IP changed for user: " + username;
        }
        return "Login successful";

    }

    public String logout(AuthLogoutRequest authLogoutRequest, HttpServletRequest request, HttpServletResponse response) {
        SecurityContextHolder.getContext().getAuthentication();
        String username = "";
        username = utilService.getUserNameFromCookies(request);
        if(StringUtils.isBlank(username)){
            throw new CustomExceptions.MissingRequestBodyException("Username is missing");
        }

        HttpSession session = request.getSession(false);
        String accessToken = getAccessToken(request);
        validationAccessToken(accessToken,session,authLogoutRequest.getFingerprint(),username);

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
        ResponseCookie userNameCookie = ResponseCookie.from("username",null) .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, userNameCookie.toString());
        refreshTokenService.deleteRefreshToken(username);
        if(session!=null) {
            sessionservice.invalidateSession(session, username);
        }else{
            ResponseCookie sessionCookie = ResponseCookie.from("SESSION", null)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie.toString());
        }
        utilService.DeleteFinger(username);
        SecurityContextHolder.clearContext();

        return "Logout Successful";
    }
}
