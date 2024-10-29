package com.spring.SecurityMVC.JwtInfo.Service;

import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {
    @Value("${spring.Refresh.token.Expiration}")
    private long REFRESH_TOKEN_EXPIRATION;

    private final RedisTemplate<String, String> redisTemplate;

    public RefreshTokenService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveRefreshToken(String username, String refreshToken) {
        String key = "refreshToken:" + username;
        redisTemplate.opsForValue().set(key, refreshToken, REFRESH_TOKEN_EXPIRATION, TimeUnit.SECONDS);
        if(!redisTemplate.hasKey(key)){
            throw new CustomExceptions.TokenException("Redis:Failed Save RefreshToken:"+username);
        }
    }

    public String getRefreshToken(String username) {
        if (!StringUtils.isBlank(username)) {
            String key = "refreshToken:" + username;
            return redisTemplate.opsForValue().get(key);
        }else{
            throw new CustomExceptions.TokenException("Failed Get RefreshToken:"+username);
        }
    }

    public String getAccessTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("Access-Token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        throw new CustomExceptions.TokenException("Failed Not Have AccessToken");
    }
    public void deleteRefreshToken(String username) {
        String key = "refreshToken:" + username;
        if(redisTemplate.hasKey(key)) {
            redisTemplate.delete(key);
        }else{
            throw new CustomExceptions.TokenException("Redis:Failed Delete RefreshToken:"+username);
        }
    }
}
