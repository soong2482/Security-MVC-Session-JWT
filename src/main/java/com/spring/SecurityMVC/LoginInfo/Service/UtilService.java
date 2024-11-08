package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.FingerPrintSettings;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

@Service
public class UtilService {
    private final UserMapper userMapper;
    private final RedisTemplate redisTemplate;
    @Autowired
    public UtilService(UserMapper userMapper, RedisTemplate redisTemplate){
        this.userMapper = userMapper;

        this.redisTemplate = redisTemplate;
    }
        public String getClientIP(HttpServletRequest request) {
            String ip = request.getHeader("X-Forwarded-For");
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                ip = ip.split(",")[0];
            } else {
                ip = request.getHeader("Proxy-Client-IP");

                if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
                    ip = request.getHeader("WL-Proxy-Client-IP");
                }
                if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
                    ip = request.getHeader("HTTP_CLIENT_IP");
                }
                if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
                    ip = request.getHeader("HTTP_X_FORWARDED_FOR");
                }
                if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
                    ip = request.getRemoteAddr();
                }
            }
            return hashIP(ip);
        }
        private String hashIP(String ipAddress) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(ipAddress.getBytes(StandardCharsets.UTF_8));
                StringBuilder hexString = new StringBuilder();
                for (byte b : hash) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) hexString.append('0');
                    hexString.append(hex);
                }
                return hexString.toString();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Error hashing IP address", e);
            }
        }
        public boolean compareHash(String username, String hashedIP) {
            String originalIP=userMapper.getUserIP(username).get();
            return originalIP.equals(hashedIP);
        }

    public ResponseEntity<FingerPrintSettings> getFingerprintSettings() {
        String[] fonts = {"14px Arial", "16px Verdana", "12px Times New Roman", "15px Helvetica"};
        String[] texts = {"fingerprint", "uniqueID", "browserTest", "sampleText"};

        Random random = new Random();
        String randomFont = fonts[random.nextInt(fonts.length)];
        String randomText = texts[random.nextInt(texts.length)];
        FingerPrintSettings fp = new FingerPrintSettings();
        fp.setFont(randomFont);
        fp.setSize(randomText);

            return ResponseEntity.ok(fp);
        }

    public String getUserNameFromCookies(HttpServletRequest request) {
        if(request.getCookies()==null){
            throw new CustomExceptions.MissingRequestBodyException("Cookies are missing");
        }
        for (Cookie cookie : request.getCookies()) {
            if ("username".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return "";
    }
    public void DeleteFinger(String username){
        String key = "finger-print:"+username;
        if(redisTemplate.hasKey(key)) {
            redisTemplate.delete(key);
        }
    }
}
