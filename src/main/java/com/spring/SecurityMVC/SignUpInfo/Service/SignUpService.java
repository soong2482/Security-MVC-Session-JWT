package com.spring.SecurityMVC.SignUpInfo.Service;

import com.spring.SecurityMVC.SignUpInfo.Domain.SignUp;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;

import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import com.spring.SecurityMVC.UserInfo.Service.UserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Service
public class SignUpService {

    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final UserMapper userMapper;
    public SignUpService(UserMapper userMapper, EmailService emailService, RedisTemplate<String, String> redisTemplate, PasswordEncoder passwordEncoder, UserDetailsService userDetailsService, UserMapper userMapper1) {
        this.emailService = emailService;
        this.redisTemplate = redisTemplate;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.userMapper = userMapper1;
    }

    public ResponseEntity<Void> SignUp(SignUp signUp, HttpServletRequest request, HttpServletResponse response) {
        if (signUp == null) {
            throw new CustomExceptions.InvalidRequestException("SignUp information cannot be null");
        }
        if (userDetailsService.findById(signUp.getUsername())) {
            throw new CustomExceptions.UserAlreadyExistsException("Username already exists");
        }
        String storedEmailCode = redisTemplate.opsForValue().get("email_verification:" + signUp.getEmail());
        if (signUp.getEmailCode().equals(storedEmailCode)) {
            signUp.setAuthority("ROLE_USER");
            String encryptedPassword = passwordEncoder.encode(signUp.getPassword());
            signUp.setPassword(encryptedPassword);
            signUp.setEnabled(true);
            userMapper.insertUser(signUp);
            userMapper.insertAuthority(signUp);
            redisTemplate.delete("email_verification:" + signUp.getEmail());
            return ResponseEntity.ok().build();
        } else {
            throw new CustomExceptions.EmailCodeMismatchException("Email code does not match or has expired");
        }
    }

    public ResponseEntity<Void> PostEmail(String email, HttpServletRequest request, HttpServletResponse response) {
        if (email == null || email.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Email cannot be null or empty");
        }
        String authCode = emailService.generateAuthCode();
        redisTemplate.opsForValue().set("email_verification:" + email, authCode, 3000, TimeUnit.SECONDS);
        String subject = "Your Authentication Code";
        String body = "Your authentication code is: " + authCode;
        emailService.sendEmail(email, subject, body);
        return ResponseEntity.ok().build();
    }

    public ResponseEntity<Void> CheckEmailCode(String email, String emailCode, HttpServletRequest request, HttpServletResponse response) {
        if (email == null || email.trim().isEmpty() || emailCode == null || emailCode.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Email and email code cannot be null or empty");
        }
        String storedAuthCode = redisTemplate.opsForValue().get("email_verification:" + email);
        if (storedAuthCode != null && storedAuthCode.equals(emailCode)) {
            return ResponseEntity.ok().build();
        } else {
            throw new CustomExceptions.EmailCodeMismatchException("Email code does not match or has expired");
        }
    }

    public ResponseEntity<Void> ValidateUserName(String username, HttpServletRequest request, HttpServletResponse response) {
        if (username == null || username.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Username cannot be null or empty");
        }
        if (userDetailsService.findById(username)) {
            throw new CustomExceptions.UserAlreadyExistsException("Username already exists");
        } else {
            return ResponseEntity.ok().build();
        }
    }

    public ResponseEntity<Void> ValidateEmail(String email, HttpServletRequest request, HttpServletResponse response) {
        if (email == null || email.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Email cannot be null or empty");
        }
        if (userDetailsService.findByEmail(email)) {
            throw new CustomExceptions.UserAlreadyExistsException("Email already exists");
        } else {
            return ResponseEntity.ok().build();
        }
    }
}
