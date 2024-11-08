package com.spring.SecurityMVC.SignUpInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Service.UtilService;
import com.spring.SecurityMVC.SignUpInfo.Domain.*;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;

import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class SignUpService {

    private final UserMapper userMapper;
    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final UtilService utilService;
    public SignUpService(UserMapper userMapper, EmailService emailService, RedisTemplate<String, String> redisTemplate, PasswordEncoder passwordEncoder, UtilService utilService) {
        this.userMapper = userMapper;
        this.emailService = emailService;
        this.redisTemplate = redisTemplate;
        this.passwordEncoder = passwordEncoder;
        this.utilService = utilService;
    }

    public ResponseEntity<String> SignUp(SignUp signUp, HttpServletRequest request, HttpServletResponse response) {
        if (signUp == null  ||signUp.getEmail()==null || signUp.getPassword() == null || signUp.getUsername() == null) {
            throw new CustomExceptions.InvalidRequestException("SignUp information cannot be null");
        }
        signUp.setRoleid("1");
        String encryptedPassword = passwordEncoder.encode(signUp.getPassword());
        signUp.setPassword(encryptedPassword);
        signUp.setIpaddress(utilService.getClientIP(request));
        signUp.setEnabled(true);
        try {
            userMapper.insertUser(signUp);
            userMapper.insertAuthority(signUp);
            userMapper.insertEnabled(signUp);
        } catch (DuplicateKeyException e) {
            throw new CustomExceptions.UserAlreadyExistsException("Duplicate entry for user: " + e.getMessage());
        } catch (DataIntegrityViolationException e) {
            throw new CustomExceptions.DataConflictException("Data integrity violation: " + e.getMessage());
        } catch (DataAccessException e) {
            throw new CustomExceptions.DatabaseException("Database operation failed: " + e.getMessage());
        }
        return ResponseEntity.ok(signUp.getUsername()+":SingUp Success");
    }

    public ResponseEntity<String> PostEmail(PostEmail postEmail, HttpServletRequest request, HttpServletResponse response) {
        String email = postEmail.getEmail();
        if (email == null || email.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Email cannot be null or empty");
        }
        String authCode = emailService.generateAuthCode();
        redisTemplate.opsForValue().set("email_verification:" + email, authCode, 300, TimeUnit.SECONDS);
        String subject = "Your Authentication Code";
        String body = "Your authentication code is: " + authCode;
        emailService.sendEmail(email, subject, body);
        return ResponseEntity.ok(email+":post mail success");
    }

    public ResponseEntity<String> CheckEmailCode(CheckEmailCode checkEmailCode, HttpServletRequest request, HttpServletResponse response) {
        String email = checkEmailCode.getEmail();
        String emailCode = checkEmailCode.getEmailcode();
        if (email == null || email.trim().isEmpty() || emailCode == null || emailCode.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Email and EmailCode cannot be null or empty");
        }
        if(!redisTemplate.hasKey("email_verification:"+email)) {
            throw new CustomExceptions.MissingRequestBodyException("Redis: Not Have EmailCode");
        }
        String storedAuthCode = redisTemplate.opsForValue().get("email_verification:" + email);

        if (storedAuthCode != null && storedAuthCode.equals(emailCode)) {
            redisTemplate.delete("email_verification:" + email);
            return ResponseEntity.ok(email+":Check Email Success");
        } else {
            throw new CustomExceptions.EmailCodeMismatchException("Email code does not match or has expired");
        }
    }

    public ResponseEntity<String> ValidateUserName(ValidateUserName validateUserName, HttpServletRequest request, HttpServletResponse response) {
        String username = validateUserName.getUsername();
        if ( username== null || username.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Username cannot be null or empty");
        }
        if (userMapper.FindById(username).isPresent()) {
            throw new CustomExceptions.UserAlreadyExistsException("Username already exists");
        } else {
            return ResponseEntity.ok(username+": Available for use");
        }
    }

    public ResponseEntity<String> ValidateEmail(ValidateEmail validateEmail, HttpServletRequest request, HttpServletResponse response) {
        String email = validateEmail.getEmail();
        if (email == null || email.trim().isEmpty()) {
            throw new CustomExceptions.InvalidRequestException("Email cannot be null or empty");
        }
        if (userMapper.FindByEmail(email).isPresent()) {
            throw new CustomExceptions.UserAlreadyExistsException("Email already exists");
        } else {
            return ResponseEntity.ok(email+": Available for use");
        }
    }
}
