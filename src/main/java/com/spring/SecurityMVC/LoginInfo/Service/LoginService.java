package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import org.springframework.security.core.GrantedAuthority;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class LoginService {
    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public LoginService(AuthenticationManager authenticationManager, UserMapper userMapper) {
        this.authenticationManager = authenticationManager;
        this.userMapper = userMapper;
    }

    public ResponseEntity<Void> Login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            HttpSession session = request.getSession(false);
            if (session != null && session.getAttribute("username") != null) {
                return ResponseEntity.ok().build();
            } else {
                throw new CustomExceptions.AuthenticationFailedException("User is not authenticated");
            }
        } else {
            try {
                Authentication authenticationRequest =
                        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
                Authentication authenticationResponse =
                        this.authenticationManager.authenticate(authenticationRequest);
                SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

                HttpSession session = request.getSession(true);
                session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
                session.setAttribute("username", loginRequest.getUsername());
                List<GrantedAuthority> authorities = (List<GrantedAuthority>) authenticationResponse.getAuthorities();
                session.setAttribute("roles", authorities);
                session.setMaxInactiveInterval(600); // 10 minutes
                return ResponseEntity.ok().build();
            } catch (Exception ex) {
                throw new CustomExceptions.AuthenticationFailedException("Authentication failed: " + ex.getMessage());
            }
        }
    }

    public ResponseEntity<Void> Logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            return ResponseEntity.ok().build();
        } else {
            throw new CustomExceptions.AuthenticationFailedException("User is not authenticated");
        }
    }
}
