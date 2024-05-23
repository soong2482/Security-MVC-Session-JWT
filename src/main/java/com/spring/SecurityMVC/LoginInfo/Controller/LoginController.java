package com.spring.SecurityMVC.LoginInfo.Controller;

import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.LoginInfo.Service.LoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {
    private final LoginService loginService;

    @PostMapping("${Security.backEndPoint}/Login")
    public ResponseEntity<Void> login(@RequestBody(required = false) LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            HttpSession session = request.getSession(false);
            if (session != null && session.getAttribute("userId") != null) {
                return ResponseEntity.ok().build();
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        }
        loginService.Login(loginRequest, response, request);
        return ResponseEntity.ok().build();
    }
    @PostMapping("${Security.backEndPoint}/Logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        return ResponseEntity.ok().build();
    }
}
