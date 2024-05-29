package com.spring.SecurityMVC.LoginInfo.Controller;

import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.LoginInfo.Service.LoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
        return loginService.Login(loginRequest, response, request);
    }
    @PostMapping("${Security.backEndPoint}/Logout")
    public ResponseEntity<Void> logout(HttpServletRequest request,HttpServletResponse response) {
        return loginService.Logout(request,response);
    }
}
