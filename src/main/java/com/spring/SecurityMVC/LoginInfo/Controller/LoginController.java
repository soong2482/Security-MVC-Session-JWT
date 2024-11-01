package com.spring.SecurityMVC.LoginInfo.Controller;

import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.LoginInfo.Domain.UsernameRequest;
import com.spring.SecurityMVC.LoginInfo.Service.LoginService;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import jakarta.mail.Session;
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
    private final SessionService sessionService;
    @PostMapping("${Security.backEndPoint}/Login")
    public ResponseEntity<String> login(@RequestBody(required = false) LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        return loginService.login(loginRequest, response, request);
    }
    @PostMapping("${Security.backEndPoint}/AuthLogin")
    public ResponseEntity<String> authlogin(HttpServletRequest request,HttpServletResponse response){
        return loginService.authlogin(request,response);
    }
    @PostMapping("${Security.backEndPoint}/Logout")
    public ResponseEntity<Void> logout(HttpServletRequest request,HttpServletResponse response) {
        return loginService.logout(request,response);
    }
    @PostMapping("${Security.backEndPoint}/DeleteSession")
    public ResponseEntity<String> deleteSession(@RequestBody UsernameRequest usernameRequest, HttpServletResponse response) {
        return sessionService.deleteSessionByUsername(usernameRequest,response);
    }

}
