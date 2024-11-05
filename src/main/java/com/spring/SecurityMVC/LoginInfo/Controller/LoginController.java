package com.spring.SecurityMVC.LoginInfo.Controller;

import com.spring.SecurityMVC.LoginInfo.Domain.*;
import com.spring.SecurityMVC.LoginInfo.Service.LoginService;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import com.spring.SecurityMVC.LoginInfo.Service.UtilService;
import jakarta.mail.Session;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {
    private final LoginService loginService;
    private final SessionService sessionService;
    private final UtilService utilService;
    @PostMapping("${Security.backEndPoint}/Login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        return loginService.login(loginRequest, response, request);
    }
    @GetMapping("${Security.backEndPoint}/GetFingerSettings")
    public ResponseEntity<FingerPrintSettings> fingersettings(){
        return utilService.getFingerprintSettings();
    }
    @PostMapping("${Security.backEndPoint}/AuthLogin")
    public ResponseEntity<String> authlogin(@RequestBody AuthLoginRequest authLoginRequest, HttpServletRequest request, HttpServletResponse response){
        return loginService.authlogin(authLoginRequest,request,response);
    }
    @PostMapping("${Security.backEndPoint}/Logout")
    public ResponseEntity<String> logout(@RequestBody AuthLogoutRequest authLogoutRequest, HttpServletRequest request, HttpServletResponse response) {
        return loginService.logout(authLogoutRequest,request,response);
    }
    @PostMapping("${Security.backEndPoint}/DeleteSession")
    public ResponseEntity<String> deleteSession(@RequestBody UsernameRequest usernameRequest, HttpServletResponse response) {
        return sessionService.deleteSessionByUsername(usernameRequest,response);
    }

}
