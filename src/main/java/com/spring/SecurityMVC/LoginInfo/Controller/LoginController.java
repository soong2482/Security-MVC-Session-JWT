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
        String body = loginService.login(loginRequest, response, request);
        return ResponseEntity.ok(body);
    }
    @GetMapping("${Security.backEndPoint}/GetFingerSettings")
    public ResponseEntity<FingerPrintSettings> fingersettings(){
        FingerPrintSettings fingerPrintSettings= utilService.getFingerprintSettings();
        return ResponseEntity.ok(fingerPrintSettings);
    }
    @PostMapping("${Security.backEndPoint}/AuthLogin")
    public ResponseEntity<String> authlogin(@RequestBody AuthLoginRequest authLoginRequest, HttpServletRequest request, HttpServletResponse response){
        String body = loginService.authlogin(authLoginRequest,request,response);
        return ResponseEntity.ok(body);
    }
    @PostMapping("${Security.backEndPoint}/Logout")
    public ResponseEntity<String> logout(@RequestBody AuthLogoutRequest authLogoutRequest, HttpServletRequest request, HttpServletResponse response) {
        String body = loginService.logout(authLogoutRequest,request,response);
        return ResponseEntity.ok(body);
    }


}
