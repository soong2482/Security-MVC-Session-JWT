package com.spring.SecurityMVC.AdminInfo.Controller;

import com.spring.SecurityMVC.LoginInfo.Domain.DeleteSessionRequest;
import com.spring.SecurityMVC.LoginInfo.Service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SuperAdminController {
    private final SessionService sessionService;

    @PostMapping("${Security.backEndPoint}/SuperAdmin/Check")
    public ResponseEntity<String> check(HttpServletRequest request, HttpServletResponse response){
        return ResponseEntity.ok().body("Welcome SuperAdmin");
    }
    @PostMapping("${Security.backEndPoint}/SuperAdmin/DeleteSession")
    public ResponseEntity<String> deleteSession(@RequestBody DeleteSessionRequest usernameRequest, HttpServletResponse response) {
        return sessionService.deleteSessionByUsername(usernameRequest,response);
    }
}
