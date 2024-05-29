package com.spring.SecurityMVC.AdminInfo.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SuperAdminController {

    @PostMapping("${Security.backEndPoint}/SuperAdmin/Check")
    public ResponseEntity<String> check(HttpServletRequest request, HttpServletResponse response){
        return ResponseEntity.ok().body("Welcome SuperAdmin");
    }
}
