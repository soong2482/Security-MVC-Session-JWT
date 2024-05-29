package com.spring.SecurityMVC.AdminInfo.Controller;

import com.spring.SecurityMVC.AdminInfo.Service.AdminService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @PostMapping("${Security.backEndPoint}/Admin/Check")
    public ResponseEntity<String> check(HttpServletResponse response, HttpServletRequest request){
       return ResponseEntity.ok().body("welcome Admin");
    }
}
