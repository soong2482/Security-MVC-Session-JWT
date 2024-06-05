package com.spring.SecurityMVC.TestInfo;

import com.spring.SecurityMVC.SignUpInfo.Domain.SignUp;
import com.spring.SecurityMVC.SignUpInfo.Service.SignUpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
@RestController
@RequiredArgsConstructor
public class TestController {
    @PostMapping("${Security.backEndPoint}/Test")
    public ResponseEntity<String> SignUp(HttpServletResponse response, HttpServletRequest request){
        return ResponseEntity.ok("JWT 인증 통과");
    }
}
