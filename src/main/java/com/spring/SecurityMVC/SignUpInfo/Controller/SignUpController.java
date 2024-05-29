package com.spring.SecurityMVC.SignUpInfo.Controller;

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
public class SignUpController {
    private final SignUpService signUpService;

    @PostMapping("${Security.backEndPoint}/SignUp")
    public ResponseEntity<Void> SignUp(@RequestBody(required = false)SignUp signUp, HttpServletResponse response, HttpServletRequest request){
        return signUpService.SignUp(signUp,request,response);
    }

    @PostMapping("${Security.backEndPoint}/PostEmail")
    public ResponseEntity<Void> PostEmail(@RequestBody Map<String, String> payload,HttpServletRequest request,HttpServletResponse response){
        return signUpService.PostEmail(payload.get("Email"),request,response);
    }
    @PostMapping("${Security.backEndPoint}/CheckEmailCode")
    public ResponseEntity<Void> CheckEmailCode(@RequestBody Map<String, String> payload, HttpServletRequest request, HttpServletResponse response){
        return signUpService.CheckEmailCode(payload.get("Email"),payload.get("EmailCode"),request,response);
    }

    @PostMapping("${Security.backEndPoint}/ValidateUserName")
    public ResponseEntity<Void> ValidateUserName(@RequestBody Map<String, String> payload, HttpServletRequest request, HttpServletResponse response) {
        return signUpService.ValidateUserName(payload.get("UserName"), request, response);
    }
    @PostMapping("${Security.backEndPoint}/ValidateEmail")
    public ResponseEntity<Void> ValidateEmail(@RequestBody Map<String, String> payload,HttpServletRequest request,HttpServletResponse response){
        return signUpService.ValidateEmail(payload.get("Email"),request,response);
    }
}
