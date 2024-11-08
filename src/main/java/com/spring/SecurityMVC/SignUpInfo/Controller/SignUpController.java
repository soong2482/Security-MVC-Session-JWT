package com.spring.SecurityMVC.SignUpInfo.Controller;

import com.spring.SecurityMVC.SignUpInfo.Domain.*;
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
    public ResponseEntity<String> SignUp(@RequestBody(required = false)SignUp signUp, HttpServletResponse response, HttpServletRequest request){
        return signUpService.SignUp(signUp,request,response);
    }

    @PostMapping("${Security.backEndPoint}/PostEmail")
    public ResponseEntity<String> PostEmail(@RequestBody PostEmail postEmail, HttpServletRequest request, HttpServletResponse response){
        return signUpService.PostEmail(postEmail,request,response);
    }
    @PostMapping("${Security.backEndPoint}/CheckEmailCode")
    public ResponseEntity<String> CheckEmailCode(@RequestBody CheckEmailCode checkEmailCode, HttpServletRequest request, HttpServletResponse response){
        return signUpService.CheckEmailCode(checkEmailCode,request,response);
    }

    @PostMapping("${Security.backEndPoint}/ValidateUserName")
    public ResponseEntity<String> ValidateUserName(@RequestBody ValidateUserName validateUserName, HttpServletRequest request, HttpServletResponse response) {
        return signUpService.ValidateUserName(validateUserName, request, response);
    }
    @PostMapping("${Security.backEndPoint}/ValidateEmail")
    public ResponseEntity<String> ValidateEmail(@RequestBody ValidateEmail validateEmail, HttpServletRequest request, HttpServletResponse response){
        return signUpService.ValidateEmail(validateEmail,request,response);
    }
}
