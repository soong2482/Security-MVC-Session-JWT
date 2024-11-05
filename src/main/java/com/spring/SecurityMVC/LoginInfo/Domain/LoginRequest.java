package com.spring.SecurityMVC.LoginInfo.Domain;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
    private String fingerprint;
}
