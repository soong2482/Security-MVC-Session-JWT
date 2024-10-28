package com.spring.SecurityMVC.LoginInfo.Domain;

import lombok.Data;

@Data
public class UsernameRequest {
    private String username;
    private String adminname;
    private String code;
}
