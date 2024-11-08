package com.spring.SecurityMVC.LoginInfo.Domain;

import lombok.Data;

@Data
public class DeleteSessionRequest {
    private String username;
    private String adminname;
    private String code;
}
