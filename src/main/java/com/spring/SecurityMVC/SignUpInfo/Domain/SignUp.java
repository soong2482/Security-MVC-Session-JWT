package com.spring.SecurityMVC.SignUpInfo.Domain;

import lombok.Data;

@Data
public class SignUp {
    private String username;
    private String password;
    private String email;
    private Boolean enabled;
    private String roleid;
    private String ipaddress;
}
