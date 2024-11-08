package com.spring.SecurityMVC.SignUpInfo.Domain;

import lombok.Data;

@Data
public class CheckEmailCode {
    private String email;
    private String emailcode;
}
