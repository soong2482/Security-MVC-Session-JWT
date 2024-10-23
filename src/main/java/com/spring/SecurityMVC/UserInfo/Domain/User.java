package com.spring.SecurityMVC.UserInfo.Domain;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
public class User implements Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private List<SimpleGrantedAuthority> authorities = new ArrayList<>();
    private String email;
    public void setAuthorities(List<String> roles) {
        for (String role : roles) {
            if (role != null && !role.isEmpty()) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
        }
    }

}
