package com.spring.SecurityMVC.LoginInfo.Domain;

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
    private String authority;
    private List<SimpleGrantedAuthority> authorities = new ArrayList<>();
    private boolean enabled;
    public List<SimpleGrantedAuthority> setAuthorities(String authority) {
        if (authority != null && !authority.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority(authority));
        }
        return authorities;
    }

}
