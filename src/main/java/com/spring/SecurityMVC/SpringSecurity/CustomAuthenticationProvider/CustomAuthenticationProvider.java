package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationProvider;

import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import com.spring.SecurityMVC.UserInfo.Domain.User;
import com.spring.SecurityMVC.UserInfo.Service.UserDetailsService;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            User user = (User) authentication.getPrincipal();
            return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
        }
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
            if (!userDetailsService.findById(username)) {
                throw new CustomExceptions.AuthenticationFailedException("Invalid username");
            }
            if (!userDetailsService.findByPassword(username,password)) {
                throw new CustomExceptions.AuthenticationFailedException("Invalid password");
            }
            if(!userDetailsService.findByEnabled(username)){
                throw new CustomExceptions.AuthenticationFailedException("Invalid Enabled");
            }
            User user = userDetailsService.findByDetailUser(username).get();
            return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
