package com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationProvider;

import com.spring.SecurityMVC.LoginInfo.Domain.User;
import com.spring.SecurityMVC.LoginInfo.Service.UserDetailsService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        try {
            if (!userDetailsService.findById(username)) {
                throw new UsernameNotFoundException("Invalid username");
            }

            User user = userDetailsService.findByPassword(username);
            if (user == null || !user.getPassword().equals(password)) {
                throw new BadCredentialsException("Invalid password");
            }
            return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
        } catch (UsernameNotFoundException | BadCredentialsException e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AuthenticationServiceException("An error occurred while trying to authenticate the user", e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
