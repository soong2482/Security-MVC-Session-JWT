package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.User;
import com.spring.SecurityMVC.LoginInfo.Mapper.UserMapper;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
public class UserDetailsService {
    private final UserMapper userMapper;

    public UserDetailsService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public boolean findById(String username) {
        try {
            if (userMapper.FindById(username) != null) {
                return true;
            } else {
                log.error("Failed to FindById:{}", username);
                return false;
            }
        } catch (Exception e) {
            log.error("DB:Error while finding user by id: {}", e.getMessage());
            return false;
        }
    }
    public User findByPassword(String username) {
        try {
            User user = userMapper.FindByPassword(username);
            if (user != null) {
                user.setAuthorities(user.getAuthority());
                return user;
            }
            else{
                log.error("Failed to FindByPassword:{}: {}",username);
                return null;
            }
        } catch (Exception e) {
            log.error("DB:Error while finding user by password: {}", e.getMessage());
        }
        return null;
    }
}
