package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.User;
import com.spring.SecurityMVC.LoginInfo.Mapper.UserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.Optional;

@Slf4j
@Service
public class UserDetailsService {
    private final UserMapper userMapper;

    public UserDetailsService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public boolean findById(String username) {
        try {
            if (userMapper.FindById(username).isPresent()) {
                return true;
            } else {
                log.error("User not found to FindById:{}", username);

            }
        } catch (Exception e) {
            log.error("DB:Error while finding user by id: {}", e.getMessage());
            return false;
        }
        return false;
    }

    public boolean findByPassword(String username, String password) {
        try {
            Optional<String> PasswordOpt = userMapper.FindByPassword(username);
            if (PasswordOpt.isPresent()) {
                if (PasswordOpt.get().equals(password)) {
                    return true;
                } else {
                    log.error("Password mismatch for user: {}", username);
                    return false;
                }
            } else {
                log.error("User not found = Failed to FindByPassword:{}", username);
                return false;
            }
        } catch (Exception e) {
            log.error("DB:Error while finding user by password: {}", e.getMessage());
        }
        return false;
    }
    public boolean findByEnabled(String username){
        try{
            Optional<Boolean> EnabledOpt= userMapper.FindByEnabled(username);
            if(EnabledOpt.isPresent()){
                if (EnabledOpt.get()) {
                    return true;
                } else {
                    log.error("User is disabled to FindByEnabled:{}", username);
                }
            }
        }catch(Exception e){
            log.error("DB:Error while finding user by Enabled: {}",e.getMessage());
        }
        return false;
    }
    public Optional<User> findByDetailUser(String username, String password) {
        try {
            Optional<User> userOpt = userMapper.FindByUserDetail(username, password);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                user.setAuthorities(user.getAuthority());
                return Optional.of(user);
            } else {
                log.error("Failed to findByDetailUser:{}: {}", username);
                return Optional.empty();
            }
        } catch (Exception e) {
            log.error("DB:Error while finding user by Detailed: {}", e.getMessage());
        }
        return Optional.empty();
    }
}
