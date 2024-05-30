package com.spring.SecurityMVC.UserInfo.Service;

import com.spring.SecurityMVC.UserInfo.Domain.User;
import com.spring.SecurityMVC.UserInfo.Mapper.UserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class UserDetailsService {
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    public UserDetailsService(UserMapper userMapper, PasswordEncoder passwordEncoder) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean findById(String username) {
        try {
            if (userMapper.FindById(username).isPresent()) {
                return true;
            } else {
                log.error("User not found to FindById:{}", username);
                return false;
            }
        } catch (Exception e) {
            log.error("DB:Error while finding user by id: {}", e.getMessage());
            return false;
        }
    }

    public boolean findByPassword(String username, String password) {
        try {
            Optional<String> PasswordOpt = userMapper.FindByPassword(username);
            if (PasswordOpt.isPresent()) {
                if (passwordEncoder.matches(password,PasswordOpt.get())) {
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
                    return false;
                }
            }
        }catch(Exception e){
            log.error("DB:Error while finding user by Enabled: {}",e.getMessage());
        }
        return false;
    }
    public Optional<User> findByDetailUser(String username) {
        try {
            Optional<User> userOpt = userMapper.FindByUserDetail(username);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                List<String> roles = userMapper.FindByRoles(username);
                Optional<List<String>> userRoles = Optional.ofNullable(roles);
                userRoles.ifPresent(user::setAuthorities);
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
    public boolean findByEmail(String email){
      try{
          if (userMapper.FindByEmail(email).isPresent()) {
              return true;
          } else {
              log.error("User not found to FindByEmail:{}", email);
              return false;
          }
      }catch(Exception e){
          log.error("DB:Error while finding user by Email: {}", e.getMessage());
      }
        return false;
    }
}
