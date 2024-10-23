package com.spring.SecurityMVC.UserInfo.Mapper;

import org.apache.ibatis.annotations.Mapper;
import com.spring.SecurityMVC.UserInfo.Domain.User;

import java.util.List;
import java.util.Optional;
import com.spring.SecurityMVC.SignUpInfo.Domain.SignUp;

import javax.swing.text.html.Option;

@Mapper
public interface UserMapper{
    Optional<String> FindById(String username);
    Optional<String> FindByPassword(String username);
    Optional<Boolean> FindByEnabled(String username);
    Optional<User> FindByUserDetail(String username);
    Optional<String> FindByEmail(String email);
    void insertAuthority(SignUp signUp);
    void insertUser(SignUp signUp);
    List<String> FindByRoles(String username);
    Optional<String> getUserIP(String username);
    void UpdateIP(String username,String ip);
}
