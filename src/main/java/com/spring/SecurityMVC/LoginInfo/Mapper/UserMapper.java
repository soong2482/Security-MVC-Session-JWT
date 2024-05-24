package com.spring.SecurityMVC.LoginInfo.Mapper;

import org.apache.ibatis.annotations.Mapper;
import com.spring.SecurityMVC.LoginInfo.Domain.User;

import java.util.Optional;


@Mapper
public interface UserMapper{
    Optional<String> FindById(String username);
    Optional<String> FindByPassword(String username);
    Optional<Boolean> FindByEnabled(String username);
    Optional<User> FindByUserDetail(String username,String password);
}
