package com.spring.SecurityMVC.LoginInfo.Mapper;

import org.apache.ibatis.annotations.Mapper;
import com.spring.SecurityMVC.LoginInfo.Domain.User;


@Mapper
public interface UserMapper{
    String FindById(String username);
    User FindByPassword(String username);
}
