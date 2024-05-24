package com.spring.SecurityMVC.LoginInfo.Service;

import com.spring.SecurityMVC.LoginInfo.Domain.LoginRequest;
import com.spring.SecurityMVC.LoginInfo.Mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;


@Service
public class LoginService {
    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public LoginService(AuthenticationManager authenticationManager, UserMapper userMapper) {
        this.authenticationManager = authenticationManager;
        this.userMapper = userMapper;
    }

    public void Login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
        if (loginRequest == null) {
            HttpSession session = request.getSession(false);
            if (session != null && session.getAttribute("username")!= null) {
                String username = (String) session.getAttribute("username");
                userMapper.FindByPassword(username);
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } else {
            Authentication authenticationRequest =
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
            Authentication authenticationResponse =
                    this.authenticationManager.authenticate(authenticationRequest);
            SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            session.setMaxInactiveInterval(10);
        }
    }
    public void Logout(HttpServletRequest request,HttpServletResponse response){
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        else{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
