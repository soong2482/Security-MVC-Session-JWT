package com.spring.SecurityMVC.SpringSecurity;

import com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter.CustomAdminAuthenticationFilter;
import com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter.CustomSuperAdminAuthenticationFilter;
import com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter.CustomUserAuthenticationFilter;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomSuccessHandler;
import com.spring.SecurityMVC.UserInfo.Service.UserDetailsService;
import com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationProvider.CustomAuthenticationProvider;
import com.spring.SecurityMVC.SpringSecurity.CustomHandler.CustomFailedHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(UserDetailsService userDetailsService) {
        return new CustomAuthenticationProvider(userDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration, CustomAuthenticationProvider customAuthenticationProvider) throws Exception {
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(customAuthenticationProvider);
        return authenticationManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CustomSuccessHandler customSuccessHandler() {
        return new CustomSuccessHandler();
    }

    @Bean
    public CustomFailedHandler customFailedHandler() {
        return new CustomFailedHandler();
    }

    @Bean
    public CustomUserAuthenticationFilter customUserAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        CustomUserAuthenticationFilter filter = new CustomUserAuthenticationFilter(customSuccessHandler(), customFailedHandler());
        filter.setAuthenticationManager(authenticationManager(null, customAuthenticationProvider(null)));
        return filter;
    }
    @Bean
    public CustomAdminAuthenticationFilter customAdminAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        CustomAdminAuthenticationFilter filter = new CustomAdminAuthenticationFilter(customSuccessHandler(), customFailedHandler());
        filter.setAuthenticationManager(authenticationManager(null, customAuthenticationProvider(null)));
        return filter;
    }


    @Bean
    public CustomSuperAdminAuthenticationFilter customSuperAdminAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        CustomSuperAdminAuthenticationFilter filter = new CustomSuperAdminAuthenticationFilter(customSuccessHandler(), customFailedHandler());
        filter.setAuthenticationManager(authenticationManager(null, customAuthenticationProvider(null)));
        return filter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,CustomUserAuthenticationFilter customUserAuthenticationFilter, CustomAdminAuthenticationFilter customAdminAuthenticationFilter, CustomSuperAdminAuthenticationFilter customSuperAdminAuthenticationFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .httpBasic(httpBasic -> httpBasic
                        .authenticationEntryPoint((request, response, authException) -> {
                            customFailedHandler().onAuthenticationFailure(request, response, authException);
                        })
                )
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().permitAll()
                )
                .formLogin(formLogin -> formLogin.disable());
        http.addFilterBefore(customUserAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customAdminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customSuperAdminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
