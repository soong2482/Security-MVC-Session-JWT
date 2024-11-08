package com.spring.SecurityMVC.SpringSecurity;


import com.spring.SecurityMVC.SpringSecurity.CustomAuthenticationFilter.*;
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
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UtilSecurityService utilSecurityService;

    public SecurityConfig(UtilSecurityService utilSecurityService) {
        this.utilSecurityService = utilSecurityService;
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(UserDetailsService userDetailsService) {
        return new CustomAuthenticationProvider(userDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration, UserDetailsService userDetailsService) throws Exception {
        CustomAuthenticationProvider customAuthenticationProvider = customAuthenticationProvider(userDetailsService);
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
        CustomUserAuthenticationFilter filter = new CustomUserAuthenticationFilter(customSuccessHandler(), customFailedHandler(),utilSecurityService);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public CustomAdminAuthenticationFilter customAdminAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        CustomAdminAuthenticationFilter filter = new CustomAdminAuthenticationFilter(customSuccessHandler(), customFailedHandler(),utilSecurityService);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }


    @Bean
    public CustomSuperAdminAuthenticationFilter customSuperAdminAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        CustomSuperAdminAuthenticationFilter filter = new CustomSuperAdminAuthenticationFilter(customSuccessHandler(), customFailedHandler(),utilSecurityService);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }





    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CustomUserAuthenticationFilter customUserAuthenticationFilter,
                                                   CustomAdminAuthenticationFilter customAdminAuthenticationFilter,
                                                   CustomSuperAdminAuthenticationFilter customSuperAdminAuthenticationFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())

                .httpBasic(httpBasic -> httpBasic
                        .authenticationEntryPoint((request, response, authException) -> {
                            customFailedHandler().onAuthenticationFailure(request, response, authException);
                        })
                )
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Arrays.asList("http://localhost:3000")); // 허용할 도메인 설정
                    config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // 허용할 HTTP 메서드 설정
                    config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type")); // 허용할 헤더 설정
                    config.setAllowCredentials(true); // 자격 증명 허용
                    return config;
                }))
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/Security/Admin/**").hasRole("ADMIN")
                        .requestMatchers("/Security/SuperAdmin/**").hasRole("SUPER_ADMIN")
                        .requestMatchers("/Security/User/**").hasRole("USER")
                        .anyRequest().permitAll()
                )
                .formLogin(formLogin -> formLogin.disable())
                .sessionManagement(sessionManagement ->
                sessionManagement
                        .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::none) // 세션 고정 방지 정책을 'none'으로 설정하여 세션 갱신 방지
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요한 경우에만 세션 생성
        );

        // 커스텀 필터 추가
        http.addFilterBefore(customUserAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customAdminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customSuperAdminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
