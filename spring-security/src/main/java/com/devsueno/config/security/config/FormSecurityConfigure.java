package com.devsueno.config.security.config;

import com.devsueno.config.security.service.CustomAccessDeniedHandler;
import com.devsueno.config.security.service.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

@Configuration
@Order(1)
public class FormSecurityConfigure extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    private AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    public void init(HttpSecurity http) throws Exception {
        http
                .authorizeRequests((authz) ->
                    authz.antMatchers("/", "/users", "user/login/**", "/login*")
                            .permitAll()
                            .antMatchers("/mypage").hasRole("USER")
                            .antMatchers("/messages").hasRole("MANAGER")
                            .antMatchers("/config").hasRole("ADMIN")
                            .anyRequest()
                            .authenticated()
                )
                .authenticationManager(authenticationManager())
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                ;
    }

    public AuthenticationManager authenticationManager() {
        return new ProviderManager(authenticationProvider());
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

}
