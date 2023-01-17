package com.devsueno.config.security.config;

import com.devsueno.config.security.filter.AjaxLoginProcessingFilter;
import com.devsueno.config.security.service.AjaxAccessDeniedHandler;
import com.devsueno.config.security.service.AjaxAuthentificationFailureHandler;
import com.devsueno.config.security.service.AjaxAuthentificationSuccessHandler;
import com.devsueno.config.security.service.AjaxLoginAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
public class AjaxSecurityConfig {

    @Bean
    public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {

        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .antMatchers("/api/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .accessDeniedHandler(new AjaxAccessDeniedHandler())
        ;
        http.csrf().disable();
        return http.build();
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(new ProviderManager(ajaxAuthenticationProvider()));
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(new AjaxAuthentificationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(new AjaxAuthentificationFailureHandler());
        return ajaxLoginProcessingFilter;
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }

}
