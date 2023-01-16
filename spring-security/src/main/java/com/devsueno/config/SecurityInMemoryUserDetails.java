package com.devsueno.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityInMemoryUserDetails {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        String password = passwordEncoder().encode("1111");
        UserDetails user = User.withUsername("user").password(password).roles("USER").build();
        UserDetails sys = User.withUsername("manager").password(password).roles("USER", "MANAGER").build();
        UserDetails admin = User.withUsername("admin").password(password).roles("USER", "MANAGER", "ADMIN").build();
        return new InMemoryUserDetailsManager(user, sys, admin);
    }
}
