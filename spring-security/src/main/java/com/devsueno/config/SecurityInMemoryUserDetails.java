package com.devsueno.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityInMemoryUserDetails {

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails sys = User.withUsername("sys").password("{noop}1111").roles("SYS").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER").build();
        return new InMemoryUserDetailsManager(user, sys, admin);
    }
}
