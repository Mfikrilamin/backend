package com.microservices.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {
    // @Bean
    // public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity
    // http) {

    // http
    // .authorizeExchange()
    // .anyExchange()
    // .authenticated()
    // .and()
    // .oauth2Login(); // to redirect to oauth2 login page.

    // return http.build();
    // }
}
