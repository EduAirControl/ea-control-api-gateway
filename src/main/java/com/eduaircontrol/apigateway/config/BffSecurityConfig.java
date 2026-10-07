package com.eduaircontrol.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * BFF (ADR-017): el gateway es un cliente OAuth2 con login por Authorization
 * Code + PKCE. La autorización fina de la API la aplica el filtro del gateway
 * (JWT en cabecera o token de la sesión), por eso las rutas quedan permitAll
 * a nivel de Spring Security y se delega en {@code JwtAuthenticationFilter}.
 */
@Configuration
@EnableWebFluxSecurity
public class BffSecurityConfig {

    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .oauth2Login(Customizer.withDefaults())
                .logout(Customizer.withDefaults());
        return http.build();
    }
}
