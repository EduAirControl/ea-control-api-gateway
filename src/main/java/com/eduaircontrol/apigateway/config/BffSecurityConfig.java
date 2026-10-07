package com.eduaircontrol.apigateway.config;

import java.net.URI;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import reactor.core.publisher.Mono;

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
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
            @Value("${app.bff.frontend-url:http://localhost:5173/}") String frontendUrl) {
        RedirectServerLogoutSuccessHandler logoutHandler = new RedirectServerLogoutSuccessHandler();
        logoutHandler.setLogoutSuccessUrl(URI.create(frontendUrl));
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .authenticationSuccessHandler(
                                new RedirectServerAuthenticationSuccessHandler(frontendUrl)))
                .logout(logout -> logout.logoutSuccessHandler(logoutHandler));
        return http.build();
    }

    /**
     * La identidad se obtiene del access token (en /api/v1/me); evitamos llamar al
     * endpoint /userinfo del AS construyendo el usuario desde el ID token.
     */
    @Bean
    ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return request -> {
            OidcIdToken idToken = request.getIdToken();
            return Mono.just(new DefaultOidcUser(List.of(), idToken, "sub"));
        };
    }
}
