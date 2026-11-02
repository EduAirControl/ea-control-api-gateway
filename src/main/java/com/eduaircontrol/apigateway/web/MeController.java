package com.eduaircontrol.apigateway.web;

import com.eduaircontrol.apigateway.security.JwtPrincipal;
import com.eduaircontrol.apigateway.security.JwtValidator;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class MeController {

    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
    private final JwtValidator jwtValidator;

    @GetMapping("/api/v1/me")
    public Mono<ResponseEntity<Map<String, Object>>> me(ServerWebExchange exchange) {
        // 1) Flujo JWT (cookie httpOnly o Bearer): validar el token directamente.
        String token = resolveToken(exchange);
        if (token != null) {
            return jwtValidator.validate(token)
                    .map(this::toBody)
                    .map(ResponseEntity::ok)
                    .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
        }
        // 2) Flujo BFF OAuth2: token en sesión Redis.
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(authentication -> authentication instanceof OAuth2AuthenticationToken)
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(authentication -> authorizedClientService
                        .<OAuth2AuthorizedClient>loadAuthorizedClient(
                                authentication.getAuthorizedClientRegistrationId(), authentication.getName()))
                .flatMap(client -> jwtValidator.validate(client.getAccessToken().getTokenValue()))
                .map(this::toBody)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    private String resolveToken(ServerWebExchange exchange) {
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        org.springframework.http.HttpCookie cookie = exchange.getRequest().getCookies().getFirst("access_token");
        if (cookie != null && !cookie.getValue().isBlank()) {
            return cookie.getValue();
        }
        return null;
    }

    private Map<String, Object> toBody(com.eduaircontrol.apigateway.security.JwtPrincipal principal) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("userId", principal.userId());
        body.put("email", principal.email());
        body.put("role", principal.role());
        body.put("roles", principal.roles());
        body.put("institutionId", principal.institutionId());
        body.put("campusId", principal.campusId());
        return body;
    }
}
