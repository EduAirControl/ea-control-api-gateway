package com.eduaircontrol.apigateway.filter;

import com.eduaircontrol.apigateway.ratelimit.RedisStateStore;
import com.eduaircontrol.apigateway.security.JwtPrincipal;
import com.eduaircontrol.apigateway.security.JwtValidator;
import com.eduaircontrol.apigateway.security.PublicPaths;
import com.eduaircontrol.apigateway.security.UnauthorizedException;
import com.eduaircontrol.apigateway.support.ErrorWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Verifica el JWT (firma RS256 + expiración + blacklist) en el borde y
 * propaga la identidad como headers internos X-User-Id / X-User-Role.
 * La autorización fina queda en cada servicio (ADR-006).
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    public static final String PRINCIPAL_ATTRIBUTE = "jwtPrincipal";
    private static final String BEARER = "Bearer ";

    private final JwtValidator jwtValidator;
    private final RedisStateStore stateStore;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpMethod method = exchange.getRequest().getMethod();
        String path = exchange.getRequest().getPath().value();
        if (PublicPaths.isPublic(method, path)) {
            return chain.filter(exchange);
        }
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER)) {
            return ErrorWriter.write(exchange.getResponse(), HttpStatus.UNAUTHORIZED,
                    "MISSING_TOKEN", "Authorization bearer token is required");
        }
        String token = header.substring(BEARER.length());
        return Mono.defer(() -> jwtValidator.validate(token))
                .flatMap(principal -> stateStore.isBlacklisted(principal.jti())
                        .flatMap(blacklisted -> blacklisted
                                ? ErrorWriter.write(exchange.getResponse(), HttpStatus.UNAUTHORIZED,
                                        "TOKEN_REVOKED", "Token has been revoked")
                                : forward(exchange, chain, principal)))
                .onErrorResume(UnauthorizedException.class, error ->
                        ErrorWriter.write(exchange.getResponse(), HttpStatus.UNAUTHORIZED,
                                error.getCode(), error.getMessage()))
                .onErrorResume(error -> ErrorWriter.write(exchange.getResponse(), HttpStatus.UNAUTHORIZED,
                        "INVALID_TOKEN", "Invalid or expired token"));
    }

    private Mono<Void> forward(ServerWebExchange exchange, GatewayFilterChain chain, JwtPrincipal principal) {
        exchange.getAttributes().put(PRINCIPAL_ATTRIBUTE, principal);
        ServerHttpRequest request = exchange.getRequest().mutate()
                .header("X-User-Id", principal.userId() == null ? "" : principal.userId())
                .header("X-User-Role", principal.role() == null ? "" : principal.role())
                .header("X-Institution-Id", principal.institutionId() == null ? "" : principal.institutionId())
                .header("X-Campus-Id", principal.campusId() == null ? "" : principal.campusId())
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    @Override
    public int getOrder() {
        return -90;
    }
}
