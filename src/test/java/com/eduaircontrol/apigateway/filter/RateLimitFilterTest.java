package com.eduaircontrol.apigateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.eduaircontrol.apigateway.config.AppProperties;
import com.eduaircontrol.apigateway.ratelimit.RedisStateStore;
import com.eduaircontrol.apigateway.security.JwtPrincipal;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

class RateLimitFilterTest {

    private RedisStateStore store;
    private RateLimitFilter filter;

    @BeforeEach
    void setUp() {
        store = mock(RedisStateStore.class);
        AppProperties properties = new AppProperties(
                new AppProperties.Jwt("http://localhost:8081/api/v1/auth/jwks",
                        "http://localhost:8081", "eduaircontrol-api"),
                new AppProperties.RateLimit(3, 60, List.of("/health"), List.of("127.0.0.1", "10.0.0.0/8")),
                Map.of());
        filter = new RateLimitFilter(store, properties);
    }

    @Test
    void blocksWhenLimitExceeded() {
        when(store.increment(anyString(), any(Duration.class))).thenReturn(Mono.just(4L));
        MockServerWebExchange exchange = exchange("/api/v1/sensors");

        filter.filter(exchange, chain()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("60");
    }

    @Test
    void allowsWhenUnderLimit() {
        when(store.increment(anyString(), any(Duration.class))).thenReturn(Mono.just(2L));
        AtomicBoolean called = new AtomicBoolean(false);

        filter.filter(exchange("/api/v1/sensors"), e -> {
            called.set(true);
            return Mono.empty();
        }).block();

        assertThat(called).isTrue();
    }

    @Test
    void exemptPathBypassesLimiter() {
        filter.filter(exchange("/health"), chain()).block();

        verify(store, never()).increment(anyString(), any(Duration.class));
    }

    @Test
    void keysByUserIdForAuthenticatedRequests() {
        when(store.increment(anyString(), any(Duration.class))).thenReturn(Mono.just(1L));
        AtomicReference<String> key = new AtomicReference<>();
        when(store.increment(anyString(), any(Duration.class))).thenAnswer(invocation -> {
            key.set(invocation.getArgument(0));
            return Mono.just(1L);
        });
        MockServerWebExchange exchange = exchange("/api/v1/sensors");
        exchange.getAttributes().put(JwtAuthenticationFilter.PRINCIPAL_ATTRIBUTE,
                new JwtPrincipal("user-9", "u@test.com", "USER", java.util.List.of("USER"), "jti", Instant.now(), "inst", "campus"));

        filter.filter(exchange, chain()).block();

        assertThat(key.get()).startsWith("rate:user:user-9:");
    }

    @Test
    void keysByIpForAnonymousRequests() {
        AtomicReference<String> key = new AtomicReference<>();
        when(store.increment(anyString(), any(Duration.class))).thenAnswer(invocation -> {
            key.set(invocation.getArgument(0));
            return Mono.just(1L);
        });

        filter.filter(exchange("/api/v1/auth/login"), chain()).block();

        assertThat(key.get()).startsWith("rate:ip:");
    }

    @Test
    void failsOpenWhenRedisUnavailable() {
        when(store.increment(anyString(), any(Duration.class)))
                .thenReturn(Mono.error(new IllegalStateException("redis down")));
        AtomicBoolean called = new AtomicBoolean(false);

        filter.filter(exchange("/api/v1/sensors"), e -> {
            called.set(true);
            return Mono.empty();
        }).block();

        assertThat(called).isTrue();
    }

    @Test
    void usesXForwardedForWhenTrustedProxy() {
        when(store.increment(anyString(), any(Duration.class))).thenReturn(Mono.just(1L));
        AtomicReference<String> key = new AtomicReference<>();
        when(store.increment(anyString(), any(Duration.class))).thenAnswer(invocation -> {
            key.set(invocation.getArgument(0));
            return Mono.just(1L);
        });

        // Request from trusted proxy (127.0.0.1) with XFF
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/sensors")
                        .header("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
                        .remoteAddress(new InetSocketAddress("127.0.0.1", 12345))
                        .build());

        filter.filter(exchange, chain()).block();

        assertThat(key.get()).startsWith("rate:ip:203.0.113.195:");
    }

    @Test
    void ignoresXForwardedForWhenUntrustedProxy() {
        when(store.increment(anyString(), any(Duration.class))).thenReturn(Mono.just(1L));
        AtomicReference<String> key = new AtomicReference<>();
        when(store.increment(anyString(), any(Duration.class))).thenAnswer(invocation -> {
            key.set(invocation.getArgument(0));
            return Mono.just(1L);
        });

        // Request from untrusted proxy (8.8.8.8) with XFF - should use remote IP
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/sensors")
                        .header("X-Forwarded-For", "203.0.113.195")
                        .remoteAddress(new InetSocketAddress("8.8.8.8", 12345))
                        .build());

        filter.filter(exchange, chain()).block();

        assertThat(key.get()).startsWith("rate:ip:8.8.8.8:");
    }

    private MockServerWebExchange exchange(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path).build());
    }

    private GatewayFilterChain chain() {
        return exchange -> Mono.empty();
    }
}
