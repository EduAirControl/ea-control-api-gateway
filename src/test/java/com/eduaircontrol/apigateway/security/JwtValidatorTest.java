package com.eduaircontrol.apigateway.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class JwtValidatorTest {

    private static KeyPair keyPair;
    private static JwtValidator validator;

    @BeforeAll
    static void setUp() {
        keyPair = TestTokens.generateKeyPair();
        validator = new JwtValidator(TestTokens.provider(keyPair), TestTokens.ISSUER, TestTokens.AUDIENCE);
    }

    @Test
    void validatesTokenAndExtractsPrincipal() {
        String token = TestTokens.token(keyPair, "user-1", "jti-1",
                List.of("ADMIN", "USER"), Instant.now().plusSeconds(600));

        JwtPrincipal principal = validator.validate(token).block();

        assertThat(principal.userId()).isEqualTo("user-1");
        assertThat(principal.role()).isEqualTo("ADMIN");
        assertThat(principal.jti()).isEqualTo("jti-1");
        assertThat(principal.expiresAt()).isAfter(Instant.now());
    }

    @Test
    void takesFirstRoleAsPrimaryRole() {
        String token = TestTokens.token(keyPair, "user-2", "jti-2",
                List.of("VIEWER", "ADMIN"), Instant.now().plusSeconds(600));

        assertThat(validator.validate(token).block().role()).isEqualTo("VIEWER");
    }

    @Test
    void rejectsExpiredToken() {
        String token = TestTokens.token(keyPair, "user-3", "jti-3",
                List.of("USER"), Instant.now().minusSeconds(60));

        assertThatThrownBy(() -> validator.validate(token).block())
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void rejectsTokenWithUnknownKid() {
        JwtValidator other = new JwtValidator(kid -> Mono.error(
                new UnauthorizedException("INVALID_TOKEN", "unknown kid")),
                TestTokens.ISSUER, TestTokens.AUDIENCE);
        String token = TestTokens.token(keyPair, "user-4", "jti-4",
                List.of("USER"), Instant.now().plusSeconds(600));

        assertThatThrownBy(() -> other.validate(token).block())
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void rejectsMalformedHeader() {
        assertThatThrownBy(() -> JwtValidator.readKid("not-a-jwt"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        KeyPair attacker = TestTokens.generateKeyPair();
        String token = TestTokens.token(attacker, "user-5", "jti-5",
                List.of("USER"), Instant.now().plusSeconds(600));

        assertThatThrownBy(() -> validator.validate(token).block())
                .isInstanceOf(UnauthorizedException.class);
    }

    /** Endurecimiento ADR-006: firma válida pero issuer ajeno → rechazado. */
    @Test
    void rejectsTokenWithWrongIssuer() {
        String token = Jwts.builder()
                .setSubject("user-6")
                .setId("jti-6")
                .claim("roles", List.of("USER"))
                .setIssuer("http://evil.example")
                .setAudience(TestTokens.AUDIENCE)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(600)))
                .setHeaderParam("kid", TestTokens.KID)
                .signWith((RSAPrivateKey) keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();

        assertThatThrownBy(() -> validator.validate(token).block())
                .isInstanceOf(UnauthorizedException.class);
    }
}
