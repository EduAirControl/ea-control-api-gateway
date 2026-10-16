package com.eduaircontrol.apigateway.security;

import java.util.List;
import org.springframework.http.HttpMethod;

/**
 * Endpoints que no requieren JWT. El resto del tráfico pasa por el filtro de
 * autenticación del gateway. Incluye el flujo de login del BFF (OAuth2/OIDC).
 */
public final class PublicPaths {

    private static final List<String> EXACT = List.of(
            "/health",
            "/api/v1/auth/health",
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/resend-code",
            "/api/v1/auth/verify-code",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/jwks");

    /** Flujo social: inicio, callbacks del proveedor y canje del codigo de un solo uso.
     *  El onboarding NO esta aqui: exige token (el usuario sale del JWT). */
    private static final List<String> SOCIAL = List.of(
            "/api/v1/auth/oauth2/google",
            "/api/v1/auth/oauth2/facebook",
            "/api/v1/auth/oauth2/google/callback",
            "/api/v1/auth/oauth2/facebook/callback",
            "/api/v1/auth/oauth2/social/exchange");

    private PublicPaths() {
    }

    public static boolean isPublic(HttpMethod method, String path) {
        if (HttpMethod.OPTIONS.equals(method)) {
            return true;
        }
        if (path.startsWith("/oauth2/") || path.startsWith("/login")) {
            return true;
        }
        return EXACT.contains(path) || SOCIAL.contains(path);
    }
}
