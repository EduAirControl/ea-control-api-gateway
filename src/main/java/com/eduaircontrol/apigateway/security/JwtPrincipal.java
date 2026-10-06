package com.eduaircontrol.apigateway.security;

import java.time.Instant;

/**
 * Identidad extraída de un access token válido. El gateway la propaga a los
 * servicios internos mediante los headers X-User-Id y X-User-Role.
 */
public record JwtPrincipal(String userId, String role, String jti, Instant expiresAt) {
}
