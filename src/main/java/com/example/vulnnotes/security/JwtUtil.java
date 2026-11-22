package com.example.vulnnotes.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Component
public class JwtUtil {

    private final SecretKey key;
    private final Duration ttl;

    // FIXED (A02:2021 Cryptographic Failures): the signing secret comes from the JWT_SECRET
    // environment variable, never from source control. The app refuses to start without it.
    public JwtUtil(@Value("${app.jwt.secret}") String secret,
                   @Value("${app.jwt.ttl:PT15M}") Duration ttl) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException("JWT_SECRET must be at least 32 bytes (256 bits)");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.ttl = ttl;
    }

    public String generateToken(String username, String role) {
        Instant now = Instant.now();
        // FIXED (A07:2021 Identification and Authentication Failures): tokens expire (default 15 min).
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(key)
                .compact();
    }

    /** Verifies signature and expiry; throws JwtException otherwise. */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Claims from an "Authorization: Bearer ..." header, or empty if missing, invalid or expired. */
    public Optional<Claims> fromAuthorizationHeader(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            return Optional.empty();
        }
        try {
            return Optional.of(parse(header.substring(7)));
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
