package com.example.vulnnotes.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * WARNING: INTENTIONALLY VULNERABLE. DO NOT DEPLOY.
 */
@Component
public class JwtUtil {

    // VULN (A02:2021 Cryptographic Failures / A07:2021 Identification and Authentication Failures):
    // hard-coded signing secret committed to source control. Anyone who reads the repo can forge tokens.
    private static final String SECRET = "vuln-notes-hardcoded-secret-key!";

    private final SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    public String generateToken(String username, String role) {
        // VULN (A07:2021 Identification and Authentication Failures):
        // no .expiration(...) set, so a stolen token is valid forever.
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(new Date())
                .signWith(key)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
