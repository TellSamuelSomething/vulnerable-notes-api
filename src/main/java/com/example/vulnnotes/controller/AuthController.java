package com.example.vulnnotes.controller;

import com.example.vulnnotes.security.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * WARNING: INTENTIONALLY VULNERABLE. DO NOT DEPLOY.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final JdbcTemplate jdbc;
    private final JwtUtil jwtUtil;

    public AuthController(JdbcTemplate jdbc, JwtUtil jwtUtil) {
        this.jdbc = jdbc;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        // VULN (A03:2021 Injection - SQL injection): user input concatenated straight into SQL.
        // password = ' OR '1'='1   or   username = admin'--   bypasses authentication.
        // VULN (A02:2021 Cryptographic Failures): compares against a cleartext password column.
        String sql = "SELECT id, username, role FROM users WHERE username = '" + username
                + "' AND password = '" + password + "'";

        List<Map<String, Object>> rows = jdbc.queryForList(sql);
        if (rows.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid credentials"));
        }

        Map<String, Object> user = rows.get(0);
        String token = jwtUtil.generateToken((String) user.get("USERNAME"), (String) user.get("ROLE"));
        return ResponseEntity.ok(Map.of(
                "token", token,
                "username", user.get("USERNAME"),
                "role", user.get("ROLE")));
    }

    /** Returns the identity in the presented JWT; used to demonstrate forged tokens being accepted. */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(@RequestHeader(value = "Authorization", required = false) String auth) {
        if (auth == null || !auth.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "missing bearer token"));
        }
        try {
            Claims claims = jwtUtil.parse(auth.substring(7));
            return ResponseEntity.ok(Map.of(
                    "username", claims.getSubject(),
                    "role", String.valueOf(claims.get("role")),
                    "expires", String.valueOf(claims.getExpiration())));
        } catch (JwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid token"));
        }
    }
}
