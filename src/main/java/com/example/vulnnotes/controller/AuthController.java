package com.example.vulnnotes.controller;

import com.example.vulnnotes.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final JdbcTemplate jdbc;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthController(JdbcTemplate jdbc, JwtUtil jwtUtil) {
        this.jdbc = jdbc;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        // FIXED (A03:2021 Injection): parameterized query; input is bound as data, never parsed as SQL.
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT username, password, role FROM users WHERE username = ?", username);

        // FIXED (A02:2021 Cryptographic Failures): compare against the stored BCrypt hash.
        if (rows.isEmpty() || !passwordEncoder.matches(password, (String) rows.get(0).get("PASSWORD"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid credentials"));
        }

        Map<String, Object> user = rows.get(0);
        String token = jwtUtil.generateToken((String) user.get("USERNAME"), (String) user.get("ROLE"));
        return ResponseEntity.ok(Map.of(
                "token", token,
                "username", user.get("USERNAME"),
                "role", user.get("ROLE")));
    }

    /** Returns the identity in the presented JWT; forged or expired tokens are rejected. */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(@RequestHeader(value = "Authorization", required = false) String auth) {
        return jwtUtil.fromAuthorizationHeader(auth)
                .<ResponseEntity<Map<String, Object>>>map(claims -> ResponseEntity.ok(Map.of(
                        "username", claims.getSubject(),
                        "role", String.valueOf(claims.get("role")),
                        "expires", String.valueOf(claims.getExpiration()))))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "missing, invalid or expired token")));
    }
}
