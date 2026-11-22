package com.example.vulnnotes.controller;

import com.example.vulnnotes.security.JwtUtil;
import com.example.vulnnotes.security.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    /** FIXED (A03 SQLi, A02 plaintext passwords): see UserService.authenticate. */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        return userService.authenticate(body.getOrDefault("username", ""), body.getOrDefault("password", ""))
                .<ResponseEntity<Map<String, Object>>>map(user -> ResponseEntity.ok(Map.of(
                        "token", jwtUtil.generateToken(user.username(), user.role()),
                        "username", user.username(),
                        "role", user.role())))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "invalid credentials")));
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
