package com.example.vulnnotes.security;

import com.example.vulnnotes.model.User;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The single place that checks credentials, shared by the JSON API and the notes page. */
@Service
public class UserService {

    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<User> authenticate(String username, String password) {
        // FIXED (A03:2021 Injection): parameterized query; input is bound as data, never parsed as SQL.
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, username, password, role FROM users WHERE username = ?", username);

        // FIXED (A02:2021 Cryptographic Failures): compare against the stored BCrypt hash.
        if (rows.isEmpty() || !passwordEncoder.matches(password, (String) rows.get(0).get("PASSWORD"))) {
            return Optional.empty();
        }
        Map<String, Object> row = rows.get(0);
        return Optional.of(new User(((Number) row.get("ID")).longValue(),
                (String) row.get("USERNAME"), (String) row.get("ROLE")));
    }
}
