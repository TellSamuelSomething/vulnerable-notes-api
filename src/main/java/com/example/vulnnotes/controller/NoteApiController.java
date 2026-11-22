package com.example.vulnnotes.controller;

import com.example.vulnnotes.model.Note;
import com.example.vulnnotes.security.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/notes")
public class NoteApiController {

    private final JdbcTemplate jdbc;
    private final JwtUtil jwtUtil;

    public NoteApiController(JdbcTemplate jdbc, JwtUtil jwtUtil) {
        this.jdbc = jdbc;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Note> getNote(@PathVariable long id,
                                        @RequestHeader(value = "Authorization", required = false) String auth) {
        // FIXED (A01:2021 Broken Access Control): authentication required...
        Optional<Claims> claims = jwtUtil.fromAuthorizationHeader(auth);
        if (claims.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // ...and ownership enforced in the query itself. Someone else's note gives 404, not 403,
        // so attackers can't even learn which ids exist.
        List<Note> notes = jdbc.query(
                "SELECT n.id, n.owner_id, n.title, n.content FROM notes n "
                        + "JOIN users u ON u.id = n.owner_id WHERE n.id = ? AND u.username = ?",
                (rs, i) -> new Note(rs.getLong("id"), rs.getLong("owner_id"),
                        rs.getString("title"), rs.getString("content")),
                id, claims.get().getSubject());
        return notes.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(notes.get(0));
    }
}
