package com.example.vulnnotes.controller;

import com.example.vulnnotes.model.Note;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * WARNING: INTENTIONALLY VULNERABLE. DO NOT DEPLOY.
 */
@RestController
@RequestMapping("/api/notes")
public class NoteApiController {

    private final JdbcTemplate jdbc;

    public NoteApiController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // VULN (A01:2021 Broken Access Control - IDOR): no authentication and no ownership check.
    // Anyone can read any user's private note just by changing the id.
    @GetMapping("/{id}")
    public ResponseEntity<Note> getNote(@PathVariable long id) {
        List<Note> notes = jdbc.query(
                "SELECT id, owner_id, title, content FROM notes WHERE id = ?",
                (rs, i) -> new Note(rs.getLong("id"), rs.getLong("owner_id"),
                        rs.getString("title"), rs.getString("content")),
                id);
        return notes.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(notes.get(0));
    }
}
