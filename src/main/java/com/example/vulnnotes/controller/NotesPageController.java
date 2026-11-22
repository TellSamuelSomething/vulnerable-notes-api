package com.example.vulnnotes.controller;

import com.example.vulnnotes.model.Note;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * WARNING: INTENTIONALLY VULNERABLE. DO NOT DEPLOY.
 */
@Controller
public class NotesPageController {

    private final JdbcTemplate jdbc;

    public NotesPageController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/notes")
    public String list(Model model) {
        model.addAttribute("notes", jdbc.query(
                "SELECT id, owner_id, title, content FROM notes ORDER BY id",
                (rs, i) -> new Note(rs.getLong("id"), rs.getLong("owner_id"),
                        rs.getString("title"), rs.getString("content"))));
        return "notes";
    }

    // VULN (A03:2021 Injection - Stored XSS): title/content stored without validation or sanitising,
    // later rendered unescaped with th:utext in notes.html.
    @PostMapping("/notes")
    public String add(@RequestParam String title,
                      @RequestParam String content,
                      @RequestParam(defaultValue = "1") long ownerId) {
        jdbc.update("INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)", ownerId, title, content);
        return "redirect:/notes";
    }
}
