package com.example.vulnnotes.controller;

import com.example.vulnnotes.model.Note;
import com.example.vulnnotes.model.User;
import com.example.vulnnotes.security.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * The notes page. Identity comes only from the server-side session, never from a request parameter.
 */
@Controller
public class NotesPageController {

    private static final String USER = "user";
    private static final String CSRF = "csrf";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbc;
    private final UserService userService;

    public NotesPageController(JdbcTemplate jdbc, UserService userService) {
        this.jdbc = jdbc;
        this.userService = userService;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/notes";
    }

    @GetMapping("/login")
    public String loginForm() {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpServletRequest request, Model model) {
        var user = userService.authenticate(username, password);
        if (user.isEmpty()) {
            model.addAttribute("error", true);
            return "login";
        }
        // New session id on login prevents session fixation.
        HttpSession session = request.getSession(true);
        request.changeSessionId();
        session.setAttribute(USER, user.get());
        byte[] token = new byte[32];
        RANDOM.nextBytes(token);
        session.setAttribute(CSRF, Base64.getUrlEncoder().withoutPadding().encodeToString(token));
        return "redirect:/notes";
    }

    @PostMapping("/logout")
    public String logout(@RequestParam(name = "_csrf", required = false) String csrf, HttpSession session) {
        requireCsrf(session, csrf);
        session.invalidate();
        return "redirect:/login";
    }

    // FIXED (A01:2021 Broken Access Control): login required, and only the user's own notes are listed.
    @GetMapping("/notes")
    public String list(HttpSession session, Model model) {
        User user = (User) session.getAttribute(USER);
        if (user == null) {
            return "redirect:/login";
        }
        model.addAttribute("user", user);
        model.addAttribute("csrf", session.getAttribute(CSRF));
        model.addAttribute("notes", jdbc.query(
                "SELECT id, owner_id, title, content FROM notes WHERE owner_id = ? ORDER BY id",
                (rs, i) -> new Note(rs.getLong("id"), rs.getLong("owner_id"),
                        rs.getString("title"), rs.getString("content")),
                user.id()));
        return "notes";
    }

    // FIXED (A01:2021 Broken Access Control): the owner is the logged-in user, not a form field,
    // and a CSRF token stops other sites from posting notes through the user's session.
    // FIXED (A03:2021 Injection - XSS): input is stored as-is, but notes.html escapes it on output
    // (th:text) and the CSP header blocks inline scripts.
    @PostMapping("/notes")
    public String add(@RequestParam String title, @RequestParam String content,
                      @RequestParam(name = "_csrf", required = false) String csrf, HttpSession session) {
        User user = (User) session.getAttribute(USER);
        if (user == null) {
            return "redirect:/login";
        }
        requireCsrf(session, csrf);
        jdbc.update("INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)", user.id(), title, content);
        return "redirect:/notes";
    }

    private static void requireCsrf(HttpSession session, String submitted) {
        Object expected = session.getAttribute(CSRF);
        if (expected == null || submitted == null
                || !MessageDigest.isEqual(expected.toString().getBytes(), submitted.getBytes())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "invalid CSRF token");
        }
    }
}
