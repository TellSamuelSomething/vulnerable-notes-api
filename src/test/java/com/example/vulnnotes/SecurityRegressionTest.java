package com.example.vulnnotes;

import com.example.vulnnotes.security.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security regression tests: every exploit from the README (written for the vulnerable `main`
 * branch) is replayed here and must FAIL on `secure`. If someone reintroduces a flaw, the build breaks.
 */
@SpringBootTest(properties = "app.jwt.secret=test-only-secret-that-is-at-least-32-bytes-long")
@AutoConfigureMockMvc
class SecurityRegressionTest {

    private static final String TEST_SECRET = "test-only-secret-that-is-at-least-32-bytes-long";
    /** The secret that was hard-coded on `main`; anyone who read the repo knows it. */
    private static final String LEAKED_MAIN_SECRET = "vuln-notes-hardcoded-secret-key!";

    @Autowired MockMvc mvc;
    @Autowired JwtUtil jwtUtil;
    @Autowired JdbcTemplate jdbc;

    private String loginJson(String username, String password) {
        return "{\"username\":\"" + username.replace("\"", "\\\"") + "\",\"password\":\""
                + password.replace("\"", "\\\"") + "\"}";
    }

    private String bearer(String username, String role) {
        return "Bearer " + jwtUtil.generateToken(username, role);
    }

    // ===== 1. SQL injection (A03)

    @Test
    void commentOutPasswordCheckIsRejected() throws Exception {
        mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("admin'--", "x")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tautologyIsRejected() throws Exception {
        mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("x", "' OR '1'='1")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unionSelectDoesNotLeakPasswords() throws Exception {
        mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("x", "' UNION SELECT 1, username || ':' || password, role "
                                + "FROM users WHERE username='admin")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void correctCredentialsStillWork() throws Exception {
        mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("alice", "alicepass")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
    }

    // ===== 2. Broken access control / IDOR (A01)

    @Test
    void noTokenIsRejected() throws Exception {
        mvc.perform(get("/api/notes/4")).andExpect(status().isUnauthorized());
    }

    @Test
    void otherUsersNoteIsNotFound() throws Exception {
        // alice asks for admin's note: 404, so she can't even tell that id 4 exists
        mvc.perform(get("/api/notes/4").header("Authorization", bearer("alice", "USER")))
                .andExpect(status().isNotFound());
    }

    @Test
    void ownNoteIsReadable() throws Exception {
        mvc.perform(get("/api/notes/1").header("Authorization", bearer("alice", "USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Alice private diary"));
    }

    @Test
    void notesPageRequiresLogin() throws Exception {
        mvc.perform(get("/notes")).andExpect(redirectedUrl("/login"));
    }

    @Test
    void h2ConsoleIsDisabled() throws Exception {
        mvc.perform(get("/h2-console")).andExpect(status().isNotFound());
    }

    // ===== 3. Stored XSS (A03)

    private static final String XSS_PAYLOAD = "<img src=x onerror=alert(1)>";

    private MockHttpSession loginOnPage() throws Exception {
        return (MockHttpSession) mvc.perform(post("/login")
                        .param("username", "bob").param("password", "bobpass"))
                .andExpect(redirectedUrl("/notes"))
                .andReturn().getRequest().getSession();
    }

    @Test
    void payloadIsEscapedOnOutput() throws Exception {
        MockHttpSession session = loginOnPage();
        mvc.perform(post("/notes").session(session)
                        .param("title", XSS_PAYLOAD).param("content", XSS_PAYLOAD)
                        .param("_csrf", (String) session.getAttribute("csrf")))
                .andExpect(redirectedUrl("/notes"));

        String html = mvc.perform(get("/notes").session(session))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(html).doesNotContain(XSS_PAYLOAD);
        assertThat(html).contains("&lt;img src=x onerror=alert(1)&gt;");
    }

    @Test
    void cspHeaderBlocksInlineScripts() throws Exception {
        mvc.perform(get("/login"))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")));
    }

    @Test
    void postWithoutCsrfTokenIsForbidden() throws Exception {
        MockHttpSession session = loginOnPage();
        mvc.perform(post("/notes").session(session).param("title", "t").param("content", "c"))
                .andExpect(status().isForbidden());
    }

    // ===== 4. Weak JWT (A02/A07)

    @Test
    void tokenSignedWithLeakedMainSecretIsRejected() throws Exception {
        String forged = Jwts.builder().subject("admin").claim("role", "ADMIN")
                .signWith(Keys.hmacShaKeyFor(LEAKED_MAIN_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokensHaveAnExpiry() {
        String token = jwtUtil.generateToken("alice", "USER");
        assertThat(jwtUtil.parse(token).getExpiration()).isNotNull();
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        JwtUtil alreadyExpired = new JwtUtil(TEST_SECRET, Duration.ofMinutes(-1));
        String token = alreadyExpired.generateToken("alice", "USER");
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shortSecretRefusesToStart() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> new JwtUtil("too-short", Duration.ofMinutes(15)));
    }

    // ===== 5. Plaintext passwords (A02)

    @Test
    void storedPasswordsAreBcryptHashes() {
        List<String> stored = jdbc.queryForList("SELECT password FROM users", String.class);
        assertThat(stored).isNotEmpty();
        assertThat(stored).allSatisfy(p -> assertThat(p).startsWith("$2a$"));
        assertThat(stored).doesNotContain("alicepass", "bobpass", "sup3rs3cr3t");
    }
}
