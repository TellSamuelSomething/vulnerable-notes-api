package com.example.vulnnotes.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * FIXED (A03:2021 Injection - XSS), defence in depth: even if some output escaping is missed,
 * the browser refuses to run inline scripts, event handlers or scripts from other origins.
 */
@Component
public class ContentSecurityPolicyFilter extends OncePerRequestFilter {

    private static final String POLICY = "default-src 'self'; script-src 'self'; object-src 'none'; "
            + "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader("Content-Security-Policy", POLICY);
        response.setHeader("X-Content-Type-Options", "nosniff");
        chain.doFilter(request, response);
    }

    /** The H2 console relies on inline scripts and frames, so the policy would break it. */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/h2-console");
    }
}
