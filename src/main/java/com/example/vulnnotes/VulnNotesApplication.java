package com.example.vulnnotes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * `secure` branch of a security-training project: the fixed version.
 * Every "// FIXED" comment marks where a deliberate flaw from `main` was repaired.
 */
@SpringBootApplication
public class VulnNotesApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnNotesApplication.class, args);
    }
}
