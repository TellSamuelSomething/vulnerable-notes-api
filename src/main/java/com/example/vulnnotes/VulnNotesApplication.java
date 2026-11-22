package com.example.vulnnotes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * WARNING: INTENTIONALLY VULNERABLE SECURITY-TRAINING PROJECT. DO NOT DEPLOY.
 * Every "// VULN" comment marks a deliberate flaw for learning purposes.
 */
@SpringBootApplication
public class VulnNotesApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnNotesApplication.class, args);
    }
}
