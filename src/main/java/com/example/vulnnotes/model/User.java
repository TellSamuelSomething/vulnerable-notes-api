package com.example.vulnnotes.model;

import java.io.Serializable;

public record User(long id, String username, String role) implements Serializable {
}
