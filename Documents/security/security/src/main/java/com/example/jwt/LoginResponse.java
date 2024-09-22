package com.example.jwt;

import javax.management.relation.Role;
import java.util.ArrayList;
import java.util.List;

public class LoginResponse {

    private String jwtToken;

    private String username;

    private List<String> role;

    public LoginResponse(String jwtToken, String username, List<String> role) {
        this.jwtToken = jwtToken;
        this.username = username;
        this.role = role;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRole() {
        return role;
    }

    public void setRole(List<String> role) {
        this.role = role;
    }
}
