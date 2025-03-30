package dev.oliveira.jwt_security.dtos;

import java.util.List;

public class JwtResponse {

    private String Token;
    private String type = "Bearer";
    private String username;
    private List<String> roles;

    public JwtResponse(String token, String username, List<String> roles) {
        Token = token;
        this.username = username;
        this.roles = roles;
    }

    public String getToken() {
        return Token;
    }

    public String getType() {
        return type;
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }
}
