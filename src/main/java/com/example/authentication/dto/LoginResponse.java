package com.example.authentication.dto;

public class LoginResponse {

    private String message;
    private String token;
    private String username;

    public LoginResponse() {
    }

    public LoginResponse(String message, String token, String username) {
        this.message = message;
        this.token = token;
        this.username = username;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
