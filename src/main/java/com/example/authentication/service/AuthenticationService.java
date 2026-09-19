package com.example.authentication.service;

import com.example.authentication.dto.LoginRequest;
import com.example.authentication.dto.LoginResponse;
import com.example.authentication.entity.JwtToken;
import com.example.authentication.entity.User;
import com.example.authentication.repository.JwtTokenRepository;
import com.example.authentication.repository.UserRepository;
import com.example.authentication.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final JwtTokenRepository jwtTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthenticationService(UserRepository userRepository,
                                 JwtTokenRepository jwtTokenRepository,
                                 JwtService jwtService,
                                 PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtTokenRepository = jwtTokenRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        if (loginRequest.getUsername() == null || loginRequest.getUsername().trim().isEmpty() ||
            loginRequest.getPassword() == null || loginRequest.getPassword().trim().isEmpty()) {
            throw new BadCredentialsException("Invalid username or password");
        }

        // 1. Find user by username
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));

        // 2. Verify password against BCrypt hash
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        // 3. Generate JWT Token
        String token = jwtService.generateToken(user.getUsername(), user.getUserId());

        // 4. Extract expiration and store in jwt_tokens database table
        Date expirationDate = jwtService.getExpirationDate(token);
        LocalDateTime expiresAt = expirationDate.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        JwtToken jwtTokenEntity = new JwtToken(user, token, expiresAt);
        jwtTokenRepository.save(jwtTokenEntity);

        return new LoginResponse("Login successful", token, user.getUsername());
    }

    @Transactional
    public void logout(String authHeader) {
        String token = extractTokenFromHeader(authHeader);
        if (token != null) {
            Optional<JwtToken> tokenOpt = jwtTokenRepository.findByToken(token);
            tokenOpt.ifPresent(jwtTokenRepository::delete);
        }
    }

    public boolean isTokenValidAndActive(String token) {
        if (token == null || jwtService.isTokenExpired(token)) {
            return false;
        }

        Optional<JwtToken> tokenOpt = jwtTokenRepository.findByToken(token);
        if (tokenOpt.isEmpty()) {
            return false;
        }

        JwtToken dbToken = tokenOpt.get();
        return dbToken.getExpiresAt().isAfter(LocalDateTime.now());
    }

    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
