package com.example.authentication.service;

import com.example.authentication.dto.RegisterRequest;
import com.example.authentication.dto.UserResponse;
import com.example.authentication.entity.User;
import com.example.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User registerUser(RegisterRequest registerRequest) {
        // 1. Validate required fields
        if (registerRequest.getUsername() == null || registerRequest.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (registerRequest.getEmail() == null || registerRequest.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email is required");
        }
        if (registerRequest.getPhone() == null || registerRequest.getPhone().trim().isEmpty()) {
            throw new IllegalArgumentException("Phone number is required");
        }
        if (registerRequest.getPassword() == null || registerRequest.getPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }

        // 2. Confirm password match
        if (!registerRequest.getPassword().equals(registerRequest.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        // 3. Basic format checks
        if (!registerRequest.getEmail().matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new IllegalArgumentException("Invalid email format");
        }
        if (!registerRequest.getPhone().matches("^[0-9+\\-\\s()]{7,15}$")) {
            throw new IllegalArgumentException("Invalid phone number format");
        }

        // 4. Unique checks
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new IllegalStateException("Username already exists");
        }
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new IllegalStateException("Email already registered");
        }
        if (userRepository.existsByPhone(registerRequest.getPhone())) {
            throw new IllegalStateException("Phone number already registered");
        }

        // 5. Hash password using BCrypt
        String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());

        // 6. Save user
        User user = new User(
                registerRequest.getUsername().trim(),
                encodedPassword,
                registerRequest.getEmail().trim().toLowerCase(),
                registerRequest.getPhone().trim()
        );

        return userRepository.save(user);
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));
    }

    public UserResponse getUserProfile(String username) {
        User user = getUserByUsername(username);
        return new UserResponse(user.getUserId(), user.getUsername(), user.getEmail(), user.getPhone());
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }
}
