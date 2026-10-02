package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.dto.MessageResponse;
import com.hdfclife.capstoneone.dto.SignupRequest;
import com.hdfclife.capstoneone.exception.DuplicateUserException;
import com.hdfclife.capstoneone.model.AuditEvent;
import com.hdfclife.capstoneone.model.AuditEventType;
import com.hdfclife.capstoneone.logging.AuditEventLogger;
import com.hdfclife.capstoneone.entity.User;
import com.hdfclife.capstoneone.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Locale;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditEventLogger auditEventLogger;

    public MessageResponse register(SignupRequest request) {
        User user = createUser(request.getUsername(), request.getEmail(), request.getPassword(), "USER");

        auditEventLogger.log(AuditEvent.request(
                AuditEventType.USER_REGISTERED,
                null,
                user.getUsername(),
                "POST",
                "/signup",
                201,
                "Public signup completed"
        ));

        return new MessageResponse("Account created successfully");
    }

    public User createAdminManagedUser(String username, String email, String password, String role) {
        String normalizedRole = role == null ? "" : role.trim().toUpperCase(Locale.ROOT);

        if (!Set.of("USER", "ADMIN", "AUDITOR").contains(normalizedRole)) {
            throw new IllegalArgumentException("Role must be USER, ADMIN, or AUDITOR");
        }

        return createUser(username, email, password, normalizedRole);
    }

    private User createUser(String requestedUsername, String requestedEmail, String password, String role) {
        String username = requestedUsername.trim();
        String email = requestedEmail.trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByUsername(username)) {
            throw new DuplicateUserException("Username is already registered");
        }

        if (userRepository.existsByEmail(email)) {
            throw new DuplicateUserException("Email is already registered");
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setEnabled(true);
        user.setLocked(false);

        try {
            return userRepository.saveAndFlush(user);
        }
        catch (DataIntegrityViolationException exception) {
            throw new DuplicateUserException("Username or email is already registered");
        }
    }
}
