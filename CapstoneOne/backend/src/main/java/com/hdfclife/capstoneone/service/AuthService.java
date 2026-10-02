package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.dto.AuthResponse;
import com.hdfclife.capstoneone.dto.LoginRequest;
import com.hdfclife.capstoneone.dto.MessageResponse;
import com.hdfclife.capstoneone.exception.InactiveTokenException;
import com.hdfclife.capstoneone.exception.InvalidCredentialsException;
import com.hdfclife.capstoneone.exception.InvalidTokenException;
import com.hdfclife.capstoneone.model.AuditEvent;
import com.hdfclife.capstoneone.model.AuditEventType;
import com.hdfclife.capstoneone.logging.AuditEventLogger;
import com.hdfclife.capstoneone.dto.IssuedTokens;
import com.hdfclife.capstoneone.entity.User;
import com.hdfclife.capstoneone.repository.UserRepository;
import com.hdfclife.capstoneone.util.Sha256;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginRateLimitService loginRateLimitService;
    private final AuditEventLogger auditEventLogger;

    public IssuedTokens login(LoginRequest request, String clientIp) {
        return loginRateLimitService.execute(
                request.getUsername(),
                clientIp,
                () -> authenticate(request));
    }

    private IssuedTokens authenticate(LoginRequest request) {
        String username = request.getUsername().trim();
        String password = request.getPassword();

        User user = userRepository.findByUsername(username)
                .filter(existingUser -> existingUser.isEnabled() && !existingUser.isLocked())
                .orElseThrow(() -> new InvalidCredentialsException("Incorrect username or password"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidCredentialsException("Incorrect username or password");
        }

        UUID sessionId = UUID.randomUUID();
        String token = jwtService.generateToken(user.getUsername(), sessionId);
        String refreshToken = jwtService.generateRefreshToken(user.getUsername(), sessionId);

        tokenService.saveSession(
                sessionId,
                user.getUsername(),
                jwtService.extractTokenId(token),
                Sha256.hash(refreshToken),
                jwtService.extractExpiration(token).toInstant(),
                jwtService.extractExpiration(refreshToken).toInstant()
        );

        auditEventLogger.log(
                AuditEvent.authentication(
                        AuditEventType.LOGIN_SUCCESS,
                        user.getUsername(),
                        "User login successful")
        );

        return new IssuedTokens(token, refreshToken);
    }

    public AuthResponse validateToken(String token) {
        jwtService.isTokenValid(token);

        String username = jwtService.extractUsername(token);
        auditEventLogger.log(AuditEvent.authentication(
                AuditEventType.TOKEN_VALIDATION_SUCCESS, username, "Token validation successful"));

        return new AuthResponse("Authentication successful", username, true);
    }

    public IssuedTokens refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh token must not be empty");
        }

        jwtService.isTokenValid(refreshToken);

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new InvalidTokenException("Token is not a refresh token");
        }

        UUID sessionId = jwtService.extractSessionId(refreshToken);
        String username = jwtService.extractUsername(refreshToken);
        String newAccessToken = jwtService.generateToken(username, sessionId);
        String newRefreshToken = jwtService.generateRefreshToken(username, sessionId);

        boolean rotated = tokenService.rotateTokens(
                sessionId,
                Sha256.hash(refreshToken),
                jwtService.extractTokenId(newAccessToken),
                jwtService.extractExpiration(newAccessToken).toInstant(),
                Sha256.hash(newRefreshToken),
                jwtService.extractExpiration(newRefreshToken).toInstant()
        );

        if (!rotated) {
            throw new InactiveTokenException("Refresh token is inactive. Please login again.");
        }

        auditEventLogger.log(AuditEvent.authentication(
                AuditEventType.TOKEN_REFRESH_SUCCESS, username, "Access token refreshed successfully"));

        return new IssuedTokens(newAccessToken, newRefreshToken);
    }

    public MessageResponse logout(String token) {
        String username = jwtService.extractUsername(token);

        if (!tokenService.revokeSession(
                jwtService.extractSessionId(token),
                jwtService.extractTokenId(token)
        )) {
            throw new InactiveTokenException("Token is already inactive");
        }
        auditEventLogger.log(AuditEvent.authentication(
                AuditEventType.LOGOUT_SUCCESS, username, "User logout successful"));

        return new MessageResponse("Logged out successfully");
    }
}
