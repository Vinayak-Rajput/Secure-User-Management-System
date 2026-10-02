package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.dto.LoginRequest;
import com.hdfclife.capstoneone.exception.InactiveTokenException;
import com.hdfclife.capstoneone.exception.InvalidCredentialsException;
import com.hdfclife.capstoneone.exception.InvalidTokenException;
import com.hdfclife.capstoneone.logging.AuditEventLogger;
import com.hdfclife.capstoneone.config.RateLimitProperties;
import com.hdfclife.capstoneone.entity.User;
import com.hdfclife.capstoneone.repository.UserRepository;
import com.hdfclife.capstoneone.security.LocalRateLimiterPool;
import com.hdfclife.capstoneone.util.Sha256;
import com.hdfclife.capstoneone.util.Sha256Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private JwtService jwtService;
    @Mock private TokenService tokenService;
    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuditEventLogger auditEventLogger;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        LoginRateLimitService rateLimitService = new LoginRateLimitService(
                new RateLimitProperties(Map.of(
                        "loginAccount", new RateLimitProperties.LimiterSettings(20, Duration.ofMinutes(1), Duration.ZERO),
                        "loginClientIp", new RateLimitProperties.LimiterSettings(20, Duration.ofMinutes(1), Duration.ZERO)
                )),
                new LocalRateLimiterPool());
        authService = new AuthService(jwtService, tokenService, userRepository, passwordEncoder, rateLimitService, auditEventLogger);
    }

    @Test
    void loginRejectsUnknownUsernameWithoutCreatingSession() {
        when(userRepository.findByUsername("missing")).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest("missing", "password"), "192.0.2.10"));

        verify(passwordEncoder, never()).matches(any(), any());
        verify(tokenService, never()).saveSession(any(), any(), any(), any(), any(), any());
    }

    @Test
    void validateTokenReturnsAuthenticatedIdentity() {
        when(jwtService.isTokenValid("access-token")).thenReturn(true);
        when(jwtService.extractUsername("access-token")).thenReturn("alice");

        var response = authService.validateToken("access-token");

        assertEquals("alice", response.getUsername());
        assertTrue(response.isAuthenticated());
    }

    @Test
    void loginCreatesSessionWithTokenIdAndRefreshHash() {
        User user = user("alice", true, false);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct horse", "stored-hash")).thenReturn(true);
        when(jwtService.generateToken(eq("alice"), any(UUID.class))).thenReturn("access-token");
        when(jwtService.generateRefreshToken(eq("alice"), any(UUID.class))).thenReturn("refresh-token");
        when(jwtService.extractTokenId("access-token")).thenReturn("access-id");
        Date accessExpiryDate = Date.from(Instant.now().plusSeconds(60));
        Date refreshExpiryDate = Date.from(Instant.now().plusSeconds(600));
        Instant accessExpiry = accessExpiryDate.toInstant();
        Instant refreshExpiry = refreshExpiryDate.toInstant();
        when(jwtService.extractExpiration("access-token")).thenReturn(accessExpiryDate);
        when(jwtService.extractExpiration("refresh-token")).thenReturn(refreshExpiryDate);

        var response = authService.login(new LoginRequest(" alice ", "correct horse"), "192.0.2.10");

        assertEquals("access-token", response.accessToken());
        assertEquals("refresh-token", response.refreshToken());
        ArgumentCaptor<UUID> sessionId = ArgumentCaptor.forClass(UUID.class);
        verify(tokenService).saveSession(
                sessionId.capture(), eq("alice"), eq("access-id"),
                eq(Sha256.hash("refresh-token")), eq(accessExpiry), eq(refreshExpiry));
        assertTrue(sessionId.getValue() != null);
        verify(jwtService).generateToken("alice", sessionId.getValue());
        verify(jwtService).generateRefreshToken("alice", sessionId.getValue());
    }

    @Test
    void loginRejectsWrongPasswordWithoutCreatingSession() {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user("alice", true, false)));
        when(passwordEncoder.matches("wrong", "stored-hash")).thenReturn(false);

        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest("alice", "wrong"), "192.0.2.10"));

        verify(tokenService, never()).saveSession(any(), any(), any(), any(), any(), any());
    }

    @Test
    void loginRejectsDisabledOrLockedAccountsAsInvalidCredentials() {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user("alice", false, false)));

        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest("alice", "password"), "192.0.2.10"));

        verify(passwordEncoder, never()).matches(any(), any());
        verify(tokenService, never()).saveSession(any(), any(), any(), any(), any(), any());
    }

    @Test
    void loginRejectsLockedAccountWithoutCheckingPassword() {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user("alice", true, true)));

        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest("alice", "password"), "192.0.2.10"));

        verify(passwordEncoder, never()).matches(any(), any());
        verify(tokenService, never()).saveSession(any(), any(), any(), any(), any(), any());
    }

    @Test
    void refreshRotatesSessionUsingPresentedTokenHash() {
        UUID sessionId = UUID.randomUUID();
        Date accessExpiryDate = Date.from(Instant.now().plusSeconds(60));
        Date refreshExpiryDate = Date.from(Instant.now().plusSeconds(600));
        Instant accessExpiry = accessExpiryDate.toInstant();
        Instant refreshExpiry = refreshExpiryDate.toInstant();
        when(jwtService.isRefreshToken("old-refresh")).thenReturn(true);
        when(jwtService.extractSessionId("old-refresh")).thenReturn(sessionId);
        when(jwtService.extractUsername("old-refresh")).thenReturn("alice");
        when(jwtService.generateToken("alice", sessionId)).thenReturn("new-access");
        when(jwtService.generateRefreshToken("alice", sessionId)).thenReturn("new-refresh");
        when(jwtService.extractTokenId("new-access")).thenReturn("new-access-id");
        when(jwtService.extractExpiration("new-access")).thenReturn(accessExpiryDate);
        when(jwtService.extractExpiration("new-refresh")).thenReturn(refreshExpiryDate);
        when(tokenService.rotateTokens(eq(sessionId), eq(Sha256.hash("old-refresh")), eq("new-access-id"),
                eq(accessExpiry), eq(Sha256.hash("new-refresh")), eq(refreshExpiry))).thenReturn(true);

        var response = authService.refresh("old-refresh");

        assertEquals("new-access", response.accessToken());
        assertEquals("new-refresh", response.refreshToken());
        verify(tokenService).rotateTokens(sessionId, Sha256.hash("old-refresh"), "new-access-id",
                accessExpiry, Sha256.hash("new-refresh"), refreshExpiry);
    }

    @Test
    void refreshRejectsAccessTokenAndInactiveRefreshSession() {
        when(jwtService.isRefreshToken("access-token")).thenReturn(false);
        assertThrows(InvalidTokenException.class,
                () -> authService.refresh("access-token"));
        verify(tokenService, never()).rotateTokens(any(), any(), any(), any(), any(), any());

        UUID sessionId = UUID.randomUUID();
        when(jwtService.isRefreshToken("replayed-refresh")).thenReturn(true);
        when(jwtService.extractSessionId("replayed-refresh")).thenReturn(sessionId);
        when(jwtService.extractUsername("replayed-refresh")).thenReturn("alice");
        when(jwtService.generateToken("alice", sessionId)).thenReturn("new-access");
        when(jwtService.generateRefreshToken("alice", sessionId)).thenReturn("new-refresh");
        when(jwtService.extractTokenId("new-access")).thenReturn("new-access-id");
        when(jwtService.extractExpiration(any())).thenReturn(Date.from(Instant.now().plusSeconds(60)));
        when(tokenService.rotateTokens(any(), any(), any(), any(), any(), any())).thenReturn(false);

        assertThrows(InactiveTokenException.class,
                () -> authService.refresh("replayed-refresh"));
    }

    @Test
    void logoutRevokesSessionUsingCurrentAccessTokenIdentifiers() {
        UUID sessionId = UUID.randomUUID();
        when(jwtService.extractUsername("access-token")).thenReturn("alice");
        when(jwtService.extractSessionId("access-token")).thenReturn(sessionId);
        when(jwtService.extractTokenId("access-token")).thenReturn("access-id");
        when(tokenService.revokeSession(sessionId, "access-id")).thenReturn(true);

        assertEquals("Logged out successfully", authService.logout("access-token").getMessage());

        verify(tokenService).revokeSession(sessionId, "access-id");
    }

    @Test
    void logoutRejectsAlreadyRevokedSession() {
        UUID sessionId = UUID.randomUUID();
        when(jwtService.extractUsername("access-token")).thenReturn("alice");
        when(jwtService.extractSessionId("access-token")).thenReturn(sessionId);
        when(jwtService.extractTokenId("access-token")).thenReturn("access-id");
        when(tokenService.revokeSession(sessionId, "access-id")).thenReturn(false);

        assertThrows(InactiveTokenException.class, () -> authService.logout("access-token"));
    }

    private static User user(String username, boolean enabled, boolean locked) {
        User user = new User();
        user.setUsername(username);
        user.setPassword("stored-hash");
        user.setEnabled(enabled);
        user.setLocked(locked);
        return user;
    }
}
