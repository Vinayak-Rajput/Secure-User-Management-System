package com.hdfclife.capstoneone.startup;

import com.hdfclife.capstoneone.model.AuthSession;
import com.hdfclife.capstoneone.repository.AuthSessionRepository;
import com.hdfclife.capstoneone.util.Sha256;
import com.hdfclife.capstoneone.util.TokenFormats;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthSessionMigrationRunnerTest {

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Mock
    private ApplicationArguments applicationArguments;

    @InjectMocks
    private LegacyAuthSessionMigrationRunner migrationRunner;

    private static final String VALID_UUID = "123e4567-e89b-12d3-a456-426614174000";
    private static final String VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    @DisplayName("Should migrate legacy sessions, update token formats, revoke them, and flush repository")
    void run_WhenLegacySessionsExist_MigratesAndFlushes() {
        // Arrange
        AuthSession alreadyValidSession = createSession(VALID_UUID, VALID_SHA256, false);
        AuthSession legacySession = createSession("legacy-access-token", "raw-refresh-token", false);

        when(authSessionRepository.findAll()).thenReturn(List.of(alreadyValidSession, legacySession));

        // Act
        migrationRunner.run(applicationArguments);

        // Assert - Already valid session should remain unchanged
        assertEquals(VALID_UUID, alreadyValidSession.getAccessTokenId());
        assertEquals(VALID_SHA256, alreadyValidSession.getRefreshTokenHash());
        assertFalse(alreadyValidSession.isRevoked());

        // Assert - Legacy session should be updated and revoked
        assertTrue(TokenFormats.isTokenId(legacySession.getAccessTokenId()), "Access token ID should be updated to a valid UUID");
        assertEquals(Sha256.hash("raw-refresh-token"), legacySession.getRefreshTokenHash(), "Refresh token should be SHA-256 hashed");
        assertTrue(legacySession.isRevoked(), "Legacy session should be revoked");

        // Verify repository flush called exactly once
        verify(authSessionRepository, times(1)).flush();
    }

    @Test
    @DisplayName("Should do nothing and not flush repository when all sessions are already in modern format")
    void run_WhenAllSessionsAlreadyValid_DoesNotFlush() {
        // Arrange
        AuthSession validSession1 = createSession(VALID_UUID, VALID_SHA256, false);
        AuthSession validSession2 = createSession(UUID.randomUUID().toString(), VALID_SHA256, false);

        when(authSessionRepository.findAll()).thenReturn(List.of(validSession1, validSession2));

        // Act
        migrationRunner.run(applicationArguments);

        // Assert & Verify
        verify(authSessionRepository, never()).flush();
    }

    @Test
    @DisplayName("Should handle empty repository gracefully without flushing")
    void run_WhenNoSessionsExist_DoesNotFlush() {
        // Arrange
        when(authSessionRepository.findAll()).thenReturn(Collections.emptyList());

        // Act
        migrationRunner.run(applicationArguments);

        // Assert & Verify
        verify(authSessionRepository, never()).flush();
    }

    // Helper method to instantiate AuthSession for testing
    private AuthSession createSession(String accessTokenId, String refreshTokenHash, boolean revoked) {
        AuthSession session = new AuthSession();
        session.setAccessTokenId(accessTokenId);
        session.setRefreshTokenHash(refreshTokenHash);
        session.setRevoked(revoked);
        return session;
    }
}