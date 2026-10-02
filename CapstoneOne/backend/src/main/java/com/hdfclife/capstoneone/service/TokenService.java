package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.entity.AuthSession;
import com.hdfclife.capstoneone.repository.AuthSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class TokenService {

    private final AuthSessionRepository authSessionRepository;

    @Transactional
    public void saveSession(UUID sessionId, String username, String accessTokenId, String refreshTokenHash, Instant accessTokenExpiresAt, Instant refreshTokenExpiresAt) {
        AuthSession session = new AuthSession();

        session.setId(sessionId);
        session.setUsername(username);
        session.setAccessTokenId(accessTokenId);
        session.setRefreshTokenHash(refreshTokenHash);
        session.setAccessTokenExpiresAt(accessTokenExpiresAt);
        session.setRefreshTokenExpiresAt(refreshTokenExpiresAt);
        session.setRevoked(false);

        authSessionRepository.save(session);
    }

    @Transactional(readOnly = true)
    public boolean isAccessTokenActive(UUID sessionId, String accessTokenId) {
        return authSessionRepository.findByIdAndRevokedFalse(sessionId)
                .map(session -> session
                        .getAccessTokenExpiresAt()
                        .isAfter(Instant.now()) && session.getAccessTokenId().equals(accessTokenId)
                )
                .orElse(false);
    }

    @Transactional
    public boolean rotateTokens(UUID sessionId, String presentedRefreshTokenHash, String newAccessTokenId, Instant newAccessTokenExpiresAt, String newRefreshTokenHash, Instant newRefreshTokenExpiresAt) {
        AuthSession session = authSessionRepository.findByIdForUpdate(sessionId).orElse(null);

        if (session == null || session.isRevoked() || !session.getRefreshTokenExpiresAt().isAfter(Instant.now())) {
            return false;
        }

        if (!MessageDigest.isEqual(session.getRefreshTokenHash().getBytes(StandardCharsets.UTF_8), presentedRefreshTokenHash.getBytes(StandardCharsets.UTF_8))) {
            session.setRevoked(true);
            authSessionRepository.save(session);

            return false;
        }

        session.setAccessTokenId(newAccessTokenId);
        session.setAccessTokenExpiresAt(newAccessTokenExpiresAt);
        session.setRefreshTokenHash(newRefreshTokenHash);
        session.setRefreshTokenExpiresAt(newRefreshTokenExpiresAt);

        authSessionRepository.save(session);

        return true;
    }

    @Transactional
    public boolean revokeSession(UUID sessionId, String accessTokenId) {
        AuthSession session = authSessionRepository.findByIdForUpdate(sessionId).orElse(null);

        if (session == null || session.isRevoked() || !session.getAccessTokenId().equals(accessTokenId) || !session.getAccessTokenExpiresAt().isAfter(Instant.now())) {
            return false;
        }

        session.setRevoked(true);
        authSessionRepository.save(session);

        return true;
    }

    @Transactional
    public int revokeAllSessions(String username) {
        return authSessionRepository.revokeAllActiveByUsername(username);
    }

}
