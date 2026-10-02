package com.hdfclife.capstoneone.startup;

import com.hdfclife.capstoneone.entity.AuthSession;
import com.hdfclife.capstoneone.repository.AuthSessionRepository;
import com.hdfclife.capstoneone.util.Sha256;
import com.hdfclife.capstoneone.util.TokenFormats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthSessionMigrationRunner implements ApplicationRunner {

    private final AuthSessionRepository authSessionRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        int migrated = 0;

        for (AuthSession session : authSessionRepository.findAll()) {
            if (TokenFormats.isTokenId(session.getAccessTokenId()) && TokenFormats.isSha256(session.getRefreshTokenHash())) {
                continue;
            }

            session.setAccessTokenId(UUID.randomUUID().toString());
            session.setRefreshTokenHash(Sha256.hash(session.getRefreshTokenHash()));
            session.setRevoked(true);

            migrated++;
        }

        if (migrated > 0) {
            authSessionRepository.flush();
            log.warn("Revoked {} legacy auth sessions containing raw tokens; users must sign in again", migrated);
        }
    }
}
