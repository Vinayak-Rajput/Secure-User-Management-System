package com.hdfclife.capstoneone.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RefreshTokenCookieFactory {
    public static final String COOKIE_NAME = "refresh_token";
    private static final String COOKIE_PATH = "/refresh";

    private final Duration tokenLifetime;
    private final boolean secure;
    private final String sameSite;

    public RefreshTokenCookieFactory(
            @Value("${jwt.refresh-expiration}") long tokenLifetimeMillis,
            @Value("${auth.refresh-cookie.secure:true}") boolean secure,
            @Value("${auth.refresh-cookie.same-site:Lax}") String sameSite
    ) {
        this.tokenLifetime = Duration.ofMillis(tokenLifetimeMillis);
        this.secure = secure;
        this.sameSite = sameSite;
    }

    public ResponseCookie issue(String refreshToken) {
        return create(refreshToken, tokenLifetime);
    }

    public ResponseCookie clear() {
        return create("", Duration.ZERO);
    }

    private ResponseCookie create(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path(COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
