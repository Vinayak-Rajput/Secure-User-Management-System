package com.hdfclife.capstoneone.service;
import com.hdfclife.capstoneone.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    private static final String CLAIM_TYPE = "type";
    private static final String TOKEN_TYPE_REFRESH = "refresh";
    private static final String CLAIM_SESSION_ID = "sid";

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public boolean isTokenValid(String token) {
        extractUsername(token);
        return true;
    }

    public boolean isTokenValid(String token, String username) {
        return extractUsername(token).equals(username);
    }

    public Date extractExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    public UUID extractSessionId(String token) {
        String value = parseClaims(token).get(CLAIM_SESSION_ID, String.class);

        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new InvalidTokenException("Token has no valid session identifier");
        }
    }

    public String extractTokenId(String token) {
        String tokenId = parseClaims(token).getId();

        if (tokenId == null || tokenId.isBlank()) {
            throw new InvalidTokenException("Token has no identifier");
        }

        return tokenId;
    }

    public boolean isRefreshToken(String token) {
        return TOKEN_TYPE_REFRESH.equals(parseClaims(token).get(CLAIM_TYPE, String.class));
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    private Claims parseClaims(String token) {
        if (token == null || token.isBlank()) {
            throw new InvalidTokenException("Token must not be empty");
        }

        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(String username, UUID sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(username)
                .id(UUID.randomUUID().toString())
                .claim(CLAIM_SESSION_ID, sessionId.toString())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    public String generateRefreshToken(String username, UUID sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshExpiration);

        return Jwts.builder()
                .subject(username)
                .claim(CLAIM_TYPE, TOKEN_TYPE_REFRESH)
                .claim(CLAIM_SESSION_ID, sessionId.toString())
                .issuedAt(now)
                .expiration(expiryDate)
                .id(UUID.randomUUID().toString())
                .signWith(getSigningKey())
                .compact();
    }
}
