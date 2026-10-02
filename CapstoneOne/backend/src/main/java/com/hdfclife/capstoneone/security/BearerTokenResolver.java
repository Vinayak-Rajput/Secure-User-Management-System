package com.hdfclife.capstoneone.security;

import com.hdfclife.capstoneone.exception.InvalidAuthorizationHeaderException;
import org.springframework.stereotype.Component;

@Component
public class BearerTokenResolver {

    public String resolve(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.length() <= 7) {
            throw new InvalidAuthorizationHeaderException("Authorization header must contain a valid Bearer token");
        }

        return authHeader.substring(7);
    }
}
