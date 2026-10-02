package com.hdfclife.capstoneone.security;

import com.hdfclife.capstoneone.config.FrontendProperties;
import com.hdfclife.capstoneone.exception.DisallowedRequestOriginException;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class RefreshRequestOriginValidator {
    private final Set<String> allowedOrigins;

    public RefreshRequestOriginValidator(FrontendProperties frontendProperties) {
        this.allowedOrigins = Set.copyOf(frontendProperties.getAllowedOrigins());
    }

    public void requireAllowed(String origin) {
        if (origin == null || !allowedOrigins.contains(origin)) {
            throw new DisallowedRequestOriginException("Refresh request origin is not allowed");
        }
    }
}
