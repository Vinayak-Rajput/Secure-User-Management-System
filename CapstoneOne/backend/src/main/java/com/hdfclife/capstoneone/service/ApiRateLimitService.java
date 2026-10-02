package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.config.RateLimitProperties;
import com.hdfclife.capstoneone.config.RateLimitProperties.LimiterSettings;
import com.hdfclife.capstoneone.security.LocalRateLimiterPool;
import org.springframework.stereotype.Service;

@Service
public class ApiRateLimitService {

    private final LimiterSettings userSettings;
    private final LimiterSettings clientIpSettings;
    private final LimiterSettings sensitiveSettings;
    private final LocalRateLimiterPool limiterPool;

    public ApiRateLimitService(
            RateLimitProperties rateLimitProperties,
            LocalRateLimiterPool limiterPool
    ) {
        this.userSettings = rateLimitProperties.require("authenticatedUser");
        this.clientIpSettings = rateLimitProperties.require("authenticatedClientIp");
        this.sensitiveSettings = rateLimitProperties.require("authenticatedSensitive");
        this.limiterPool = limiterPool;
    }

    public boolean tryAcquire(String username, String clientIp, boolean sensitiveRoute) {
        if (!limiterPool.get("authenticated-user", username, userSettings).acquirePermission()) {
            return false;
        }
        if (!limiterPool.get("authenticated-ip", clientIp, clientIpSettings).acquirePermission()) {
            return false;
        }
        return !sensitiveRoute || limiterPool.get("authenticated-sensitive", username, sensitiveSettings).acquirePermission();
    }
}
