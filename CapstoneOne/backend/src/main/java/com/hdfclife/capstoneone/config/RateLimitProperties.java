package com.hdfclife.capstoneone.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

@ConfigurationProperties(prefix = "resilience4j.ratelimiter")
public record RateLimitProperties(Map<String, LimiterSettings> instances) {

    public LimiterSettings require(String name) {
        LimiterSettings settings = instances == null ? null : instances.get(name);

        if (settings == null) {
            throw new IllegalStateException("Rate limiter configuration is missing: " + name);
        }
        return settings;
    }

    public record LimiterSettings(
            int limitForPeriod,
            Duration limitRefreshPeriod,
            Duration timeoutDuration
    ) {
    }
}
