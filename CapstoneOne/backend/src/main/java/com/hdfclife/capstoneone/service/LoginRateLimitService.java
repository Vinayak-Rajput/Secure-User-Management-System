package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.config.RateLimitProperties;
import com.hdfclife.capstoneone.config.RateLimitProperties.LimiterSettings;
import com.hdfclife.capstoneone.security.LocalRateLimiterPool;
import io.github.resilience4j.ratelimiter.RateLimiter;
import org.springframework.stereotype.Service;

import java.util.function.Supplier;

@Service
public class LoginRateLimitService {
    private final LimiterSettings accountSettings;
    private final LimiterSettings clientIpSettings;
    private final LocalRateLimiterPool limiterPool;

    public LoginRateLimitService(RateLimitProperties rateLimitProperties, LocalRateLimiterPool limiterPool) {
        this.accountSettings = rateLimitProperties.require("loginAccount");
        this.clientIpSettings = rateLimitProperties.require("loginClientIp");
        this.limiterPool = limiterPool;
    }

    public <T> T execute(String username, String clientIp, Supplier<T> login) {
        RateLimiter accountLimiter = limiterPool.get("login-account", username, accountSettings);
        RateLimiter ipLimiter = limiterPool.get("login-ip", clientIp, clientIpSettings);

        return accountLimiter.executeSupplier(() -> ipLimiter.executeSupplier(login));
    }
}
