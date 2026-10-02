package com.hdfclife.capstoneone.config;

import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
@RequiredArgsConstructor
public class DatabaseCircuitBreakerAspect {

    private final CircuitBreakerRegistry circuitBreakerRegistry;

    @Around("execution(* com.hdfclife.capstoneone.service.AuthService.login(..)) || " +
            "execution(* com.hdfclife.capstoneone.service.AuthService.refresh(..)) || " +
            "execution(* com.hdfclife.capstoneone.service.AuthService.logout(..)) || " +
            "execution(* com.hdfclife.capstoneone.service.UserService.*(..)) || " +
            "execution(* com.hdfclife.capstoneone.service.UserRegistrationService.*(..))")
    public Object protectApplicationDatabaseOperations(ProceedingJoinPoint invocation) throws Throwable {

        return circuitBreakerRegistry
                .circuitBreaker("authenticationDatabase")
                .executeCheckedSupplier(invocation::proceed);
    }

    @Around("execution(* com.hdfclife.capstoneone.service.AuditLogService.*(..))")
    public Object protectAuditLogDatabaseOperations(ProceedingJoinPoint invocation) throws Throwable {

        return circuitBreakerRegistry
                .circuitBreaker("auditLogDatabase")
                .executeCheckedSupplier(invocation::proceed);
    }
}
