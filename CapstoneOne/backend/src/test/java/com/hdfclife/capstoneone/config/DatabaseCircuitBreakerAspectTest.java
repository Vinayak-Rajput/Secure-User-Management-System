package com.hdfclife.capstoneone.config;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DatabaseCircuitBreakerAspectTest {

    @Mock
    private ProceedingJoinPoint joinPoint;

    private CircuitBreakerRegistry registry;
    private DatabaseCircuitBreakerAspect aspect;

    @BeforeEach
    void setUp() {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(10)
                .minimumNumberOfCalls(5)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .permittedNumberOfCallsInHalfOpenState(2)
                .recordExceptions(DataAccessResourceFailureException.class)
                .build();

        registry = CircuitBreakerRegistry.of(config);
        aspect = new DatabaseCircuitBreakerAspect(registry);
    }

    @Test
    void authenticationCircuitAllowsSuccessfulDatabaseCalls() throws Throwable {
        when(joinPoint.proceed()).thenReturn("ok");

        Object result = aspect.protectApplicationDatabaseOperations(joinPoint);

        assertEquals("ok", result);
        assertEquals(CircuitBreaker.State.CLOSED, registry.circuitBreaker("authenticationDatabase").getState());
        verify(joinPoint).proceed();
    }

    @Test
    void authenticationCircuitOpensAfterRepeatedDatasourceFailures() throws Throwable {
        when(joinPoint.proceed()).thenThrow(new DataAccessResourceFailureException("database down"));

        for (int i = 0; i < 5; i++) {
            assertThrows(DataAccessResourceFailureException.class,
                    () -> aspect.protectApplicationDatabaseOperations(joinPoint));
        }

        assertEquals(CircuitBreaker.State.OPEN, registry.circuitBreaker("authenticationDatabase").getState());
        assertThrows(CallNotPermittedException.class,
                () -> aspect.protectApplicationDatabaseOperations(joinPoint));
        verify(joinPoint, times(5)).proceed();
    }

    @Test
    void authenticationCircuitIgnoresBusinessFailuresThatAreNotDatasourceErrors() throws Throwable {
        when(joinPoint.proceed()).thenThrow(new IllegalStateException("bad credentials path"));

        for (int i = 0; i < 5; i++) {
            assertThrows(IllegalStateException.class,
                    () -> aspect.protectApplicationDatabaseOperations(joinPoint));
        }

        assertEquals(CircuitBreaker.State.CLOSED, registry.circuitBreaker("authenticationDatabase").getState());
    }

    @Test
    void auditCircuitOpensIndependentlyFromAuthenticationCircuit() throws Throwable {
        when(joinPoint.proceed()).thenThrow(new DataAccessResourceFailureException("audit down"));

        for (int i = 0; i < 5; i++) {
            assertThrows(DataAccessResourceFailureException.class,
                    () -> aspect.protectAuditLogDatabaseOperations(joinPoint));
        }

        assertEquals(CircuitBreaker.State.OPEN, registry.circuitBreaker("auditLogDatabase").getState());
        assertEquals(CircuitBreaker.State.CLOSED, registry.circuitBreaker("authenticationDatabase").getState());
        assertThrows(CallNotPermittedException.class,
                () -> aspect.protectAuditLogDatabaseOperations(joinPoint));
    }
}
