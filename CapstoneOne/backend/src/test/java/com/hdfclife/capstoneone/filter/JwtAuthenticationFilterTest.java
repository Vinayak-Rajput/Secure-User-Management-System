package com.hdfclife.capstoneone.filter;

import com.hdfclife.capstoneone.security.SecurityExceptionHandlers;
import com.hdfclife.capstoneone.exception.InvalidAuthorizationHeaderException;
import com.hdfclife.capstoneone.exception.InvalidTokenException;
import com.hdfclife.capstoneone.service.TokenService;
import com.hdfclife.capstoneone.security.BearerTokenResolver;
import com.hdfclife.capstoneone.service.JwtService;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.Duration;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock private JwtService jwtService;
    @Mock private UserDetailsService userDetailsService;
    @Mock private BearerTokenResolver bearerTokenResolver;
    @Mock private TokenService tokenService;
    @Mock private SecurityExceptionHandlers securityExceptionHandlers;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;

    private CircuitBreakerRegistry circuitBreakerRegistry;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowSize(10)
                .minimumNumberOfCalls(5)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .recordExceptions(DataAccessResourceFailureException.class)
                .build();
        circuitBreakerRegistry = CircuitBreakerRegistry.of(config);
        filter = new JwtAuthenticationFilter(
                jwtService,
                userDetailsService,
                bearerTokenResolver,
                tokenService,
                securityExceptionHandlers,
                circuitBreakerRegistry);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void missingAuthorizationHeaderContinuesFilterChain() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(bearerTokenResolver, never()).resolve(any());
    }

    @Test
    void malformedAuthorizationHeaderIsRejected() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Token abc");
        when(bearerTokenResolver.resolve("Token abc"))
                .thenThrow(new InvalidAuthorizationHeaderException("bad header"));

        filter.doFilterInternal(request, response, filterChain);

        verify(securityExceptionHandlers).commence(eq(request), eq(response), any());
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void invalidJwtIsRejected() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer bad");
        when(bearerTokenResolver.resolve("Bearer bad")).thenReturn("bad");
        when(jwtService.extractUsername("bad")).thenThrow(new InvalidTokenException("invalid"));

        filter.doFilterInternal(request, response, filterChain);

        verify(securityExceptionHandlers).commence(eq(request), eq(response), any());
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void inactiveAccessTokenIsRejected() throws Exception {
        UUID sessionId = UUID.randomUUID();
        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(bearerTokenResolver.resolve("Bearer token")).thenReturn("token");
        when(jwtService.extractUsername("token")).thenReturn("alice");
        when(jwtService.extractSessionId("token")).thenReturn(sessionId);
        when(jwtService.extractTokenId("token")).thenReturn("access-id");
        when(tokenService.isAccessTokenActive(sessionId, "access-id")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(securityExceptionHandlers).commence(eq(request), eq(response), any());
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void validTokenAuthenticatesAndContinues() throws Exception {
        UUID sessionId = UUID.randomUUID();
        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(bearerTokenResolver.resolve("Bearer token")).thenReturn("token");
        when(jwtService.extractUsername("token")).thenReturn("alice");
        when(jwtService.extractSessionId("token")).thenReturn(sessionId);
        when(jwtService.extractTokenId("token")).thenReturn("access-id");
        when(tokenService.isAccessTokenActive(sessionId, "access-id")).thenReturn(true);
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(
                User.withUsername("alice").password("x").roles("USER").build());
        when(jwtService.isTokenValid("token", "alice")).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(securityExceptionHandlers, never()).commence(any(), any(), any());
    }

    @Test
    void openCircuitBreakerReturnsServiceUnavailable() throws Exception {
        UUID sessionId = UUID.randomUUID();
        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(bearerTokenResolver.resolve("Bearer token")).thenReturn("token");
        when(jwtService.extractUsername("token")).thenReturn("alice");
        when(jwtService.extractSessionId("token")).thenReturn(sessionId);
        when(jwtService.extractTokenId("token")).thenReturn("access-id");

        CircuitBreaker breaker = circuitBreakerRegistry.circuitBreaker("authenticationDatabase");
        breaker.transitionToOpenState();

        filter.doFilterInternal(request, response, filterChain);

        verify(securityExceptionHandlers).serviceUnavailable(eq(request), eq(response), any(CallNotPermittedException.class));
        verify(filterChain, never()).doFilter(request, response);
        verify(tokenService, never()).isAccessTokenActive(any(), any());
    }

    @Test
    void datasourceFailureDuringSessionLookupReturnsServiceUnavailable() throws Exception {
        UUID sessionId = UUID.randomUUID();
        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(bearerTokenResolver.resolve("Bearer token")).thenReturn("token");
        when(jwtService.extractUsername("token")).thenReturn("alice");
        when(jwtService.extractSessionId("token")).thenReturn(sessionId);
        when(jwtService.extractTokenId("token")).thenReturn("access-id");
        when(tokenService.isAccessTokenActive(sessionId, "access-id"))
                .thenThrow(new DataAccessResourceFailureException("db down"));

        filter.doFilterInternal(request, response, filterChain);

        verify(securityExceptionHandlers).serviceUnavailable(eq(request), eq(response), any(DataAccessResourceFailureException.class));
        verify(filterChain, never()).doFilter(request, response);
    }
}
