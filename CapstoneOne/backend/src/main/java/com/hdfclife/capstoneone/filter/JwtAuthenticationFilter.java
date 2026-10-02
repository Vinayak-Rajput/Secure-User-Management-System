package com.hdfclife.capstoneone.filter;

import com.hdfclife.capstoneone.security.BearerTokenResolver;
import com.hdfclife.capstoneone.security.SecurityExceptionHandlers;
import com.hdfclife.capstoneone.exception.InvalidAuthorizationHeaderException;
import com.hdfclife.capstoneone.exception.InvalidTokenException;
import com.hdfclife.capstoneone.service.JwtService;
import com.hdfclife.capstoneone.service.TokenService;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.JwtException;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final BearerTokenResolver bearerTokenResolver;
    private final TokenService tokenService;
    private final SecurityExceptionHandlers securityExceptionHandlers;
    private final CircuitBreakerRegistry circuitBreakerRegistry;

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt;

        try {
            jwt = bearerTokenResolver.resolve(authHeader);
        }
        catch (InvalidAuthorizationHeaderException exception) {
            SecurityContextHolder.clearContext();
            reject(request, response, exception.getMessage());

            return;
        }

        final String username;
        final UUID sessionId;
        final String tokenId;

        try {
            username = jwtService.extractUsername(jwt);
            sessionId = jwtService.extractSessionId(jwt);
            tokenId = jwtService.extractTokenId(jwt);
        }
        catch (AuthenticationException exception) {
            SecurityContextHolder.clearContext();
            reject(request, response, "Authentication failed.");

            return;
        }
        catch (InvalidTokenException | JwtException | IllegalArgumentException exception) {
            SecurityContextHolder.clearContext();
            reject(request, response, "Invalid or expired token.");

            return;
        }

        try {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = circuitBreakerRegistry.circuitBreaker("authenticationDatabase")
                        .executeSupplier(() -> {
                            if (!tokenService.isAccessTokenActive(sessionId, tokenId)) {
                                return null;
                            }
                            return userDetailsService.loadUserByUsername(username);
                        });

                if (userDetails == null) {
                    SecurityContextHolder.clearContext();
                    reject(request, response, "Token is inactive.");

                    return;
                }

                if (!jwtService.isTokenValid(jwt, userDetails.getUsername())) {
                    SecurityContextHolder.clearContext();
                    reject(request, response, "Invalid or expired token.");

                    return;
                }
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        catch (CallNotPermittedException | DataAccessResourceFailureException exception) {
            SecurityContextHolder.clearContext();
            securityUnavailable(request, response, exception);

            return;
        }
        catch (AuthenticationException exception) {
            SecurityContextHolder.clearContext();
            reject(request, response, "Authentication failed.");

            return;
        }
        catch (InvalidTokenException | JwtException | IllegalArgumentException exception) {
            SecurityContextHolder.clearContext();
            reject(request, response, "Invalid or expired token.");

            return;
        }

        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, String message) throws IOException, ServletException {
        securityExceptionHandlers.commence(request, response, new BadCredentialsException(message));
    }

    private void securityUnavailable(HttpServletRequest request, HttpServletResponse response, Exception exception) throws IOException {
        securityExceptionHandlers.serviceUnavailable(request, response, exception);
    }
}
