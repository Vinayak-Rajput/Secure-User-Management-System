package com.hdfclife.capstoneone.filter;

import com.hdfclife.capstoneone.dto.ErrorResponse;
import com.hdfclife.capstoneone.logging.RequestCorrelationId;
import com.hdfclife.capstoneone.model.AuditEventType;
import com.hdfclife.capstoneone.service.ApiRateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.slf4j.MDC;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class ApiRateLimitFilter extends OncePerRequestFilter {

    private static final String RETRY_AFTER_SECONDS = "60";

    private final ApiRateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!isAuthenticated(authentication)) {
            filterChain.doFilter(request, response);
            return;
        }

        boolean sensitiveRoute = isSensitiveRoute(request.getRequestURI());
        boolean permitted = rateLimitService.tryAcquire(authentication.getName(), request.getRemoteAddr(), sensitiveRoute);

        if (!permitted) {
            String correlationId = RequestCorrelationId.attach(request, response);

            MDC.put("correlationId", correlationId);
            MDC.put("eventType", AuditEventType.RATE_LIMITED.name());
            MDC.put("httpMethod", request.getMethod());
            MDC.put("requestPath", request.getRequestURI());
            MDC.put("httpStatus", String.valueOf(HttpStatus.TOO_MANY_REQUESTS.value()));

            try {
                log.warn("Authenticated request rate limit exceeded: method={}, path={}", request.getMethod(), request.getRequestURI());
            }
            finally {
                MDC.remove("eventType");
                MDC.remove("httpMethod");
                MDC.remove("requestPath");
                MDC.remove("httpStatus");
                MDC.remove("correlationId");
            }

            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Retry-After", RETRY_AFTER_SECONDS);

            objectMapper.writeValue(response.getWriter(),
                    new ErrorResponse(
                            HttpStatus.TOO_MANY_REQUESTS.value(),
                            "Too Many Requests",
                            "Too many requests. Please try again later.",
                            request.getRequestURI(),
                            correlationId
                    )
            );

            return;
        }
        filterChain.doFilter(request, response);
    }

    private static boolean isAuthenticated(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken);
    }

    private static boolean isSensitiveRoute(String requestUri) {
        return requestUri.equals("/users") || requestUri.startsWith("/users/") || requestUri.startsWith("/audit/");
    }
}
