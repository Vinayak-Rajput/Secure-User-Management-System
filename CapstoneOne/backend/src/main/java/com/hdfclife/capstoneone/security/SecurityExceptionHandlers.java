package com.hdfclife.capstoneone.security;

import com.hdfclife.capstoneone.dto.ErrorResponse;
import com.hdfclife.capstoneone.model.AuditEventType;
import com.hdfclife.capstoneone.logging.RequestCorrelationId;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityExceptionHandlers implements AuthenticationEntryPoint, AccessDeniedHandler {
    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, @NonNull HttpServletResponse response, AuthenticationException exception) throws IOException {
        setFailureContext(request, AuditEventType.AUTHENTICATION_FAILED, 401, exception);
        log.warn("Authentication denied: method={}, path={}", request.getMethod(), request.getRequestURI());
        writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "Authentication is required to access this resource.", request);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException {
        setFailureContext(request, AuditEventType.AUTHORIZATION_FAILED, 403, exception);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken)) {
            MDC.put("actorUsername", authentication.getName());
        }

        log.warn("Access denied: method={}, path={}", request.getMethod(), request.getRequestURI());
        writeError(response, HttpServletResponse.SC_FORBIDDEN, "You do not have permission to access this resource.", request);
    }

    public void serviceUnavailable(HttpServletRequest request, HttpServletResponse response, Exception exception) throws IOException {
        setFailureContext(request, AuditEventType.DATABASE_UNAVAILABLE, HttpServletResponse.SC_SERVICE_UNAVAILABLE, exception);
        putAuthenticatedActor();

        log.error("Authentication database unavailable: method={}, path={}", request.getMethod(), request.getRequestURI());
        writeError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Authentication data is temporarily unavailable. Please try again later.", request);
    }

    private void writeError(HttpServletResponse response, int status, String message, HttpServletRequest request) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        String reason = HttpStatus.valueOf(status).getReasonPhrase();
        String correlationId = RequestCorrelationId.attach(request, response);

        MDC.put("correlationId", correlationId);

        objectMapper.writeValue(response.getWriter(), new ErrorResponse(status, reason, message, request.getRequestURI(), correlationId));
    }

    private void setFailureContext(HttpServletRequest request, AuditEventType eventType, int status, Exception exception) {
        MDC.put("httpMethod", request.getMethod());
        MDC.put("requestPath", request.getRequestURI());
        MDC.put("eventType", eventType.name());
        MDC.put("httpStatus", String.valueOf(status));
        MDC.put("exceptionType", exception.getClass().getSimpleName());
        MDC.put("correlationId", RequestCorrelationId.ensure(request));
    }

    private void putAuthenticatedActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken)) {
            MDC.put("actorUsername", authentication.getName());
        }
    }
}
