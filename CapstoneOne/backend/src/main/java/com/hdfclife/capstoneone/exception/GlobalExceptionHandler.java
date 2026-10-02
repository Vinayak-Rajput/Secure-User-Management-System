package com.hdfclife.capstoneone.exception;

import com.hdfclife.capstoneone.dto.ErrorResponse;
import com.hdfclife.capstoneone.model.AuditEventType;
import com.hdfclife.capstoneone.logging.RequestCorrelationId;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler({
            JwtException.class,
            InvalidTokenException.class,
            InvalidCredentialsException.class,
            InactiveTokenException.class
    })
    public ResponseEntity<ErrorResponse> handleAuthenticationFailure(RuntimeException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.AUTHENTICATION_FAILED, 401, exception, request);
        log.warn("Authentication failed: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.UNAUTHORIZED, "Authentication failed.", request);
    }

    @ExceptionHandler(DisallowedRequestOriginException.class)
    public ResponseEntity<ErrorResponse> handleDisallowedRequestOrigin(DisallowedRequestOriginException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.AUTHORIZATION_FAILED, HttpStatus.FORBIDDEN.value(), exception, request);
        log.warn("Access denied: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.FORBIDDEN, "The request origin is not allowed.", request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.AUTHORIZATION_FAILED, HttpStatus.FORBIDDEN.value(), exception, request);
        putAuthenticatedActor();
        log.warn("Access denied: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.FORBIDDEN, "You do not have permission to access this resource.", request);
    }

    @ExceptionHandler({
            InvalidAuthorizationHeaderException.class,
            IllegalArgumentException.class,
            MissingRequestHeaderException.class,
            HttpMessageNotReadableException.class,
            MethodArgumentTypeMismatchException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.BAD_REQUEST, 400, exception, request);
        log.warn("Client request failed: method={}, path={}, exceptionType={}", request.getMethod(), request.getRequestURI(), exception.getClass().getSimpleName());

        return buildResponse(HttpStatus.BAD_REQUEST, "Invalid request.", request);
    }

    @ExceptionHandler(DuplicateUserException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateUser(DuplicateUserException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.DUPLICATE_USER, 409, exception, request);
        log.warn("Duplicate user registration: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.CONFLICT, "Account could not be created because the username or email is already in use.", request);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound(UserNotFoundException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.USER_NOT_FOUND, 404, exception, request);
        putAuthenticatedActor();
        log.warn("User resource not found: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.NOT_FOUND, "The requested user was not found.", request);
    }

    @ExceptionHandler(UserOperationException.class)
    public ResponseEntity<ErrorResponse> handleUserOperation(UserOperationException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.USER_ADMIN_ACTION_FAILED, 409, exception, request);
        putAuthenticatedActor();
        log.warn("User administration action rejected: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.CONFLICT, "The requested user operation could not be completed.", request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationFailure(MethodArgumentNotValidException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.VALIDATION_FAILED, 400, exception, request);
        log.warn("Request validation failed: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.BAD_REQUEST, "Request validation failed.", request);
    }

    @ExceptionHandler(RequestNotPermitted.class)
    public ResponseEntity<ErrorResponse> handleRateLimitExceeded(RequestNotPermitted exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.RATE_LIMITED, 429, exception, request);
        log.warn("Request rate limit exceeded: method={}, path={}", request.getMethod(), request.getRequestURI());

        return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .header(RequestCorrelationId.HEADER_NAME, correlationId(request))
                .body(
                        new ErrorResponse(
                                429,
                                HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase(),
                                "Too many requests. Please try again later.",
                                request.getRequestURI(),
                                correlationId(request)
                        )
                );
    }

    @ExceptionHandler(CallNotPermittedException.class)
    public ResponseEntity<ErrorResponse> handleCircuitBreakerOpen(CallNotPermittedException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.CIRCUIT_OPEN, 503, exception, request);
        putAuthenticatedActor();
        log.warn("Circuit breaker opened: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.SERVICE_UNAVAILABLE, "Service is temporarily unavailable. Please try again later.", request);
    }

    @ExceptionHandler(DataAccessResourceFailureException.class)
    public ResponseEntity<ErrorResponse> handleDatabaseUnavailable(DataAccessResourceFailureException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.DATABASE_UNAVAILABLE, HttpStatus.SERVICE_UNAVAILABLE.value(), exception, request);
        putAuthenticatedActor();
        log.error("Database resource unavailable: method={}, path={}", request.getMethod(), request.getRequestURI());

        return buildResponse(HttpStatus.SERVICE_UNAVAILABLE,
                "Authentication data is temporarily unavailable. Please try again later.", request);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleOtherDatabaseError(DataAccessException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.DATABASE_OPERATION_FAILED, HttpStatus.INTERNAL_SERVER_ERROR.value(), exception, request);
        putAuthenticatedActor();
        log.error("Database operation failed: method={}, path={}, exceptionType={}", request.getMethod(), request.getRequestURI(), exception.getClass().getSimpleName());

        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "The database operation could not be completed.", request);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotAllowed(HttpRequestMethodNotSupportedException exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.METHOD_NOT_ALLOWED, 405, exception, request);
        log.warn("HTTP method not allowed: method={}, path={}", request.getMethod(), request.getRequestURI());

        ResponseEntity.BodyBuilder response = ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .header(RequestCorrelationId.HEADER_NAME, correlationId(request));

        if (exception.getSupportedHttpMethods() != null) {

            response.allow(exception.getSupportedHttpMethods().toArray(HttpMethod[]::new));
        }

        return response.body(new ErrorResponse(HttpStatus.METHOD_NOT_ALLOWED.value(), HttpStatus.METHOD_NOT_ALLOWED.getReasonPhrase(), "HTTP method is not supported for this endpoint.", request.getRequestURI(), correlationId(request)));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpectedError(Exception exception, HttpServletRequest request) {

        setFailureContext(AuditEventType.UNEXPECTED_ERROR, 500, exception, request);
        log.error("Unhandled request error: method={}, path={}, exceptionType={}", request.getMethod(), request.getRequestURI(), exception.getClass().getSimpleName());

        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.", request);
    }

    private ResponseEntity<ErrorResponse> buildResponse(HttpStatus status, String message, HttpServletRequest request) {

        String safeMessage = message == null || message.isBlank() ? "Invalid request" : message;
        ErrorResponse body = new ErrorResponse(status.value(), status.getReasonPhrase(), safeMessage, request.getRequestURI(), correlationId(request));

        return ResponseEntity.status(status)
                .header(RequestCorrelationId.HEADER_NAME, body.getCorrelationId())
                .body(body);
    }

    private void setFailureContext(AuditEventType eventType, int status, Exception exception, HttpServletRequest request) {
        MDC.put("eventType", eventType.name());
        MDC.put("httpStatus", String.valueOf(status));
        MDC.put("exceptionType", exception.getClass().getSimpleName());

        correlationId(request);
    }

    private String correlationId(HttpServletRequest request) {
        String id = RequestCorrelationId.ensure(request);
        MDC.put("correlationId", id);

        return id;
    }

    private void putAuthenticatedActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken)) {
            MDC.put("actorUsername", authentication.getName());
        }
    }

}
