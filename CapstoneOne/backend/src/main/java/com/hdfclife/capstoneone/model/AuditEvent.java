package com.hdfclife.capstoneone.model;

public record AuditEvent(
        AuditEventType type,
        String actorUsername,
        String subjectUsername,
        String httpMethod,
        String requestPath,
        Integer httpStatus,
        String message
) {

    public static AuditEvent authentication(AuditEventType type, String actorUsername, String message) {
        return new AuditEvent(type, actorUsername, null, null, null, null, message);
    }

    public static AuditEvent request(
            AuditEventType type,
            String actorUsername,
            String subjectUsername,
            String httpMethod,
            String requestPath,
            int httpStatus,
            String message
    ) {
        return new AuditEvent(type, actorUsername, subjectUsername, httpMethod, requestPath, httpStatus, message);
    }
}
