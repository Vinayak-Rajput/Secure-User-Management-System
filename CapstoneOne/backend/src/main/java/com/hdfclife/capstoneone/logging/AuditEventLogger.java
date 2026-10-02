package com.hdfclife.capstoneone.logging;

import com.hdfclife.capstoneone.model.AuditEvent;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@Slf4j
public class AuditEventLogger {

    public void log(AuditEvent event) {
        Map<String, String> previousContext = MDC.getCopyOfContextMap();

        try {
            MDC.put("eventType", event.type().name());

            putIfPresent("actorUsername", event.actorUsername());
            putIfPresent("subjectUsername", event.subjectUsername());
            putIfPresent("httpMethod", event.httpMethod());
            putIfPresent("requestPath", event.requestPath());
            putIfPresent("httpStatus", event.httpStatus() == null ? null : event.httpStatus().toString());

            log.info(event.message());
        }
        finally {
            if (previousContext == null) {
                MDC.clear();
            }
            else {
                MDC.setContextMap(previousContext);
            }
        }
    }

    private void putIfPresent(String key, String value) {
        if (value != null) {
            MDC.put(key, value);
        }
    }
}
