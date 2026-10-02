package com.hdfclife.capstoneone.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class AuditLogAppender extends AppenderBase<ILoggingEvent> {

    private static final Logger STATUS_LOG = LoggerFactory.getLogger("AUDIT_STORAGE_STATUS");

    private static final long RECONNECT_DELAY_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final long STATUS_LOG_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);

    private final AtomicLong failureCount = new AtomicLong();
    private final AtomicLong droppedEventCount = new AtomicLong();

    private volatile long nextConnectionAttemptNanos;
    private volatile long lastFailureLogNanos;

    @Setter
    private String jdbcUrl;

    @Setter
    private String username;

    @Setter
    private String password;

    private Connection connection;
    private String insertSql;

    @Override
    public void start() {
        try {
            connect();
            super.start();
        }
        catch (IOException | SQLException exception) {
            closeConnection();
            reportFailure("initialize", exception, false);
            super.start();
        }
    }

    private void connect() throws SQLException, IOException {
        if (insertSql == null) {
            try (InputStream resource = getClass().getResourceAsStream("/sql/insert-audit-log.sql")) {
                if (resource == null) {
                    throw new IOException("Classpath resource /sql/insert-audit-log.sql was not found");
                }

                insertSql = new String(resource.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
        }

        Properties connectionProperties = new Properties();

        connectionProperties.setProperty("user", username);
        connectionProperties.setProperty("password", password == null ? "" : password);
        connectionProperties.setProperty("connectTimeout", "3");
        connectionProperties.setProperty("socketTimeout", "3");

        connection = DriverManager.getConnection(jdbcUrl, connectionProperties);
    }

    @Override
    protected synchronized void append(ILoggingEvent event) {
        if (connection == null) {
            if (System.nanoTime() < nextConnectionAttemptNanos) {
                droppedEventCount.incrementAndGet();
                return;
            }
            try {
                connect();
                reportRecovery();
            }
            catch (IOException | SQLException exception) {
                closeConnection();
                reportFailure("reconnect", exception, true);

                return;
            }
        }

        try (PreparedStatement statement = connection.prepareStatement(insertSql)) {

            statement.setObject(1, java.time.Instant.ofEpochMilli(event.getTimeStamp()).atOffset(java.time.ZoneOffset.UTC));
            statement.setString(2, event.getLevel().toString());
            statement.setString(3, value(event, "eventType", "LOG_EVENT"));
            statement.setString(4, value(event, "actorUsername", null));
            statement.setString(5, value(event, "subjectUsername", null));
            statement.setString(6, event.getThrowableProxy() == null ? null : event.getThrowableProxy().getClassName());
            statement.setString(7, value(event, "httpMethod", null));
            statement.setString(8, value(event, "requestPath", null));
            statement.setObject(9, integerValue(event));
            statement.setObject(10, longValue(event));
            statement.setString(11, value(event, "correlationId", null));

            statement.executeUpdate();
        }
        catch (SQLException exception) {
            closeConnection();
            reportFailure("insert", exception, true);
        }
    }

    private String value(ILoggingEvent event, String key, String defaultValue) {
        String value = event.getMDCPropertyMap().get(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private Integer integerValue(ILoggingEvent event) {
        String value = value(event, "httpStatus", null);
        return value == null ? null : parseInteger(value);
    }

    private Long longValue(ILoggingEvent event) {
        String value = value(event, "durationMs", null);
        return value == null ? null : parseLong(value);
    }

    private Integer parseInteger(String value) {
        try {
            return Integer.valueOf(value);
        }
        catch (NumberFormatException exception) {
            STATUS_LOG.warn("event=AUDIT_LOG_FIELD_INVALID field=httpStatus");
            return null;
        }
    }

    private Long parseLong(String value) {
        try {
            return Long.valueOf(value);
        }
        catch (NumberFormatException exception) {
            STATUS_LOG.warn("event=AUDIT_LOG_FIELD_INVALID field=durationMs");
            return null;
        }
    }

    @Override
    public void stop() {
        closeConnection();
        super.stop();
    }

    private void closeConnection() {
        if (connection == null) {
            return;
        }
        try {
            connection.close();
        }
        catch (SQLException exception) {
            STATUS_LOG.warn("event=AUDIT_LOG_CONNECTION_CLOSE_FAILED exceptionType={}", exception.getClass().getSimpleName());
        }
        finally {
            connection = null;
        }
    }

    private void reportFailure(String phase, Exception exception, boolean eventDropped) {
        long failures = failureCount.incrementAndGet();

        if (eventDropped) {
            droppedEventCount.incrementAndGet();
        }

        long now = System.nanoTime();
        nextConnectionAttemptNanos = now + RECONNECT_DELAY_NANOS;

        if (lastFailureLogNanos == 0 || now - lastFailureLogNanos >= STATUS_LOG_INTERVAL_NANOS) {
            lastFailureLogNanos = now;

            String exceptionType = exception.getClass().getSimpleName();
            STATUS_LOG.error("event=AUDIT_LOG_STORAGE_FAILURE phase={} exceptionType={} totalFailures={} droppedEvents={}", phase, exceptionType, failures, droppedEventCount.get());

            addWarn("PostgreSQL audit appender failure: phase=" + phase + ", exceptionType=" + exceptionType);
        }
    }

    private void reportRecovery() {
        nextConnectionAttemptNanos = 0;
        long dropped = droppedEventCount.getAndSet(0);

        if (dropped > 0) {
            STATUS_LOG.warn("event=AUDIT_LOG_STORAGE_RECOVERED droppedEvents={} totalFailures={}", dropped, failureCount.get());
        }

        lastFailureLogNanos = 0;
    }
}
