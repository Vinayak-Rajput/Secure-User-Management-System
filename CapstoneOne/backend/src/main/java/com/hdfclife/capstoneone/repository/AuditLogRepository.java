package com.hdfclife.capstoneone.repository;

import com.hdfclife.capstoneone.dto.AuditLogResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;

@Repository
public class AuditLogRepository {
    private static final RowMapper<AuditLogResponse> ROW_MAPPER = AuditLogRepository::mapRow;

    private final JdbcTemplate jdbcTemplate;
    private final String selectLogsSql;

    public AuditLogRepository(
            @Qualifier("auditLogJdbcTemplate") JdbcTemplate jdbcTemplate,
            @Value("classpath:sql/select-audit-logs.sql") Resource selectLogsQuery
    ) {
        this.jdbcTemplate = jdbcTemplate;
        try (var queryStream = selectLogsQuery.getInputStream()) {
            this.selectLogsSql = new String(queryStream.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Unable to load audit log query", exception);
        }
    }

    public List<AuditLogResponse> findRecentLogs(int limit, int offset) {
        return jdbcTemplate.query(selectLogsSql, ROW_MAPPER, limit, offset);
    }

    private static AuditLogResponse mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new AuditLogResponse(
                rs.getLong("id"),
                rs.getObject("event_time", OffsetDateTime.class),
                rs.getString("level"),
                rs.getString("event_type"),
                rs.getString("actor_username"),
                rs.getString("subject_username"),
                rs.getString("exception_type"),
                rs.getString("http_method"),
                rs.getString("request_path"),
                (Integer) rs.getObject("http_status"),
                (Long) rs.getObject("duration_ms"),
                rs.getString("correlation_id")
        );
    }
}
