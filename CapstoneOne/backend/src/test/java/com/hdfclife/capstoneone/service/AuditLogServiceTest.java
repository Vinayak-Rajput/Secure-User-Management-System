package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.dto.AuditLogResponse;
import com.hdfclife.capstoneone.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditLogServiceTest {

    @InjectMocks
    private AuditLogService auditLogService;

    @Mock
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void setUp() {
    }

    @Test
    void findRecentLogsRejectsInvalidPagination() {
        assertThrows(IllegalArgumentException.class, () -> auditLogService.findRecentLogs(0, 0));
        assertThrows(IllegalArgumentException.class, () -> auditLogService.findRecentLogs(501, 0));
        assertThrows(IllegalArgumentException.class, () -> auditLogService.findRecentLogs(10, -1));

        verify(auditLogRepository, never()).findRecentLogs(0, 0);
    }

}
