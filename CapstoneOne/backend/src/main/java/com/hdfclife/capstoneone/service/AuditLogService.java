package com.hdfclife.capstoneone.service;

import com.hdfclife.capstoneone.dto.AuditLogResponse;
import com.hdfclife.capstoneone.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditLogService {
    private final AuditLogRepository auditLogRepository;

    public List<AuditLogResponse> findRecentLogs(int limit, int offset) {
        if (limit < 1 || limit > 500 || offset < 0) {
            throw new IllegalArgumentException("limit must be between 1 and 500 and offset must be non-negative");
        }

        return auditLogRepository.findRecentLogs(limit, offset);
    }
}
