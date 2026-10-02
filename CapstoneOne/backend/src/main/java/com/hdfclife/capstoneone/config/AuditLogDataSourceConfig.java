package com.hdfclife.capstoneone.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.boot.jdbc.DataSourceBuilder;
import com.zaxxer.hikari.HikariDataSource;

@Configuration
public class AuditLogDataSourceConfig {

    @Bean(
            name = "auditLogReaderDataSource",
            destroyMethod = "close"
    )
    public HikariDataSource auditLogReaderDataSource(
            @Value("${audit.datasource.url}") String url,
            @Value("${audit.datasource.reader-username}") String username,
            @Value("${audit.datasource.reader-password}") String password
    ) {

        return DataSourceBuilder.create()
                .type(HikariDataSource.class)
                .url(url)
                .username(username)
                .password(password)
                .build();
    }

    @Bean(name = "auditLogJdbcTemplate")
    public JdbcTemplate auditLogJdbcTemplate(@Qualifier("auditLogReaderDataSource") HikariDataSource dataSource) {

        return new JdbcTemplate(dataSource);
    }
}
