SELECT id, event_time, level, event_type, actor_username, subject_username, exception_type,
       http_method, request_path, http_status, duration_ms, correlation_id
FROM public.application_logs
ORDER BY event_time DESC, id DESC
LIMIT ? OFFSET ?
