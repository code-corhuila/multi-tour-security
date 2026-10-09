CREATE INDEX idx_outbox_event_pending ON security.outbox_event (status, next_attempt_at);
CREATE INDEX idx_outbox_event_published_at ON security.outbox_event (published_at);
