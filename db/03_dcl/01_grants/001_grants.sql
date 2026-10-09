GRANT USAGE ON SCHEMA security TO security_reader, security_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA security TO security_reader;
-- DELETE lets the retention job purge published events through the service (ADR-004 D10)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA security TO security_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA security GRANT SELECT ON TABLES TO security_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA security GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO security_writer;
GRANT security_writer TO security_app;
