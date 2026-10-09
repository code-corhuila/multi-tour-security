REVOKE security_writer FROM security_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA security REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM security_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA security REVOKE SELECT ON TABLES FROM security_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA security FROM security_reader, security_writer;
REVOKE ALL ON SCHEMA security FROM security_reader, security_writer;
