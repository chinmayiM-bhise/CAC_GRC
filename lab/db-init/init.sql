-- Initialize Enterprise Database Schema & Roles for CAC-GRC Auditing

-- Create standard application role (least privilege)
CREATE ROLE app_user WITH LOGIN PASSWORD 'app_password';

-- Create read-only auditor role for CaC engine
CREATE ROLE auditor_readonly WITH LOGIN PASSWORD 'auditor_read_pass';
GRANT pg_read_all_settings TO auditor_readonly;
GRANT pg_read_all_stats TO auditor_readonly;

-- Create sample enterprise data table
CREATE TABLE IF NOT EXISTS customer_pii (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100),
    email VARCHAR(100),
    encrypted_national_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant select rights only
GRANT SELECT ON customer_pii TO auditor_readonly;
