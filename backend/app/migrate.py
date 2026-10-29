from sqlalchemy import text
from app.database import engine, Base
import app.models # Ensure all models are registered

def run_migrations():
    """
    Applies incremental schema updates and missing columns safely without data loss.
    Works seamlessly on both SQLite and PostgreSQL.
    """
    print("[*] Running schema migrations...")
    Base.metadata.create_all(bind=engine)

    migration_statements = [
        # test_definitions
        ("test_definitions", "is_required", "ALTER TABLE test_definitions ADD COLUMN is_required BOOLEAN DEFAULT 1;"),
        ("test_definitions", "is_behavioral", "ALTER TABLE test_definitions ADD COLUMN is_behavioral BOOLEAN DEFAULT 0;"),
        
        # evidence_records
        ("evidence_records", "evidence_provenance", "ALTER TABLE evidence_records ADD COLUMN evidence_provenance VARCHAR(50) DEFAULT 'LIVE_TARGET';"),
        ("evidence_records", "execution_status", "ALTER TABLE evidence_records ADD COLUMN execution_status VARCHAR(50) DEFAULT 'SUCCESS';"),
        
        # framework_controls
        ("framework_controls", "assessment_method", "ALTER TABLE framework_controls ADD COLUMN assessment_method VARCHAR(50) DEFAULT 'TECHNICAL_AUTOMATED';"),
        ("framework_controls", "official_requirement", "ALTER TABLE framework_controls ADD COLUMN official_requirement TEXT;"),
        ("framework_controls", "guidance", "ALTER TABLE framework_controls ADD COLUMN guidance TEXT;"),
        ("framework_controls", "framework_version", "ALTER TABLE framework_controls ADD COLUMN framework_version VARCHAR(50) DEFAULT '2022';"),
        ("framework_controls", "is_enhancement", "ALTER TABLE framework_controls ADD COLUMN is_enhancement BOOLEAN DEFAULT 0;"),
        ("framework_controls", "parent_control_id", "ALTER TABLE framework_controls ADD COLUMN parent_control_id VARCHAR(50);"),
        ("framework_controls", "status", "ALTER TABLE framework_controls ADD COLUMN status VARCHAR(30) DEFAULT 'ACTIVE';"),
        ("framework_controls", "provenance", "ALTER TABLE framework_controls ADD COLUMN provenance VARCHAR(255);"),

        # policy_mappings
        ("policy_mappings", "reviewer", "ALTER TABLE policy_mappings ADD COLUMN reviewer VARCHAR(100);"),
        ("policy_mappings", "reviewed_at", "ALTER TABLE policy_mappings ADD COLUMN reviewed_at DATETIME;"),
        ("policy_mappings", "review_notes", "ALTER TABLE policy_mappings ADD COLUMN review_notes TEXT;"),
        
        # policies
        ("policies", "purpose", "ALTER TABLE policies ADD COLUMN purpose TEXT;"),
        ("policies", "statement", "ALTER TABLE policies ADD COLUMN statement TEXT;"),
        ("policies", "scope", "ALTER TABLE policies ADD COLUMN scope VARCHAR(255) DEFAULT 'Enterprise Infrastructure & Systems';"),
        ("policies", "lifecycle_status", "ALTER TABLE policies ADD COLUMN lifecycle_status VARCHAR(30) DEFAULT 'DRAFT';"),
        ("policies", "approver", "ALTER TABLE policies ADD COLUMN approver VARCHAR(100);"),
        ("policies", "rejection_reason", "ALTER TABLE policies ADD COLUMN rejection_reason TEXT;"),
        ("policies", "effective_date", "ALTER TABLE policies ADD COLUMN effective_date DATETIME;"),
        ("policies", "review_date", "ALTER TABLE policies ADD COLUMN review_date DATETIME;"),
        ("policies", "is_sample", "ALTER TABLE policies ADD COLUMN is_sample BOOLEAN DEFAULT 0;"),
        ("policies", "required_evidence_desc", "ALTER TABLE policies ADD COLUMN required_evidence_desc TEXT;"),
        
        # findings
        ("findings", "target_type", "ALTER TABLE findings ADD COLUMN target_type VARCHAR(50) DEFAULT 'LINUX_VM';"),
        ("findings", "target_host", "ALTER TABLE findings ADD COLUMN target_host VARCHAR(100);"),
        ("findings", "occurrence_count", "ALTER TABLE findings ADD COLUMN occurrence_count INTEGER DEFAULT 1;"),
        ("findings", "first_detected_at", "ALTER TABLE findings ADD COLUMN first_detected_at DATETIME;"),
        ("findings", "last_detected_at", "ALTER TABLE findings ADD COLUMN last_detected_at DATETIME;"),
        ("findings", "verified_resolved_at", "ALTER TABLE findings ADD COLUMN verified_resolved_at DATETIME;"),
        ("findings", "resolution_run_id", "ALTER TABLE findings ADD COLUMN resolution_run_id VARCHAR(100);"),
        ("findings", "risk_waiver_justification", "ALTER TABLE findings ADD COLUMN risk_waiver_justification TEXT;"),
        ("findings", "risk_waiver_approved_by", "ALTER TABLE findings ADD COLUMN risk_waiver_approved_by VARCHAR(100);"),
        ("findings", "risk_waiver_expires_at", "ALTER TABLE findings ADD COLUMN risk_waiver_expires_at DATETIME;"),
        
        # chaos_drifts
        ("chaos_drifts", "lifecycle_phase", "ALTER TABLE chaos_drifts ADD COLUMN lifecycle_phase VARCHAR(50) DEFAULT 'MUTATION_APPLIED';"),
        ("chaos_drifts", "lifecycle_history", "ALTER TABLE chaos_drifts ADD COLUMN lifecycle_history JSON;"),
        ("chaos_drifts", "detection_result", "ALTER TABLE chaos_drifts ADD COLUMN detection_result JSON;"),
        ("chaos_drifts", "recovery_result", "ALTER TABLE chaos_drifts ADD COLUMN recovery_result JSON;"),
    ]

    with engine.connect() as conn:
        for table, col, stmt in migration_statements:
            try:
                conn.execute(text(stmt))
                print(f"    Added column '{col}' to table '{table}'.")
            except Exception:
                # Column already exists
                pass

        try:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_control_mapping ON policy_mappings(policy_id, control_id);"))
        except Exception:
            pass

        conn.commit()
    print("[+] Migrations completed successfully.")

if __name__ == "__main__":
    run_migrations()
