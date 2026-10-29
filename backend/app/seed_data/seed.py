import json
import os
import sys
import datetime
from pathlib import Path

# Add backend directory to path so app modules can be imported
backend_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.database import engine, Base, SessionLocal
from app.models.policy import Policy
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.test_definition import TestDefinition
from app.models.evidence import EvidenceRecord
from app.models.score import EWCESScore

SEED_DIR = Path(__file__).resolve().parent

def load_json(filename: str):
    with open(SEED_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_iso(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None

def seed_database():
    print("=" * 60)
    print("CAC-GRC Database Initializer & Ground Truth Seeder")
    print("=" * 60)

    # 1. Create all database tables
    print("[1/5] Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("      Tables verified successfully.")

    db = SessionLocal()
    try:
        # Clean up any deprecated Gitea tests if present
        obsolete_tests = db.query(TestDefinition).filter(
            TestDefinition.test_id.in_(["TEST-GIT-BRANCH-PROT-T1", "TEST-GIT-BRANCH-PROT-T2"])
        ).all()
        if obsolete_tests:
            for ot in obsolete_tests:
                db.delete(ot)
            db.commit()
            print("      Removed deprecated Git test definitions from database.")

        # 2. Seed Framework Controls (NIST SP 800-53 Rev 5 & ISO/IEC 27001:2022)
        print("[2/5] Seeding Framework Controls...")
        nist_data = load_json("nist_800_53_r5.json")
        for item in nist_data:
            existing = db.query(FrameworkControl).filter_by(control_id=item["control_id"]).first()
            if not existing:
                ctrl = FrameworkControl(
                    control_id=item["control_id"],
                    framework_name=item["framework_name"],
                    framework_version=item.get("framework_version", "Rev 5.2.0"),
                    control_code=item["control_code"],
                    title=item["title"],
                    description=item["description"],
                    domain_family=item["domain_family"],
                    assessment_method=item.get("assessment_method", "ORGANIZATIONAL_MANUAL"),
                    official_requirement=item.get("official_requirement"),
                    guidance=item.get("guidance"),
                    is_enhancement=item.get("is_enhancement", False),
                    parent_control_id=item.get("parent_control_id"),
                    status=item.get("status", "ACTIVE"),
                    provenance=item.get("provenance", "NIST SP 800-53 Rev 5.2.0 OSCAL Catalog")
                )
                db.add(ctrl)
            else:
                existing.framework_version = item.get("framework_version", existing.framework_version)
                existing.is_enhancement = item.get("is_enhancement", existing.is_enhancement)
                existing.parent_control_id = item.get("parent_control_id", existing.parent_control_id)
                existing.status = item.get("status", existing.status)
                existing.provenance = item.get("provenance", existing.provenance)
                existing.official_requirement = item.get("official_requirement", existing.official_requirement)
                existing.guidance = item.get("guidance", existing.guidance)
        
        iso_data = load_json("iso_27001_2022.json")
        for item in iso_data:
            existing = db.query(FrameworkControl).filter_by(control_id=item["control_id"]).first()
            if not existing:
                ctrl = FrameworkControl(
                    control_id=item["control_id"],
                    framework_name=item["framework_name"],
                    framework_version=item.get("framework_version", "2022"),
                    control_code=item["control_code"],
                    title=item["title"],
                    description=item["description"],
                    domain_family=item["domain_family"],
                    assessment_method=item.get("assessment_method", "ORGANIZATIONAL_MANUAL"),
                    official_requirement=item.get("official_requirement"),
                    guidance=item.get("guidance"),
                    is_enhancement=item.get("is_enhancement", False),
                    parent_control_id=item.get("parent_control_id"),
                    status=item.get("status", "ACTIVE"),
                    provenance=item.get("provenance", "ISO/IEC 27001:2022 Annex A Reference Controls")
                )
                db.add(ctrl)
            else:
                existing.framework_version = item.get("framework_version", existing.framework_version)
                existing.is_enhancement = item.get("is_enhancement", existing.is_enhancement)
                existing.parent_control_id = item.get("parent_control_id", existing.parent_control_id)
                existing.status = item.get("status", existing.status)
                existing.provenance = item.get("provenance", existing.provenance)
                existing.official_requirement = item.get("official_requirement", existing.official_requirement)
                existing.guidance = item.get("guidance", existing.guidance)
        db.commit()
        print(f"      Seeded {len(nist_data)} NIST controls and {len(iso_data)} ISO controls.")

        # 3. Seed Corporate Policies
        print("[3/5] Seeding Corporate Policies...")
        policy_data = load_json("sample_policies.json")
        policy_code_map = {}
        for item in policy_data:
            existing = db.query(Policy).filter_by(policy_code=item["policy_code"]).first()
            eff_dt = parse_iso(item.get("effective_date"))
            rev_dt = parse_iso(item.get("review_date"))
            if not existing:
                pol = Policy(
                    policy_code=item["policy_code"],
                    title=item["title"],
                    description=item["description"],
                    category=item["category"],
                    version=item["version"],
                    owner=item["owner"],
                    approver=item.get("approver", "CISO"),
                    lifecycle_status=item.get("lifecycle_status", "APPROVED"),
                    scope=item.get("scope", "Enterprise Infrastructure"),
                    is_sample=item.get("is_sample", True),
                    purpose=item.get("purpose"),
                    statement=item.get("statement"),
                    required_evidence_desc=item.get("required_evidence_desc"),
                    effective_date=eff_dt,
                    review_date=rev_dt,
                )
                db.add(pol)
                db.flush()
                policy_code_map[item["policy_code"]] = pol.id
            else:
                existing.title = item["title"]
                existing.description = item["description"]
                existing.category = item["category"]
                existing.version = item["version"]
                existing.owner = item["owner"]
                existing.approver = item.get("approver", existing.approver)
                existing.lifecycle_status = item.get("lifecycle_status", existing.lifecycle_status)
                existing.scope = item.get("scope", existing.scope)
                existing.is_sample = item.get("is_sample", existing.is_sample)
                existing.purpose = item.get("purpose", existing.purpose)
                existing.statement = item.get("statement", existing.statement)
                existing.required_evidence_desc = item.get("required_evidence_desc", existing.required_evidence_desc)
                if eff_dt:
                    existing.effective_date = eff_dt
                if rev_dt:
                    existing.review_date = rev_dt
                policy_code_map[item["policy_code"]] = existing.id
        db.commit()
        print(f"      Seeded {len(policy_data)} Corporate Policies.")

        # 4. Seed Ground Truth Policy-to-Control Mappings
        print("[4/5] Seeding Human-Reviewed Ground Truth Mappings...")
        mapping_data = load_json("ground_truth_mappings.json")
        mapping_map = {} # (policy_code, control_id) -> mapping_id
        for item in mapping_data:
            pol_id = policy_code_map.get(item["policy_code"])
            if not pol_id:
                continue
            existing = db.query(PolicyMapping).filter_by(
                policy_id=pol_id,
                control_id=item["control_id"]
            ).first()
            if not existing:
                mp = PolicyMapping(
                    policy_id=pol_id,
                    control_id=item["control_id"],
                    mapping_status=item["mapping_status"],
                    is_ground_truth=item["is_ground_truth"],
                    confidence_score=item["confidence_score"],
                    rationale=item["rationale"],
                    reviewer=item.get("reviewer"),
                    reviewed_at=parse_iso(item.get("reviewed_at")),
                    review_notes=item.get("review_notes"),
                )
                db.add(mp)
                db.flush()
                mapping_map[(item["policy_code"], item["control_id"])] = mp.id
            else:
                existing.mapping_status = item.get("mapping_status", existing.mapping_status)
                existing.is_ground_truth = item.get("is_ground_truth", existing.is_ground_truth)
                existing.confidence_score = item.get("confidence_score", existing.confidence_score)
                existing.rationale = item.get("rationale", existing.rationale)
                mapping_map[(item["policy_code"], item["control_id"])] = existing.id
        db.commit()
        print(f"      Seeded {len(mapping_data)} Ground Truth Mappings.")

        # 5. Seed Test Definitions (Compliance-as-Code)
        print("[5/5] Seeding Compliance-as-Code Test Definitions...")
        test_data = load_json("test_definitions.json")
        seeded_tests = 0
        for item in test_data:
            pol_code = item["policy_code"]
            mapping_id = None
            for (p_code, c_id), m_id in mapping_map.items():
                if p_code == pol_code:
                    mapping_id = m_id
                    break
            
            if not mapping_id:
                continue

            existing = db.query(TestDefinition).filter_by(test_id=item["test_id"]).first()
            if not existing:
                test_def = TestDefinition(
                    test_id=item["test_id"],
                    mapping_id=mapping_id,
                    tier=item["tier"],
                    is_required=item.get("is_required", True),
                    is_behavioral=item.get("is_behavioral", False),
                    target_type=item["target_type"],
                    name=item["name"],
                    description=item["description"],
                    max_ttl_hours=item["max_ttl_hours"],
                    test_spec=item["test_spec"],
                )
                db.add(test_def)
                seeded_tests += 1
            else:
                existing.is_required = item.get("is_required", True)
                existing.is_behavioral = item.get("is_behavioral", False)
                existing.name = item["name"]
                existing.description = item["description"]
                existing.test_spec = item["test_spec"]
        db.commit()
        print(f"      Seeded {seeded_tests} Test Definitions (Tier 1 & Tier 2).")

        print("=" * 60)
        print("Database Initialization and Seeding Complete!")
        print("=" * 60)

    except Exception as e:
        db.rollback()
        print(f"Error during seeding: {e}")
        raise e
    finally:
        db.close()

seed_all = seed_database

if __name__ == "__main__":
    seed_database()
