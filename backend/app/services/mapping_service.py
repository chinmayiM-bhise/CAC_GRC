"""
CAC-GRC Semantic Policy Mapping Service.

Implements Dimension 1: Policy-to-Framework Control Alignment using a
Curated Cybersecurity/GRC Domain Concept Lexicon combined with Filtered TF-IDF
Cosine Similarity (Hybrid Matcher).

Key Architectural Guarantees:
1. Bridging the Vocabulary Gap: Maps operational technical language (e.g., sudo, pull request,
   TLS daemon) to formal governance standards (e.g., least privilege, change management,
   transmission confidentiality).
2. Human-in-the-Loop Review: Suggested mappings default strictly to 'SUGGESTED' with
   is_ground_truth=False. Algorithmic similarity scores NEVER silently certify regulatory
   equivalence or runtime control effectiveness.
3. Strict Role-Gated Approval: Approving a suggested mapping to 'HUMAN_APPROVED' requires
   auditor or administrator credentials with an append-only audit trail.
"""

import re
import math
from typing import List, Set, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.policy import Policy
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.audit_log import AuditLog
from app.models.base import utc_now
from app.auth import ROLE_AUDITOR, ROLE_ADMIN


# -------------------------------------------------------------------------
# CURATED GRC DOMAIN LEXICON & TAXONOMY
# -------------------------------------------------------------------------
GRC_CONCEPT_RULES = [
    {
        "concept": "CONCEPT_ACCOUNT_LOCKOUT",
        "patterns": [
            r"\blockout\b", r"\block\b", r"\blocked\b", r"\bfailed authentication\b",
            r"\bconsecutive failed\b", r"\binvalid logon\b", r"\bunsuccessful logon\b",
            r"\bbrute[\s-]force\b", r"\bfailed attempts\b"
        ],
        "weight": 1.5
    },
    {
        "concept": "CONCEPT_LEAST_PRIVILEGE",
        "patterns": [
            r"\bleast privilege\b", r"\bsuperuser\b", r"\broot\b", r"\bsudo\b",
            r"\belevation\b", r"\bprivileged access\b", r"\bprivilege elevation\b",
            r"\badministrative operations\b", r"\badministrative access\b",
            r"\bindividualized accounts\b"
        ],
        "weight": 1.5
    },
    {
        "concept": "CONCEPT_AUTHENTICATION",
        "patterns": [
            r"\bauthentication\b", r"\bauthenticator\b", r"\bcredentials\b",
            r"\bpassword complexity\b", r"\bsecure authentication\b",
            r"\bauthentication information\b"
        ],
        "weight": 1.2
    },
    {
        "concept": "CONCEPT_AUDIT_LOGGING",
        "patterns": [
            r"\baudit logging\b", r"\baudit log\b", r"\baudit record\b", r"\bauditable events\b",
            r"\bevent logging\b", r"\baudit generation\b", r"\blogs\b", r"\blogging\b",
            r"\btamper[\s-]evident audit\b"
        ],
        "weight": 1.5
    },
    {
        "concept": "CONCEPT_CRYPTOGRAPHY_TRANSIT",
        "patterns": [
            r"\btls\b", r"\bssl\b", r"\bcryptograph\w*\b", r"\bencrypt\w*\b",
            r"\btransmission confidentiality\b", r"\bdata in transit\b", r"\bunencrypted\b",
            r"\bsecure transmission\b"
        ],
        "weight": 1.5
    },
    {
        "concept": "CONCEPT_CHANGE_MANAGEMENT",
        "patterns": [
            r"\bbranch protection\b", r"\bpull request\b", r"\bpeer review\b",
            r"\bchange management\b", r"\bchange control\b", r"\bconfiguration change\b",
            r"\bdirect pushes\b", r"\bmerging\b", r"\bcode review\b", r"\bpre-deployment review\b"
        ],
        "weight": 1.5
    },
    {
        "concept": "CONCEPT_NETWORK_SECURITY",
        "patterns": [
            r"\bnetwork perimeter\b", r"\brouting perimeter\b", r"\bfirewall\w*\b",
            r"\bnetwork security\b", r"\bnetwork devices\b"
        ],
        "weight": 1.5
    }
]

# Stopwords that frequently dilute GRC similarity calculations across disparate domains
GRC_STOPWORDS = {
    "organization", "information", "system", "systems", "shall", "must", "all",
    "accordance", "relevant", "including", "defined", "implemented", "established",
    "management", "procedures", "across", "within", "during", "specified", "topic",
    "specific", "rules", "technologies", "capable", "capability", "appropriate"
}


# -------------------------------------------------------------------------
# TEXT NORMALIZATION AND CONCEPT EXTRACTION
# -------------------------------------------------------------------------
def extract_concepts(text: str) -> Set[str]:
    """Identifies canonical cybersecurity and GRC domain concepts in free text."""
    text_lower = text.lower()
    concepts = set()
    for rule in GRC_CONCEPT_RULES:
        for pat in rule["patterns"]:
            if re.search(pat, text_lower):
                concepts.add(rule["concept"])
                break
    return concepts


def tokenize(text: str) -> List[str]:
    """Basic alphanumeric tokenization (words >= 3 characters)."""
    return re.findall(r'\b[a-zA-Z0-9]{3,}\b', text.lower())


def tokenize_filtered(text: str) -> List[str]:
    """Tokenizes text while filtering high-frequency generic compliance stopwords."""
    raw = tokenize(text)
    return [t for t in raw if t not in GRC_STOPWORDS]


# -------------------------------------------------------------------------
# SIMILARITY SCORING ALGORITHMS
# -------------------------------------------------------------------------
def compute_tf_idf_similarity(
    text1: str,
    text2: str,
    corpus: List[str],
    filter_stopwords: bool = False,
    df_cache: Optional[Dict[str, int]] = None
) -> float:
    """Computes TF-IDF cosine similarity between two texts against a reference corpus."""
    tok_fn = tokenize_filtered if filter_stopwords else tokenize
    tokens1 = tok_fn(text1)
    tokens2 = tok_fn(text2)
    vocab = list(set(tokens1 + tokens2))
    if not vocab:
        return 0.0

    N = len(corpus) + 1
    df = {}
    if df_cache is not None:
        for word in vocab:
            df[word] = df_cache.get(word, 0) + 1
    else:
        tokenized_docs = [set(tok_fn(d)) if isinstance(d, str) else d for d in corpus]
        for word in vocab:
            count = sum(1 for doc_words in tokenized_docs if word in doc_words)
            df[word] = count + 1

    v1 = []
    v2 = []
    for word in vocab:
        idf = math.log(N / df[word]) + 1
        tf1 = tokens1.count(word) / (len(tokens1) or 1)
        tf2 = tokens2.count(word) / (len(tokens2) or 1)
        v1.append(tf1 * idf)
        v2.append(tf2 * idf)

    dot = sum(a * b for a, b in zip(v1, v2))
    mag1 = math.sqrt(sum(a * a for a in v1))
    mag2 = math.sqrt(sum(b * b for b in v2))
    if mag1 == 0 or mag2 == 0:
        return 0.0
    return min(1.0, max(0.0, dot / (mag1 * mag2)))


def compute_keyword_overlap(text1: str, text2: str) -> float:
    """Computes Jaccard keyword overlap similarity between two token sets."""
    set1 = set(tokenize(text1))
    set2 = set(tokenize(text2))
    if not set1 or not set2:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return min(1.0, max(0.0, intersection / union))


def compute_hybrid_similarity(
    text1: str,
    text2: str,
    corpus: List[str],
    alpha: float = 0.5,
    df_cache: Optional[Dict[str, int]] = None
) -> float:
    """
    Computes hybrid semantic similarity combining domain concept overlap and filtered TF-IDF cosine:
        Score = alpha * Concept_Jaccard + (1 - alpha) * Filtered_TFIDF_Cosine
    Calibrated strictly on development data: alpha=0.5, threshold=0.20.
    """
    if not text1.strip() or not text2.strip():
        return 0.0

    # 1. Domain Concept Jaccard
    c1 = extract_concepts(text1)
    c2 = extract_concepts(text2)
    if c1 or c2:
        concept_sim = len(c1 & c2) / len(c1 | c2)
    else:
        concept_sim = 0.0

    # 2. Filtered TF-IDF Cosine
    tfidf_sim = compute_tf_idf_similarity(text1, text2, corpus, filter_stopwords=True, df_cache=df_cache)

    # 3. Hybrid Combination
    score = (alpha * concept_sim) + ((1.0 - alpha) * tfidf_sim)
    return min(1.0, max(0.0, score))


# -------------------------------------------------------------------------
# MAPPING SERVICE CLASS
# -------------------------------------------------------------------------
class MappingService:
    CALIBRATED_THRESHOLD = 0.20
    CALIBRATED_ALPHA = 0.5

    @classmethod
    def build_corpus(cls, db: Session) -> Tuple[Dict[str, str], Dict[str, str], List[str]]:
        """Constructs reference text dictionaries and corpus from policies and controls."""
        policies = {p.policy_code: f"{p.title} {p.description}" for p in db.query(Policy).all()}
        controls = {c.control_id: f"{c.title} {c.description}" for c in db.query(FrameworkControl).all()}
        corpus = list(policies.values()) + list(controls.values())
        return policies, controls, corpus

    @classmethod
    def suggest_mappings(
        cls,
        db: Session,
        policy_code: Optional[str] = None,
        threshold: float = CALIBRATED_THRESHOLD,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Generates candidate policy-to-control mappings using the hybrid semantic matcher.
        Guarantees that all suggestions are marked with 'SUGGESTED' status and is_ground_truth=False.
        Preserves human review by requiring auditor signoff before certification.
        """
        policy_query = db.query(Policy)
        if policy_code:
            policy_query = policy_query.filter(Policy.policy_code == policy_code)
        policies = policy_query.all()

        all_controls = db.query(FrameworkControl).all()
        _, _, corpus = cls.build_corpus(db)

        # Precompute filtered DF cache once across the reference corpus for high-performance inference
        tokenized_corpus = [set(tokenize_filtered(doc)) for doc in corpus]
        df_cache: Dict[str, int] = {}
        for doc_words in tokenized_corpus:
            for w in doc_words:
                df_cache[w] = df_cache.get(w, 0) + 1

        suggestions = []
        for pol in policies:
            pol_text = f"{pol.title} {pol.description}"
            pol_concepts = extract_concepts(pol_text)

            candidate_scores = []
            for ctrl in all_controls:
                ctrl_text = f"{ctrl.title} {ctrl.description}"
                ctrl_concepts = extract_concepts(ctrl_text)

                score = compute_hybrid_similarity(
                    pol_text,
                    ctrl_text,
                    corpus,
                    alpha=cls.CALIBRATED_ALPHA,
                    df_cache=df_cache
                )
                if score >= threshold:
                    matched_concepts = sorted(list(pol_concepts & ctrl_concepts))

                    # Check if mapping already exists in database
                    existing_map = db.query(PolicyMapping).filter(
                        PolicyMapping.policy_id == pol.id,
                        PolicyMapping.control_id == ctrl.control_id
                    ).first()

                    mapping_id = existing_map.id if existing_map else None
                    current_review = existing_map.mapping_status if existing_map else None

                    candidate_scores.append({
                        "mapping_id": mapping_id,
                        "current_review_status": current_review,
                        "policy_id": pol.id,
                        "policy_code": pol.policy_code,
                        "policy_title": pol.title,
                        "control_id": ctrl.control_id,
                        "control_title": ctrl.title,
                        "framework_name": ctrl.framework_name,
                        "confidence_score": round(score, 4),
                        "mapping_status": "SUGGESTED",
                        "is_ground_truth": False,
                        "requires_human_review": True,
                        "matched_concepts": matched_concepts,
                        "rationale": (
                            f"Hybrid semantic similarity score {score:.4f} exceeds threshold {threshold:.2f}. "
                            f"Matched concepts: {', '.join(matched_concepts) if matched_concepts else 'None'}. "
                            f"Requires independent human auditor review before regulatory adoption."
                        )
                    })

            # Sort by highest score first
            candidate_scores.sort(key=lambda x: x["confidence_score"], reverse=True)
            suggestions.extend(candidate_scores[:limit])

        return suggestions

    @classmethod
    def review_mapping(
        cls,
        db: Session,
        mapping_id: str,
        new_status: str,
        actor: str,
        reviewer_role: str,
        rationale: Optional[str] = None,
        reviewer: Optional[str] = None
    ) -> PolicyMapping:
        """
        Auditor review endpoint for policy mappings.
        Ensures that regulatory equivalence cannot be certified algorithmically.
        """
        valid_statuses = {"HUMAN_APPROVED", "APPROVED", "REJECTED", "DRAFT", "SUGGESTED", "PROPOSED", "REVIEWED"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid mapping status '{new_status}'. Must be one of {valid_statuses}")

        if new_status in ["HUMAN_APPROVED", "APPROVED", "REJECTED"] and (not rationale or not rationale.strip()):
            raise ValueError("Review notes (rationale) are required when approving or rejecting a policy mapping.")

        if new_status in ["HUMAN_APPROVED", "APPROVED"] and reviewer_role not in [ROLE_AUDITOR, ROLE_ADMIN]:
            raise PermissionError("Only an AUDITOR or ADMIN can certify a mapping as APPROVED / HUMAN_APPROVED.")

        mapping = db.query(PolicyMapping).filter(PolicyMapping.id == mapping_id).first()
        if not mapping:
            raise ValueError(f"PolicyMapping with id '{mapping_id}' not found.")

        old_status = mapping.mapping_status
        mapping.mapping_status = new_status
        mapping.reviewer = reviewer or actor
        mapping.reviewed_at = utc_now()
        if rationale:
            mapping.rationale = rationale
            mapping.review_notes = rationale

        if new_status in ["HUMAN_APPROVED", "APPROVED"]:
            mapping.is_ground_truth = True

        # Record privileged action in audit trail
        audit_entry = AuditLog(
            actor=actor,
            action="REVIEW_POLICY_MAPPING",
            target=f"mapping:{mapping.id}",
            outcome="SUCCESS",
            details={
                "policy_id": mapping.policy_id,
                "control_id": mapping.control_id,
                "previous_status": old_status,
                "new_status": new_status,
                "reviewer_role": reviewer_role,
                "rationale": rationale
            }
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(mapping)
        return mapping

    @classmethod
    def delete_mapping(cls, db: Session, mapping_id: str, actor: str, role: str) -> None:
        """Deletes a policy-to-control mapping with audit history."""
        mapping = db.query(PolicyMapping).filter(PolicyMapping.id == mapping_id).first()
        if not mapping:
            raise ValueError(f"PolicyMapping with id '{mapping_id}' not found.")

        policy_id = mapping.policy_id
        control_id = mapping.control_id

        audit_entry = AuditLog(
            actor=actor,
            action="DELETE_POLICY_MAPPING",
            target=f"mapping:{mapping_id}",
            outcome="SUCCESS",
            details={
                "policy_id": policy_id,
                "control_id": control_id,
                "previous_status": mapping.mapping_status,
                "deleted_by_role": role
            }
        )
        db.add(audit_entry)
        db.delete(mapping)
        db.commit()

    @classmethod
    def get_coverage_report(cls, db: Session) -> Dict[str, Any]:
        """
        Computes multi-dimensional coverage metrics:
        1. Catalog coverage (total controls in official catalog)
        2. Policy mapping coverage (controls mapped to >= 1 policy)
        3. Mapping validation (controls with approved mappings)
        4. Technical assessment coverage (controls with automated test runner specifications)
        """
        from app.models.test_definition import TestDefinition

        all_controls = db.query(FrameworkControl).all()
        all_policies = db.query(Policy).all()
        all_mappings = db.query(PolicyMapping).all()
        all_tests = db.query(TestDefinition).all()

        # Build mapping and test associations
        control_map: Dict[str, FrameworkControl] = {c.control_id: c for c in all_controls}
        policy_map: Dict[str, Policy] = {p.id: p for p in all_policies}

        # Controls with automated test definitions
        test_mapping_ids = {t.mapping_id for t in all_tests}
        tested_control_ids = {m.control_id for m in all_mappings if m.id in test_mapping_ids}

        # Policy coverage tracking
        policies_with_mappings = {m.policy_id for m in all_mappings}
        policies_without_mappings = [p.policy_code for p in all_policies if p.id not in policies_with_mappings]

        # Mappings by status
        mappings_by_status: Dict[str, int] = {}
        for m in all_mappings:
            st = m.mapping_status or "PROPOSED"
            mappings_by_status[st] = mappings_by_status.get(st, 0) + 1

        # Control sets
        mapped_control_ids = {m.control_id for m in all_mappings}
        approved_mapped_control_ids = {
            m.control_id for m in all_mappings
            if m.mapping_status in ["APPROVED", "HUMAN_APPROVED"]
        }
        unreviewed_control_ids = sorted(list({
            cid for cid in mapped_control_ids
            if cid not in approved_mapped_control_ids
        }))
        unmapped_control_ids = sorted(list({
            c.control_id for c in all_controls
            if c.control_id not in mapped_control_ids
        }))

        def build_framework_metrics(ctrl_list: List[FrameworkControl]) -> Dict[str, Any]:
            total = len(ctrl_list)
            base = sum(1 for c in ctrl_list if not getattr(c, "is_enhancement", False) and getattr(c, "status", "ACTIVE") == "ACTIVE")
            enh = sum(1 for c in ctrl_list if getattr(c, "is_enhancement", False) and getattr(c, "status", "ACTIVE") == "ACTIVE")
            withdrawn = sum(1 for c in ctrl_list if getattr(c, "status", "ACTIVE") == "WITHDRAWN")

            c_ids = {c.control_id for c in ctrl_list}
            mapped = len(c_ids & mapped_control_ids)
            unmapped = total - mapped
            approved = len(c_ids & approved_mapped_control_ids)
            unreviewed = len(c_ids & set(unreviewed_control_ids))
            tested = len(c_ids & tested_control_ids)

            return {
                "total_catalog_controls": total,
                "base_controls_count": base,
                "enhancements_count": enh,
                "withdrawn_controls_count": withdrawn,
                "mapped_controls_count": mapped,
                "unmapped_controls_count": unmapped,
                "approved_mapped_controls_count": approved,
                "unreviewed_mapped_controls_count": unreviewed,
                "technically_assessed_controls_count": tested,
                "mapping_coverage_pct": round((mapped / total * 100), 2) if total else 0.0,
                "approved_coverage_pct": round((approved / total * 100), 2) if total else 0.0,
                "technical_assessment_pct": round((tested / total * 100), 2) if total else 0.0,
            }

        iso_controls = [c for c in all_controls if c.framework_name == "ISO_27001_2022"]
        nist_controls = [c for c in all_controls if c.framework_name == "NIST_SP_800_53_R5"]

        return {
            "iso_27001": build_framework_metrics(iso_controls),
            "nist_800_53": build_framework_metrics(nist_controls),
            "combined": build_framework_metrics(all_controls),
            "mappings_by_status": mappings_by_status,
            "unmapped_control_ids": unmapped_control_ids,
            "unreviewed_control_ids": unreviewed_control_ids,
            "policies_without_mappings": sorted(policies_without_mappings),
        }
