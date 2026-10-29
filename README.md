# CAC-GRC: Continuous Automated Compliance & Evidence-Weighted Scoring

> Enterprise SaaS platform for continuous security assurance, policy-to-control mapping, agentless assessment, and evidence integrity across **ISO/IEC 27001:2022** and **NIST SP 800-53 Rev 5**.

---

## 1. Core Research & Architectural Contributions

1. **Decoupled Dual Evaluation:**
   * **Dimension 1 (Mapping Validity):** Evaluates whether an internal corporate policy aligns accurately with regulatory clauses using semantic similarity (TF-IDF cosine) and token-overlap baselines against human-curated ground truth.
   * **Dimension 2 (Control Effectiveness via EW-CES):** Evaluates whether the target systems satisfy approved security requirements at runtime.
2. **Evidence-Weighted Control Effectiveness Scoring (EW-CES):**
   Replaces arbitrary compliance percentages with an explainable 4-state confidence model:
   - **`VERIFIED_EFFECTIVE`**: Required configuration checks and behavioral challenge tests passed with fresh, integrity-verified evidence.
   - **`CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED`**: Static configurations conform to policy, but behavioral runtime validation has not been performed or is absent.
   - **`DEFICIENT`**: One or more required checks have confirmed operational failures at runtime.
   - **`UNKNOWN`**: Evidence is missing, expired past its Time-To-Live ($TTL$), conflicting, or ledger hash integrity is compromised.
3. **Agentless Out-of-Band Testing:**
   Evaluates Linux operating systems (PAM, `auditd`, SSH), PostgreSQL databases (least privilege, TLS enforcement), and Gitea source repositories (branch protection) via native protocols without maintaining custom software agents on targets.
4. **Verifiable Hash-Linked Evidence Ledger:**
   Preserves evidence integrity using canonical SHA-256 serialization and an unbroken hash chain linking each observation to the preceding block.
5. **Database-Persisted Chaos & Drift Engine:**
   Persists simulated and live target mutations across separate CLI processes and sessions, requiring pre/post verification to eliminate synthetic false positives.

---

## 2. Platform Architecture

```text
CAC GRC/
├── AUDIT_REPORT.md                         # Technical baseline and vulnerability audit
├── IMPLEMENTATION_PLAN.md                  # Detailed phase-by-phase implementation plan
├── DEVELOPMENT_PLAN.md                     # Architectural blueprint & roadmap
├── LEDGER_THREAT_MODEL.md                  # Cryptographic evidence ledger threat model
├── README.md                               # Quickstart and overview
│
├── lab/                                    # Target Lab Environment
│   ├── docker-compose.yml                  # PostgreSQL Target (port 5433) & Gitea Target (port 3000)
│   ├── db-init/init.sql                    # Enterprise database initialization
│   └── vm-setup/                           # Linux VM (Ubuntu Server LTS) Target
│       ├── bootstrap.sh                    # Automated PAM faillock, auditd, and SSH setup
│       └── Vagrantfile                     # Automated VirtualBox VM deployment
│
├── backend/                                # Central GRC Controller (Python / FastAPI)
│   ├── requirements.txt                    # Project dependencies
│   ├── app/
│   │   ├── main.py                         # Enterprise REST API & UI router
│   │   ├── config.py                       # Lab endpoints and credentials (least-privilege)
│   │   ├── database.py                     # SQLAlchemy session & SQLite/Postgres engine
│   │   ├── migrate.py                      # Incremental schema migration engine
│   │   ├── models/                         # ORM Models (Policy, Control, Mapping, Tests, Evidence, Scores, Findings, Assessments, Chaos, AuditLog)
│   │   ├── schemas/                        # Pydantic v2 validation schemas
│   │   ├── engine/
│   │   │   ├── runner/                     # Agentless Runner (SSHRunner, DBRunner, GitRunner)
│   │   │   ├── ledger/                     # Cryptographic Vault (SHA-256 Merkle chain)
│   │   │   ├── scoring/                    # EW-CES 4-State Classifier & Temporal Decay
│   │   │   └── orchestrator.py             # Assessment Orchestrator
│   │   ├── chaos/                          # Database-Persisted Chaos Engine
│   │   │   ├── mutations.py                # Drift mutations (SIMULATED & LIVE_LAB_MUTATION)
│   │   │   └── cli.py                      # Multi-process CLI tool
│   │   └── static/
│   │       └── index.html                  # Enterprise GRC SaaS Dashboard (Sprinto/Scrut style)
│   └── tests/
│       └── test_platform.py                # Automated test suite (14/14 passing)
│
└── experiments/                            # Reproducible Research Experiments
    ├── benchmark_mapping_validity.py       # Dimension 1: TF-IDF vs Jaccard against Ground Truth
    └── benchmark_ew_ces_vs_binary.py       # Dimension 2: 10-Condition EW-CES vs Binary Scoring
```

---

## 3. Quickstart & Verification Commands

### Step 1: Start the Platform Server & Enterprise Dashboard
```powershell
$env:PYTHONPATH="backend"
python -m uvicorn app.main:app --reload --port 8000
```
Open **[http://localhost:8000/dashboard](http://localhost:8000/dashboard)** in your browser.
* Persistent enterprise sidebar: Overview, Framework Controls, Policy Mappings, Findings & Remediation, Evidence Vault, Monitored Assets, Assessment History, Reports, and Lab Drift Experiments.
* Click any control to open the slide-over **Control Detail Drawer**.

### Step 2: Run Automated Test Suite
Pytest is preconfigured via `pytest.ini` with `pythonpath = backend` and `testpaths = backend/tests`. Run directly from repository root in PowerShell or CMD:
```powershell
python -m pytest -v
```
*(No manual `$env:PYTHONPATH` configuration required. All test suites run cleanly on Windows).*

### Step 3: Run Research Experiments
```powershell
# Run Dimension 1 Empirical Mapping Benchmark:
python experiments/benchmark_mapping_validity.py

# Run Dimension 2 EW-CES vs Binary Scoring (10 Conditions):
python experiments/benchmark_ew_ces_vs_binary.py
```

### Step 4: Use the Database-Persisted Chaos CLI
```powershell
# Check active drifts across processes:
python backend/app/chaos/cli.py --status

# Inject simulated drift:
python backend/app/chaos/cli.py --inject pam-lockout-bypass --mode SIMULATED

# Restore baseline:
python backend/app/chaos/cli.py --restore
```
