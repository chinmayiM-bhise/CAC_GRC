import argparse
import json
import sys
from pathlib import Path

# Ensure backend root is on path
backend_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.chaos.mutations import ChaosInjector, DRIFT_CATALOG

def main():
    parser = argparse.ArgumentParser(description="CAC-GRC Chaos & Compliance Drift Injector CLI (Database-Persisted)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List all available drift scenarios")
    group.add_argument("--inject", type=str, metavar="DRIFT_ID", help="Inject a specific drift scenario")
    group.add_argument("--restore", action="store_true", help="Restore all environments to compliant baseline")
    group.add_argument("--status", action="store_true", help="Show currently active drifts in database")
    group.add_argument("--experiment", type=str, metavar="DRIFT_ID", help="Execute the complete 8-phase verifiable drift & recovery experiment")

    parser.add_argument(
        "--mode",
        choices=["SIMULATED", "LIVE_LAB_MUTATION"],
        default="SIMULATED",
        help="Execution mode (default: SIMULATED for offline testing; LIVE_LAB_MUTATION for real lab targets)"
    )
    parser.add_argument("--actor", type=str, default="CLI_USER", help="Actor identity for audit logs")

    args = parser.parse_args()

    if args.list:
        print("\n=== AVAILABLE CHAOS DRIFT SCENARIOS ===")
        for d_id, info in DRIFT_CATALOG.items():
            print(f"[{d_id}]")
            print(f"  Target:                  {info['target']}")
            print(f"  Live Mutation Supported: {info.get('live_mutation_supported', False)}")
            print(f"  Affected Controls:       {', '.join(info['affected_controls'])}")
            print(f"  Affected Tests:          {', '.join(info['affected_tests'])}")
            print(f"  Description:             {info['description']}\n")

    elif args.inject:
        try:
            res = ChaosInjector.inject_drift(args.inject, mode=args.mode, actor=args.actor)
            print(f"\n[+] DRIFT INJECTED: {args.inject} (Mode: {args.mode})")
            print(f"    Target:            {DRIFT_CATALOG[args.inject]['target']}")
            print(f"    Affected Controls: {', '.join(res['affected_controls'])}")
            print(f"    Affected Tests:    {', '.join(res['affected_tests'])}")
            print(f"    Status:            {res['status']}")
            print("Drift is persisted in the database. Assessment runs will reflect this state.\n")
        except ConnectionError as ce:
            print(f"\n[-] LIVE MUTATION FAILED: {ce}\n")
            sys.exit(1)
        except ValueError as ve:
            print(f"\n[-] VALIDATION ERROR: {ve}\n")
            sys.exit(1)
        except Exception as e:
            print(f"\n[-] ERROR: {e}\n")
            sys.exit(1)

    elif args.restore:
        res = ChaosInjector.restore_baseline(actor=args.actor)
        print(f"\n[+] BASELINE RESTORED: Cleared and marked {res['cleared_drifts_count']} active drifts as RESTORED in database.\n")

    elif args.status:
        active = ChaosInjector.list_active_drifts()
        if not active:
            print("\n[i] All targets are in COMPLIANT BASELINE (0 active drifts in database).\n")
        else:
            print(f"\n=== ACTIVE DRIFTS IN DATABASE ({len(active)}) ===")
            for item in active:
                print(f"  - [{item['drift_id']}]")
                print(f"    Mode:        {item['drift_type']}")
                print(f"    Target:      {item['target_type']}")
                print(f"    Injected At: {item['injected_at']}")
                print(f"    Actor:       {item['actor']}")
                print(f"    Controls:    {', '.join(item['affected_controls'])}")
            print()

    elif args.experiment:
        print(f"\n[*] EXECUTING 8-PHASE VERIFIABLE DRIFT EXPERIMENT: {args.experiment} (Mode: {args.mode})...")
        res = ChaosInjector.execute_full_lifecycle_experiment(args.experiment, mode=args.mode, actor=args.actor)
        for ev in res.get("events", []):
            st = ev["status"]
            icon = "[+]" if st == "SUCCESS" else "[-]"
            print(f"  {icon} [{ev['phase']}] ({st}): {ev['details']}")
        print(f"\n[+] EXPERIMENT RESULT: Lifecycle Completed = {res['lifecycle_completed']}, Detection Verified = {res.get('detection_verified')}, Recovery Verified = {res.get('recovery_verified')}\n")

if __name__ == "__main__":
    main()
