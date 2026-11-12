# SoT Validator (`sot-validator`)

Inventory Validation System for Legacy Network Source of Truth.

## Overview

`sot-validator` extracts site and equipment records in controlled batches from an internal legacy Source of Truth (SoT) system and validates whether recorded network devices, IP addresses, and network-attached equipment (servers, SANs, UPSs, VMs, etc.) are still in active use.

### Phase 1 Objectives
- **Read-Only Batch Extraction**: Safely extract `Site` hierarchies (Network Devices, Ports, VLANs/Subnets, IP Addresses + ARP discovery data, Network-Attached Equipment) via **GET-only Web Scraping** and/or **SQL / CSV Exports**, with per-site batching and local snapshot caching.
- **Multi-Signal Validation**: Collect and correlate activity signals tailored to our environment (~100 sites on `10.x.0.0/16` with ~10 `/24` subnets per site):
  - Recent ARP entries and last-seen timestamps from SoT / routers
  - **Extreme Networks** switch port status / link state / PoE draw
  - Scoped ICMP reachability (targeting assigned IPs / active `/24` blocks, never full `/16` sweeps)
  - SNMP / HTTPS reachability for **Extreme** switches and **APC** UPS management cards
  - Multi-instance **VMware vCenter** power state & Guest Tools correlation (~90% Windows VM footprint)
- **Actionable Classification**: Classify each inventory item into one of four states:
  - `Confirmed Active`
  - `Stale / Likely Unused`
  - `Unreachable / Needs Manual Review`
  - `Insufficient Data`
- **Extensible Architecture**: Produce structured reports (JSON/CSV/Markdown/HTML5) designed to feed automated flagging or cleanup workflows inside the Source of Truth.

### Phase 2 Objectives (Historical Tracking, Stale Quarantine & Gated Remediation)
- **Validation History & Streak Ledger (`HistoryStore`)**: Track multi-run validation outcomes in SQLite/JSON, recording `consecutive_stale_runs`, `stale_duration_days`, state-transition drift (`NEWLY_STALE`, `NEWLY_UNREACHABLE`, `RESURRECTED`, `RECOVERED`), and `/24` subnet IP utilization.
- **Quarantine Policy & Signed Approval Manifests (`QuarantineEngine`, `RemediationApprovalManifest`)**: Graduate items to cleanup eligibility only after meeting multi-run streak thresholds while exempting protected infrastructure, and export SHA-256 integrity-verified operator manifests.
- **Gated Remediation Executor & Rollback Journal (`RemediationExecutor`, `RollbackJournal`)**: Execute SHA-256-verified, operator-approved manifests (`--confirm-write` required for writes; `dry_run=True` by default), emitting paired `remediate.sql` and `rollback.sql` scripts and an append-only `remediation_journal.jsonl`.

### Phase 3 Objectives (Reverse Discovery Reconciliation, Fleet Campaigns & HTML Dashboard)
- **Reverse Discovery & Shadow IT Reconciler (`InventoryReconciler`)**: Compare live multi-vCenter, Extreme switch ARP/SNMP, and `/24` ICMP discovery feeds against SoT snapshots to surface `UNTRACKED_VM`, `UNTRACKED_IP`, `UNTRACKED_DEVICE`, and `ATTRIBUTE_MISMATCH` records, generating CSV and SQL onboarding templates.
- **Multi-Site Campaign Orchestrator & Alerting (`CampaignOrchestrator`, `AlertSink`)**: Run rolling validation waves across site cohorts with WAN/collector outage circuit breakers and structured JSON/Slack/Teams webhook alerts.
- **Interactive HTML Operations Dashboard (`HtmlDashboardGenerator`)**: Produce a self-contained, zero-CDN-dependency HTML5 dashboard (`validation_dashboard.html`) with KPI cards, `/24` subnet utilization bars, client-side search/filter controls, quarantine queues, and untracked asset tables.

### Phase 4 Objectives (Staged Extreme Networks Switch Port & PoE Reclamation)
- **LLDP/CDP Uplink & Infrastructure Guard (`LldpUplinkGuard`)**: Protect inter-switch uplinks, trunks, routers, wireless APs, APC UPS management interfaces, and VMware ESXi/vCenter host ports from automated port shutdown.
- **Staged ExtremeXOS & VOSS Port Reclamation Planner (`ExtremePortReclamationPlanner`)**: Generate dry-run port shutdown and PoE disable plans (`port_reclamation_plan.json`, `reclaim_ports_exos.xsf`, `reclaim_ports_voss.cli`) with 1-command rollback scripts and estimated PoE wattage savings.

### Phase 5 Objectives (Modern SoT Migration & Dual-Run Parity Validation)
- **Golden Inventory Exporter (`ModernSoTExporter`, `GoldenInventoryFilter`)**: Filter out stale/quarantined assets, merge approved Shadow IT discoveries, and export normalized NetBox and Nautobot JSON and per-entity CSV bundles (`sites.csv`, `vlans.csv`, `prefixes.csv`, `devices.csv`, `interfaces.csv`, `ip_addresses.csv`, `virtual_machines.csv`).
- **Dual-Run Parity & Site Cutover Scorecards (`ModernSoTParityValidator`, `SiteMigrationReadinessScorecard`)**: Detect `MISSING_IN_MODERN_SOT`, `STALE_LEAKED_TO_MODERN_SOT`, and `ATTRIBUTE_MISMATCH` discrepancies and compute `0.0-100.0` per-site readiness scores (`READY_FOR_CUTOVER`, `NEEDS_REMEDIATION`, `BLOCKED`).

### Phase 6 Objectives (APC UPS Fleet Health & ITSM Change-Ticket Governance)
- **APC UPS Battery & Environmental Health Evaluator (`ApcUpsHealthEvaluator`)**: Parse PowerNet-MIB OIDs (`1.3.6.1.4.1.318.*`) for battery replacement indicators (`BATTERY_REPLACEMENT_NEEDED`), low runtime, high temperature, high load, and utility line failure causes across all sites.
- **ITSM Change-Ticket & Approval Gate (`ItsmTicketPayloadBuilder`, `ItsmGateVerifier`)**: Generate ServiceNow, Jira, and generic webhook change tickets for quarantine, port reclamation, Shadow IT onboarding, and UPS hardware incidents, and enforce SHA-256 digest and ticket approval verification before remediation execution.

## Architecture

```
+------------------------+
| Legacy Source of Truth |  (Read-Only Web UI Scraper / SQL & CSV Exports)
+-----------+------------+
            |
            |  1. Controlled Batch Extraction (~100 Sites, 10.x.0.0/16 per Site)
            v
+------------------------+
|   Local Snapshot Store |  Normalized Domain Models (Site, Device, Port, Subnet, IP, Equipment)
+-----------+------------+
            |
            |  2. Signal Collectors (Pluggable Probes & Correlators)
            +---> Passive Signals: ARP cache age, SoT last-seen, Extreme switch port link state
            +---> VM Correlator: Multi-vCenter inventory (90% Windows VMs; power + Tools state)
            +---> Active Probes: /24-scoped ICMP ping, SNMP/HTTPS (Extreme switches & APC UPSs)
            v
+------------------------+
|  Classification Engine |  Weighted rules & confidence scoring
+-----------+------------+
            |
            |  3. Reporting, Quarantine, Reconciliation, Port Reclamation, Migration & ITSM
            v
+------------------------+
|   Validation Reports   |  JSON / CSV / Summary Markdown / Interactive HTML5 Dashboard
+------------------------+
```

## CLI Usage

Run the unified CLI via `python3 -m sot_validator <subcommand>`:

### Phase 1: Extraction, Validation & Reporting (`extract`, `validate`, `report`, `run`)

```bash
# End-to-end extraction, validation, and reporting with interactive HTML dashboard
PYTHONPATH=src python3 -m sot_validator run \
  --fixtures \
  --html-dashboard \
  --output-dir ./output

# Step-by-step workflow
PYTHONPATH=src python3 -m sot_validator extract --fixtures --snapshot-dir ./snapshots
PYTHONPATH=src python3 -m sot_validator validate --snapshot-dir ./snapshots --output-dir ./output
PYTHONPATH=src python3 -m sot_validator report \
  --input-dir ./output \
  --snapshot-dir ./snapshots \
  --output-dir ./output \
  --html-dashboard
```

### Phase 2: Historical Tracking, Quarantine & Gated Remediation (`history`, `quarantine`, `remediate`)

```bash
# Record validation runs into HistoryStore and inspect streaks / drift events
PYTHONPATH=src python3 -m sot_validator history \
  --db-path ./output/history.db \
  --record ./output/validation_results.json \
  --output-dir ./output

# Evaluate stale streaks against QuarantinePolicy and approve eligible entries
PYTHONPATH=src python3 -m sot_validator quarantine \
  --results-file ./output/validation_results.json \
  --db-path ./output/history.db \
  --snapshot-dir ./output/snapshots \
  --min-consecutive-stale-runs 3 \
  --min-stale-days 30 \
  --approve-all \
  --reviewer netops-lead \
  --output ./output/approval_manifest.json

# Preview SQL scripts in default dry-run mode
PYTHONPATH=src python3 -m sot_validator remediate \
  --manifest ./output/approval_manifest.json \
  --output-dir ./output

# Execute approved remediation in gated write mode and record rollback journal
PYTHONPATH=src python3 -m sot_validator remediate \
  --execute-approved-plan ./output/approval_manifest.json \
  --confirm-write \
  --output-dir ./output
```

### Phase 3: Reverse Discovery Reconciliation & Multi-Site Campaigns (`reconcile`, `campaign`)

```bash
# Reconcile live discovery feeds against SoT snapshots to detect untracked assets
PYTHONPATH=src python3 -m sot_validator reconcile \
  --csv-dir tests/fixtures/sot_samples/csv \
  --vcenter-json tests/fixtures/sot_samples/vcenter/vcenter_inventory.json \
  --snmp-fixture tests/fixtures/sot_samples/snmp/extreme_and_apc_walks.json \
  --output-dir ./output

# Run a rolling multi-site validation campaign with circuit breaker and alert output
PYTHONPATH=src python3 -m sot_validator campaign \
  --fixtures \
  --num-sites 4 \
  --cohort-size 2 \
  --webhook-format slack \
  --html-dashboard \
  --output-dir ./output
```

### Phase 4: Staged Extreme Networks Switch Port & PoE Reclamation (`reclaim-ports`)

```bash
PYTHONPATH=src python3 -m sot_validator reclaim-ports \
  --snapshot-dir ./output/snapshots \
  --db-path ./output/history.db \
  --dialect exos \
  --output-dir ./output
```

### Phase 5: Modern SoT Golden Export & Dual-Run Parity Scorecards (`export-modern-sot`, `parity-check`)

```bash
# Export validated golden inventory to NetBox JSON + per-entity CSV bundle
PYTHONPATH=src python3 -m sot_validator export-modern-sot \
  --snapshot-dir ./output/snapshots \
  --results-file ./output/validation_results.json \
  --target-platform netbox \
  --output-dir ./output

# Evaluate dual-run parity and site migration readiness scorecards
PYTHONPATH=src python3 -m sot_validator parity-check \
  --snapshot-dir ./output/snapshots \
  --golden-bundle ./output/netbox_golden_bundle.json \
  --modern-bundle ./output/netbox_golden_bundle.json \
  --output-dir ./output
```

### Phase 6: APC UPS Fleet Health & ITSM Change-Ticket Governance (`ups-health`, `itsm`)

```bash
# Evaluate APC UPS PowerNet-MIB health telemetry across sites
PYTHONPATH=src python3 -m sot_validator ups-health \
  --snapshot-dir ./output/snapshots \
  --snmp-fixture tests/fixtures/sot_samples/snmp/extreme_and_apc_walks.json \
  --output-dir ./output

# Generate, approve, and verify an ITSM change ticket
PYTHONPATH=src python3 -m sot_validator itsm \
  --manifest-file ./output/approval_manifest.json \
  --provider servicenow \
  --approval-status APPROVED \
  --output-dir ./output
```

## Development & Checks

Run the repository verification gate:

```bash
bash factory/checks.sh
```
