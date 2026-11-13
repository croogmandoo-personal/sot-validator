# AGENTS.md — SoT Validator (`sot-validator`)

## Project Overview

`sot-validator` is a batch-oriented, read-only inventory validation system for a legacy internal Network Source of Truth (SoT). It extracts site hierarchies (`Site`, `NetworkDevice`, `Port`, `VLAN/Subnet`, `IPAddress` + ARP discovery data, `Equipment`) in controlled batches, evaluates validation signals (ARP age, port link state, ICMP, SNMP/API, VM power state, last-seen timestamps), and classifies each record into:
- `Confirmed Active`
- `Stale / Likely Unused`
- `Unreachable / Needs Manual Review`
- `Insufficient Data`

## Repository Structure

- `src/sot_validator/` — Core Python package:
  - `models/` — Canonical domain models (`Site`, `NetworkDevice`, `Port`, `VLAN`, `Subnet`, `IPAddress`, `ArpEntry`, `Equipment`, `ValidationSignal`, `ValidationResult`).
  - `extraction/` — Read-only batch extractor (`BatchExtractor`, `SnapshotStore`, `SqlExportSoTClient`, `HtmlScraperSoTClient`, `FixtureSoTClient`) and the transport-level `ReadOnlyHttpGuard` (`guard.py`, GET/HEAD only); on-disk SQLite exports are opened `mode=ro` with `query_only` and ATTACH/DETACH denied.
  - `signals/` — Passive (`arp.py`, `port_state.py`, `last_seen.py`), `/24`-scoped active (`icmp.py`, `management.py`), multi-vCenter (`hypervisor.py`), Phase 4 AD/DNS/DHCP (`directory_dns.py`), Phase 6 APC UPS telemetry (`ups_health.py`), and Phase 10–12 Proxmox VE `:8006` / Docker-Portainer `:9000` guest & container (`proxmox_containers.py`) collectors.
  - `classifier/` — Deterministic multi-signal `ClassificationEngine` and `ClassificationPolicy`.
  - `reporting/` — Multi-format report generators (`JSON`, `CSV`, `Markdown`, and interactive `HTML` operations dashboard) and the fleet-wide site health scorecard (`fleet.py`: `FleetScorer`, `FleetScoreWeights`, `SiteScorecard`, `render_fleet_markdown`, `render_fleet_html`; the previous score is supplied by the caller and drift comes from `HistoryStore.detect_drift`; not yet wired into the CLI).
  - `history/` — Phase 2 multi-run validation history store, stale streak tracker, and state-drift analyzer. The SQLite ledger is schema-versioned via `PRAGMA user_version` with ordered `_MIGRATIONS` applied on open (newer databases are refused with `HistorySchemaVersionError`); add schema changes as new migrations, never by editing migration 1. Retention (`retention.py`: `RetentionPolicy`, `PruneReport`) runs through `HistoryStore.prune_runs`: an age limit and a per-site run-count limit select old runs, which are deleted with their `drift_events` rows in one `BEGIN IMMEDIATE` transaction only when `dry_run=False` (dry-run is the default); the newest run is always kept, `item_streaks` is never touched, and no migration is involved.
  - `remediation/` — Phase 1/2 dry-run action plans, quarantine graduation policies, SHA-256 signed approval manifests, gated remediation executor with rollback journal, and Phase 4 Extreme switch port/PoE reclamation planner (`port_reclamation.py`).
  - `reconciliation/` — Phase 3 reverse discovery & untracked inventory ("Shadow IT") reconciler and SoT import template generator.
  - `campaign/` — Phase 3 multi-site rolling campaign orchestrator, WAN/vCenter outage circuit breakers, and alert sinks.
  - `connectors/` — Phase 4 live pilot connector transports and pre-flight cutover validator.
  - `migration/` — Phase 5 NetBox / Nautobot golden inventory exporter and dual-run parity / readiness scorecard checker.
  - `itsm/` — Phase 6 ServiceNow / Jira change-ticket governance and approval synchronization sink.
  - `discovery/` — Phase 7 two-stage `/16`-to-`/24` live subnet discovery scanner (`SubnetDiscoveryScanner`, `DiscoveryConfig`, `DiscoveredHost`), `Site` snapshot bootstrapper, Phase 10–12 service banner and certificate fingerprinter (`fingerprinter.py`: `ServiceBannerFingerprinter`, `RawServiceBanner`, `DeviceFingerprint`), Phase 10–12 `monitor.py` snapshot diff engine and drift alert dispatcher (`SnapshotDiffEngine`, `SnapshotDiffReport`, `ScanDriftEvent`, `DriftAlertDispatcher`), and Phase 10–12 router ARP / DHCP lease table enricher (`router_tables.py`: `RouterArpDhcpCollector`, `RouterTableParsers`).
  - `curation/` — Phase 8 SQLite/JSON operator curation overlay store (`CurationStore`, `ItemEditPatch`, `AuditLogEntry`, `apply_curation_overlay`) with a SHA-256 hash-chained, append-only audit log (`prev_hash`/`entry_hash`, `BEGIN IMMEDIATE` appends), a chain verifier (`verify_audit_chain`, `AuditChainReport`), an external anchor via `CurationStore.export_chain_head()`, in-place legacy SQLite / JSON migration that appends a `migration` marker entry, and bulk CSV curation import (`bulk.py`: `parse_patch_csv`, `preview_patches`, `apply_patches`) over `record_type, record_id, field, new_value, reason` rows that previews each row as `change` / `no_op` / `conflict` / `invalid`, applies only on a matching SHA-256 confirm token in one transaction, and records a shared `batch_id` inside each audit entry's `changes`. Used by the workbench; not wired into the CLI.
  - `topology/` — Phase 9 network role & VLAN heuristic identifier (`NetworkRoleIdentifier`, `ConsolidatedRouter`), device type catalog & port range builder (`DeviceTypeCatalog`, `DevicePortManager`), hierarchical topology graph builder (`TopologyGraphBuilder`, `TopologyGraph`), Phase 10–12 switch FDB / Bridge-MIB MAC-to-port mapper with trunk/access inferrer (`fdb_mapper.py`: `FdbTableParser`, `SwitchFdbPortMapper`), and Phase 13–14 offline UPS power-dependency map, blast-radius and false-redundancy analysis with UPS risk ranking (`power.py`: `PowerMapLoader`, `PowerDependencyGraph`, `rank_power_risk`; not yet wired into the CLI).
  - `workbench/` — Phase 8/9 self-contained interactive HTTP Web Workbench server (`WorkbenchServer`, `WorkbenchState`, `WorkbenchSecurityConfig`), token-authenticated JSON REST API writes guarded by a same-origin check and a request-body cap, read-only `GET /api/topology`, token-guarded bulk CSV `POST /api/curation/preview` and `POST /api/curation/apply` (stateless confirm-token apply), hardening headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) on every response, and HTML5/SVG topology & inventory curation UI (`render_workbench_html`) with a Topology Map tab, a switch faceplate, and a Bulk Import tab (CSV upload, diff preview with status filter, confirm-token Apply).
  - `quality/` — Phase 13 SoT data-quality conflict detector (`DataQualityChecker`, `QualityFinding`) with deterministic duplicate IP/MAC, out-of-block IP, orphan-reference and hostname-mismatch rules, plus the `VlanConsistencyAuditor` (`vlan.py`) SoT-vs-FDB/router ARP/DHCP-scope VLAN rules (undocumented/unobserved VLANs, subnet and access-port VLAN mismatches, DHCP scope/subnet gaps), not yet wired into the CLI.
  - `lifecycle/` — TLS certificate expiry and weak-crypto inventory (`CertificateInventory`, `CertificateRecord`, `CertificateFinding`) with expiry buckets, self-signed/SHA-1/small-RSA/hostname-mismatch rules and JSON/Markdown report helpers, plus firmware lifecycle compliance (`firmware.py`: `FirmwareParser` for Extreme EXOS / Switch Engine / VOSS / Fabric Engine and APC NMC `sysDescr`, `compare_versions`, the operator JSON `LifecycleCatalog` of baselines and end-of-sale / end-of-support dates, `FirmwareComplianceChecker` over `FirmwareObservation` records giving `FirmwareFinding` statuses, and `generate_firmware_json_report` / `generate_firmware_markdown_report`); no network I/O. Not yet wired into the CLI or the probes.
  - `enrichment/` — Offline-only IEEE OUI registry (`oui.py`: `OuiRegistry`, `OuiMatch`) that loads MA-L/MA-M/MA-S CSV exports with longest-prefix lookup and a `KNOWN_OUI_VENDORS` fallback, plus multicast / locally-administered MAC classification (`classify_mac`, `is_multicast`, `is_locally_administered`). Not yet wired into the CLI or the topology and discovery code.
  - `config/` — Unified TOML fleet configuration loader (`load_config(path) -> AppConfig`, `ConfigError`, `SecretValue`) validating `10.x.0.0/16` site blocks, `/24` active subnets, thresholds and concurrency caps; secrets must be `${env:NAME}` references resolved from the environment and are always redacted. An optional `[retention]` table (`RetentionConfig`: `max_age_days`, `max_runs_per_site`) sets the history retention limits; only `history-prune --config` reads the fleet file.
  - `observability/` — Standard-library structured logging and run metrics: `configure_logging` (text/JSON on the `sot_validator` logger), `get_logger`, `log_context` / `wrap_with_context` run/site context, `RedactionFilter` key-based secret redaction (`REDACTION_MASK`), thread-safe `MetricsRegistry`, atomic Prometheus textfile `write_textfile`, and the `register_starter_metrics` starter metric set (`sot_run_last_success_timestamp_seconds`, `sot_run_duration_seconds`, `sot_site_status`, `sot_records_total`, `sot_collector_errors_total`, `sot_probe_duration_seconds`).
  - `testing/` — Seeded, deterministic synthetic fleet generator (`synthetic.py`: `SyntheticFleetGenerator`, `SyntheticFleet`, `drift_site`) producing fake `synth-` sites with `02:` MACs inside `10.(i+1).0.0/16`, plus the shared timed pipeline runner (`pipeline.py`: `run_pipeline`, `PipelineTimings`) for classification, FDB mapping, snapshot diffing and the HTML dashboard.
  - `cli/` — Unified CLI runner package (`python3 -m sot_validator` or `python3 -m sot_validator.cli`):
    - `__init__.py` re-exports `main`, `build_parser` and `_workbench_url` (no logic); `__main__.py` runs `main()`.
    - `parser.py` — top-level `build_parser()` and `main()`; calls each command module's `register(subparsers)` in the order the top-level `--help` lists subcommands.
    - `_common.py` — shared helpers and constants (source/validation flags, SoT client and site extraction, classification engine, results/history/curation store loaders, snapshot and JSON list loaders).
    - Command group modules, each with one `register(subparsers)` plus its `cmd_*` handlers: `core.py` (`extract`, `validate`, `report`, `run`), `history.py` (`history`, `history-prune`, `quarantine`), `remediation.py` (`remediate`, `reconcile`), `campaign.py` (`campaign`, `preflight`), `ports.py` (`reclaim-ports`), `migration.py` (`export-modern-sot` / `migrate-export`, `parity-check` / `migration-parity`), `ups.py` (`ups-health`), `itsm.py` (`itsm` / `itsm-sync`), `discovery.py` (`discover` [with `--router-arp`, `--dhcp-leases`, `--proxmox-snapshot` enrichment]), `workbench.py` (`serve` [e.g. `sot-validator serve --port <port>`, with `--token` / `--allow-remote`; prints the `#token=` URL once at start-up], `curate`), `topology.py` (`topology`, `fingerprint`, `map-ports`, `diff-scans`).
    - Adding a subcommand: add it to the matching group module's `register()`, or create a new module with `register(subparsers)` and call it from `parser.py` at the right position; keep every module under 800 lines. Then regenerate the help snapshots in `tests/fixtures/cli_help/` (`UPDATE_CLI_HELP_SNAPSHOTS=1 python3 -m pytest tests/test_cli_surface.py`) and add a Namespace case to `tests/test_cli_surface.py`.
- `tests/` — `pytest` unit and integration tests; `tests/perf/` holds the `perf`-marked 100-site pipeline performance budgets.
- `examples/` — Example fleet configuration (`sot-validator.example.toml`) and placeholder firmware lifecycle catalog (`lifecycle-catalog.example.json`).
- `docs/` — Architecture, discovery notes, and SoT API/schema specifications.
- `factory/` — Software factory scripts and gate configuration (`factory/checks.sh` and `factory/config.json` are protected paths).

## Confirmed Environment Profile

- **SoT Access**: No formal REST API; relies on **HTML Web Scraping (`GET`-only)** and/or **SQL / CSV Exports**. No explicit API rate limits, though extraction operates in site batches.
- **Scale & Addressing**: **~100 Sites**, each allocated a **`10.x.0.0/16`**, with **~10 active `/24` blocks per site**. Active network probing must strictly target allocated `/24` blocks or assigned SoT IPs (never sweep an entire `/16`).
- **Virtualization**: **Multiple VMware vCenter instances**; **~90% of VMs are Windows** (where Windows Firewall often drops ICMP echo, making vCenter power state / Guest Tools heartbeat and ARP primary signals).
- **Network Switches**: Primarily **Extreme Networks**.
- **UPS Fleet**: Primarily **APC** (SNMP `PowerNet-MIB` / management card web UI).

## Key Conventions & Constraints

1. **Read-Only Extraction & Gated Remediation**: Extraction and probing adapters (`SoTClient`, `HtmlScraperSoTClient`, `SqlExportSoTClient`, active probes) must strictly enforce read-only operations. Phase 2 remediation defaults to `dry_run=True`; any write-back or SQL remediation execution must require an operator-approved, SHA-256-verified manifest, explicit confirmation flags, and an append-only rollback journal.
2. **Batch-Oriented & `/24`-Scoped**: Extraction and active network probing must operate in configurable site batches (`10.x.0.0/16` per site, scoped to the ~10 active `/24` subnets and assigned IPs) with bounded concurrency to avoid overloading legacy systems or WAN links.
3. **Simplicity & Maintainability**: Favor standard library (`dataclasses`, `sqlite3`, `hashlib`, `csv`, `json`, `html.parser`) + `pytest`. Avoid heavy external frameworks or complex broker dependencies.
4. **Authenticated Workbench Writes**: Every `sot-validator serve` write (`POST`, and any `PUT`/`PATCH`/`DELETE`) requires `Authorization: Bearer <token>` (constant-time compared against `WorkbenchSecurityConfig.token`, which is generated with `secrets.token_urlsafe(32)` when not supplied), a same-origin `Origin`/`Referer`, and a body under `max_body_bytes`. Binds to non-loopback hosts are refused unless `allow_remote=True` (`serve --allow-remote`; `serve` exits with a one-line error instead of a traceback on a refused or failed bind), `serve` prints `http://<host>:<port>/#token=<token>` once at start-up (`--token` supplies a fixed token), and every response carries the CSP / `nosniff` / `DENY` / `no-referrer` hardening headers. Read-only `GET` routes stay token-free.
5. **Protected Paths**: Never modify `factory/checks.sh` or `factory/config.json` inside factory job branches.

## Running Checks & Tests

Run the gate script from the repository root:

```bash
bash factory/checks.sh
```

Run `pytest` directly when tests are present:

```bash
python3 -m pytest
```

Run the 100-site performance budgets in `tests/perf/` (marked `perf`; excluded from the default run by `addopts = "-m \"not perf\""` in `pyproject.toml`, and a later `-m perf` overrides it):

```bash
python3 -m pytest -m perf
```
