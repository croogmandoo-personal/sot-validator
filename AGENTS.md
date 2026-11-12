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
  - `extraction/` — Read-only batch extractor (`BatchExtractor`, `SnapshotStore`, `SqlExportSoTClient`, `HtmlScraperSoTClient`, `FixtureSoTClient`).
  - `signals/` — Passive (`arp.py`, `port_state.py`, `last_seen.py`), `/24`-scoped active (`icmp.py`, `management.py`), multi-vCenter (`hypervisor.py`), Phase 4 AD/DNS/DHCP (`directory_dns.py`), Phase 6 APC UPS telemetry (`ups_health.py`), and Phase 10–12 Proxmox VE `:8006` / Docker-Portainer `:9000` guest & container (`proxmox_containers.py`) collectors.
  - `classifier/` — Deterministic multi-signal `ClassificationEngine` and `ClassificationPolicy`.
  - `reporting/` — Multi-format report generators (`JSON`, `CSV`, `Markdown`, and interactive `HTML` operations dashboard).
  - `history/` — Phase 2 multi-run validation history store, stale streak tracker, and state-drift analyzer.
  - `remediation/` — Phase 1/2 dry-run action plans, quarantine graduation policies, SHA-256 signed approval manifests, gated remediation executor with rollback journal, and Phase 4 Extreme switch port/PoE reclamation planner (`port_reclamation.py`).
  - `reconciliation/` — Phase 3 reverse discovery & untracked inventory ("Shadow IT") reconciler and SoT import template generator.
  - `campaign/` — Phase 3 multi-site rolling campaign orchestrator, WAN/vCenter outage circuit breakers, and alert sinks.
  - `connectors/` — Phase 4 live pilot connector transports and pre-flight cutover validator.
  - `migration/` — Phase 5 NetBox / Nautobot golden inventory exporter and dual-run parity / readiness scorecard checker.
  - `itsm/` — Phase 6 ServiceNow / Jira change-ticket governance and approval synchronization sink.
  - `discovery/` — Phase 7 two-stage `/16`-to-`/24` live subnet discovery scanner (`SubnetDiscoveryScanner`, `DiscoveryConfig`, `DiscoveredHost`), `Site` snapshot bootstrapper, Phase 10–12 service banner and certificate fingerprinter (`fingerprinter.py`: `ServiceBannerFingerprinter`, `RawServiceBanner`, `DeviceFingerprint`), Phase 10–12 `monitor.py` snapshot diff engine and drift alert dispatcher (`SnapshotDiffEngine`, `SnapshotDiffReport`, `ScanDriftEvent`, `DriftAlertDispatcher`), and Phase 10–12 router ARP / DHCP lease table enricher (`router_tables.py`: `RouterArpDhcpCollector`, `RouterTableParsers`).
  - `curation/` — Phase 8 SQLite/JSON operator curation overlay store (`CurationStore`, `ItemEditPatch`, `AuditLogEntry`, `apply_curation_overlay`).
  - `topology/` — Phase 9 network role & VLAN heuristic identifier (`NetworkRoleIdentifier`, `ConsolidatedRouter`), device type catalog & port range builder (`DeviceTypeCatalog`, `DevicePortManager`), hierarchical topology graph builder (`TopologyGraphBuilder`, `TopologyGraph`), and Phase 10–12 switch FDB / Bridge-MIB MAC-to-port mapper with trunk/access inferrer (`fdb_mapper.py`: `FdbTableParser`, `SwitchFdbPortMapper`).
  - `workbench/` — Phase 8/9 self-contained interactive HTTP Web Workbench server (`WorkbenchServer`, `WorkbenchState`), JSON REST API including read-only `GET /api/topology`, and HTML5/SVG topology & inventory curation UI (`render_workbench_html`) with a Topology Map tab and a switch faceplate.
  - `cli.py` — Unified CLI runner (`extract`, `validate`, `report`, `run`, `history`, `quarantine`, `remediate`, `reconcile`, `campaign`, `preflight`, `reclaim-ports`, `export-modern-sot` / `migrate-export`, `parity-check` / `migration-parity`, `ups-health`, `itsm` / `itsm-sync`, `discover` [with `--router-arp`, `--dhcp-leases`, `--proxmox-snapshot` enrichment], `serve` [e.g. `sot-validator serve --port <port>`], `curate`, `topology`, `fingerprint`, `map-ports`, `diff-scans`).
- `tests/` — `pytest` unit and integration tests.
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
4. **Protected Paths**: Never modify `factory/checks.sh` or `factory/config.json` inside factory job branches.

## Running Checks & Tests

Run the gate script from the repository root:

```bash
bash factory/checks.sh
```

Run `pytest` directly when tests are present:

```bash
python3 -m pytest
```
