# AGENTS.md — SoT Validator (`sot-validator`)

## Project Overview

`sot-validator` is a batch-oriented, read-only inventory validation system for a legacy internal Network Source of Truth (SoT). It extracts site hierarchies (`Site`, `NetworkDevice`, `Port`, `VLAN/Subnet`, `IPAddress` + ARP discovery data, `Equipment`) in controlled batches, evaluates validation signals (ARP age, port link state, ICMP, SNMP/API, VM power state, last-seen timestamps), and classifies each record into:
- `Confirmed Active`
- `Stale / Likely Unused`
- `Unreachable / Needs Manual Review`
- `Insufficient Data`

## Repository Structure

- `src/sot_validator/` — Core Python package (domain models, batch extractor, signal collectors, classification engine, reporting, CLI).
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

1. **Read-Only First Phase**: Never issue mutating commands (port enable/disable, PoE toggles, record deletions, HTTP `POST` form submissions) against the legacy SoT in Phase 1. All SoT scrapers and SQL/export adapters must strictly enforce read-only operations.
2. **Batch-Oriented & `/24`-Scoped**: Extraction and active network probing must operate in configurable site batches (`10.x.0.0/16` per site, scoped to the ~10 active `/24` subnets and assigned IPs) with bounded concurrency to avoid overloading legacy systems or WAN links.
3. **Simplicity & Maintainability**: Favor standard library + lightweight Python packages (`pydantic` or `dataclasses`, `httpx`/`requests`, `beautifulsoup4` for scraping, `pytest`). Avoid heavy frameworks or complex external broker requirements.
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
