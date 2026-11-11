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

## Key Conventions & Constraints

1. **Read-Only First Phase**: Never issue mutating commands (port enable/disable, PoE toggles, record deletions) against the legacy SoT in Phase 1. All SoT adapters must strictly enforce read-only operations.
2. **Batch-Oriented & Rate-Limited**: Extraction and active network probing must operate in configurable batches with bounded concurrency, rate limiting, and retry/backoff to avoid overloading legacy systems or network gear.
3. **Simplicity & Maintainability**: Favor standard library + lightweight Python packages (`pydantic` or `dataclasses`, `httpx`/`requests`, `pytest`). Avoid heavy frameworks or complex external broker requirements.
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
