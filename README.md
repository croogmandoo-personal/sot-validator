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
- **Extensible Architecture**: Produce structured reports (JSON/CSV/Markdown) designed to feed future automated flagging or cleanup workflows inside the Source of Truth.

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
            |  3. Reporting & Audit Output
            v
+------------------------+
|   Validation Reports   |  JSON / CSV / Summary Markdown
+------------------------+
  - Confirmed Active
  - Stale / Likely Unused
  - Unreachable / Needs Manual Review
  - Insufficient Data
```

## Development & Checks

Run the repository verification gate:

```bash
bash factory/checks.sh
```
