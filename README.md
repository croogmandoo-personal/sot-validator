# SoT Validator (`sot-validator`)

Inventory Validation System for Legacy Network Source of Truth.

## Overview

`sot-validator` extracts site and equipment records in controlled batches from an internal legacy Source of Truth (SoT) system and validates whether recorded network devices, IP addresses, and network-attached equipment (servers, SANs, UPSs, VMs, etc.) are still in active use.

### Phase 1 Objectives
- **Read-Only Batch Extraction**: Safely extract `Site` hierarchies (Network Devices, Ports, VLANs/Subnets, IP Addresses + ARP discovery data, Network-Attached Equipment) with pagination, rate-limiting, and local snapshot caching.
- **Multi-Signal Validation**: Collect and correlate activity signals including:
  - Recent ARP entries and last-seen timestamps from SoT / routers
  - Switch port status / link state
  - ICMP reachability
  - SNMP / API reachability where available
  - Hypervisor / VM power state correlation
- **Actionable Classification**: Classify each inventory item into one of four states:
  - `Confirmed Active`
  - `Stale / Likely Unused`
  - `Unreachable / Needs Manual Review`
  - `Insufficient Data`
- **Extensible Architecture**: Produce structured reports (JSON/CSV/Markdown) designed to feed future automated flagging or cleanup workflows inside the Source of Truth.

## Architecture

```
+------------------------+
| Legacy Source of Truth |  (Read-Only API / DB / Exports)
+-----------+------------+
            |
            |  1. Controlled Batch Extraction (Rate-limited, paginated per Site)
            v
+------------------------+
|   Local Snapshot Store |  Normalized Domain Models (Site, Device, Port, Subnet, IP, Equipment)
+-----------+------------+
            |
            |  2. Signal Collectors (Pluggable Probes & Correlators)
            +---> Passive Signals: ARP cache age, SoT last-seen, hypervisor VM state
            +---> Active Probes: ICMP ping, SNMP/API reachability, switch port link state
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
