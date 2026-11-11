# Architecture & Phased Plan — Inventory Validation System (`sot-validator`)

## 1. Objective & Context

Our internal Source of Truth (SoT) tracks network and server inventory across sites:
- **Site**: Address, contact info, room list
  - **Network Devices**: Switches/routers, ports (with mapping), operational commands (enable/disable port, PoE control, etc. — *strictly off-limits in Phase 1*)
  - **VLANs / Subnets**
  - **IP Addresses**: Device assignments, ARP discovery data
  - **Network-Attached Equipment**: Servers, SANs, UPSs, VMs, etc.

Over time, records in the legacy SoT drift from physical and virtual reality. We need a **read-only, batch-oriented validation system** that extracts records in controlled batches, correlates multiple passive and active validation signals, and classifies every item into one of four actionable states:
1. `Confirmed Active`
2. `Stale / Likely Unused`
3. `Unreachable / Needs Manual Review`
4. `Insufficient Data`

---

## 2. Confirmed Environment Profile & Discovery Findings

| Dimension | Confirmed Environment Detail | Architectural Implication |
| :--- | :--- | :--- |
| **SoT Access Mechanism** | **No formal API** — relies on **Web UI Scraping** and/or **SQL / CSV Exports** | Stage 1 (`SoTClient`) must prioritize a **SQL/CSV Export Adapter** and a **Read-Only HTML Scraper Adapter** (strictly `GET`-only; never submit forms/POSTs that trigger port enable/disable or PoE changes). |
| **SoT Rate Limits** | **None explicitly enforced** | No artificial API gateway quota, but batching per site (`10.x.0.0/16`) with polite concurrency and per-site checkpointing protects the legacy web/DB server. |
| **Network Topology & Scale** | **~100 Sites**, each assigned a **`10.x.0.0/16`**, with **~10 active `/24` blocks per site** | Never sweep full `/16` ranges (65k IPs/site). Scope all extraction and active probing strictly to recorded SoT IP assignments and the ~10 allocated `/24` subnets per site. |
| **Hypervisors & VMs** | **Multiple VMware vCenter instances**; **~90% of VMs are Windows** | Multi-vCenter collector correlating across instances via BIOS UUID / MoRef / MAC / IP / hostname. Because Windows Firewall frequently drops ICMP ping by default, vCenter power state + VMware Tools heartbeat + ARP/port state must outweigh failed ICMP pings on Windows VMs. |
| **Network Switches** | Primarily **Extreme Networks** | Passive port/ARP signals from SoT complemented by SNMP `IF-MIB` (`ifAdminStatus`, `ifOperStatus`, `ifLastChange`), `IP-MIB` (`ipNetToMediaTable` / `ipNetToPhysicalTable`), and Extreme PoE/LLDP MIBs where reachable. |
| **UPS Equipment** | Primarily **APC** | Validate via ICMP and SNMP (`SNMPv2-MIB::sysUpTime`, `sysDescr`, APC `PowerNet-MIB` identity/status OIDs) or HTTPS management card reachability. |

---

## 3. High-Level Architecture

The system is decoupled into four sequential, batch-driven pipeline stages so that extraction, signal probing, classification, and reporting can run independently and resume from local state without repeatedly hitting the legacy SoT.

```mermaid
flowchart LR
    subgraph SoT["Legacy Source of Truth (Read-Only)"]
        API["Web UI Scraper (GET-only) / SQL & CSV Exports"]
    end

    subgraph Stage1["Stage 1: Batch Extractor"]
        Ext["Per-Site Scraper / SQL Export Ingestor"]
        Snap["Local Batch Snapshot (JSON / SQLite)"]
        Ext --> Snap
    end

    subgraph Stage2["Stage 2: Signal Collectors"]
        Passive["Passive Signals (ARP Age, Last-Seen, Port Link State)"]
        Active["Active Probes (Scoped /24 ICMP, Extreme Switch & APC UPS SNMP)"]
        VM["Multi-vCenter Inventory Correlator (90% Windows VMs)"]
    end

    subgraph Stage3["Stage 3: Classification Engine"]
        Rules["Weighted Signal Evaluator"]
        Class["Status + Confidence + Evidence Trail"]
        Rules --> Class
    end

    subgraph Stage4["Stage 4: Reporting & Future Hooks"]
        Rep["Reports (JSON, CSV, Markdown Summary)"]
        Hook["Phase 2 Dry-Run / Flagging Interface"]
    end

    API --> Ext
    Snap --> Passive
    Snap --> Active
    Snap --> VM
    Passive --> Rules
    Active --> Rules
    VM --> Rules
    Class --> Rep
    Class --> Hook
```

### Signal Priority & Cost Hierarchy
To minimize load on both the legacy SoT and live network infrastructure, signals are evaluated in order of lowest cost / highest passivity first:
1. **Tier 1 — Passive SoT Metadata (Zero Network Overhead)**:
   - Recent ARP discovery timestamps already recorded in SoT
   - Last-seen timestamps on devices/IPs/equipment
   - Recorded Extreme switch port operational status / link state and PoE draw
2. **Tier 2 — Multi-vCenter Inventory Correlation (Low Overhead, Bulk Read)**:
   - Query or ingest across multiple VMware vCenter instances (power state, VMware Guest Tools status/heartbeat, guest NIC IP/MAC bindings)
   - Critical for the ~90% Windows VM fleet where Windows Defender Firewall may block ICMP echo requests
3. **Tier 3 — Scoped Active Network Probes (Bounded Concurrency, `/24`-Scoped per Site Batch)**:
   - ICMP echo (ping) sweeps restricted strictly to assigned SoT IPs / allocated `/24` blocks within each site's `10.x.0.0/16`
   - Read-only SNMP (`sysUpTime`, `ifOperStatus`, ARP tables, Extreme switch MIBs, APC UPS `PowerNet-MIB`) or HTTPS management UI reachability checks

---

## 4. Classification Matrix

| Classification | Criteria Summary | Example Evidence |
| :--- | :--- | :--- |
| **Confirmed Active** | At least one strong positive recent signal (within active threshold, e.g., ≤ 7 days). | Recent ARP entry, Extreme switch port link UP, ICMP reply, SNMP response (Extreme switch / APC UPS), or vCenter VM powered ON with active Guest Tools. |
| **Stale / Likely Unused** | Sufficient signal coverage exists, and all signals consistently indicate inactivity beyond the stale threshold (e.g., > 30–90 days). | Switch port DOWN for > 60 days, ARP expired/absent, ICMP unreachable, and (if VM) powered OFF or missing across all vCenter instances. |
| **Unreachable / Needs Manual Review** | Conflicting signals or active probes fail despite indications the device should be online, or host firewall blocks probes. | Extreme port link is UP / PoE drawing power, or Windows VM is marked ON in SoT, but ICMP/SNMP probes time out and vCenter/ARP correlation is unavailable. |
| **Insufficient Data** | Record lacks required identifiers or signal collectors could not evaluate the target. | Equipment record has no IP address, no switch port mapping, no vCenter match, and no last-seen timestamp. |

---

## 5. Phased Implementation Plan

### Phase 0: Discovery & Canonical Data Model
- **Issue 1 (Discovery / Source Mapping)**: Map legacy SoT HTML DOM structures (for `GET`-only web scraping) and/or SQL export table schemas, multi-vCenter connection/export details, and SNMP community/credentials for Extreme switches and APC UPSs.
- **Issue 2 (Domain Models)**: Define canonical, normalized data schemas (`Site`, `NetworkDevice`, `Port`, `VLAN`, `Subnet`, `IPAddress`, `ArpEntry`, `Equipment`, `ValidationSignal`, `ValidationResult`).

### Phase 1A: Read-Only Batch Extraction (Scraping & SQL Exports)
- **Issue 3 (Batch Extractor)**: Build the read-only SoT extraction engine supporting SQL/CSV export ingestion and `GET`-only HTML scraping per site (`10.x.0.0/16` batches across ~100 sites), with local snapshot persistence and offline fixtures.

### Phase 1B: Validation Signal Collectors
- **Issue 4 (Passive Signals)**: Implement evaluators for ARP discovery recency, Extreme switch port link/admin/PoE state, and SoT last-seen timestamps.
- **Issue 5 (Active Probes)**: Implement bounded-concurrency ICMP reachability (strictly scoped to allocated `/24` blocks / assigned IPs, never full `/16` sweeps) and SNMP/HTTP collectors tailored for Extreme switches and APC UPSs.
- **Issue 6 (Multi-vCenter VM Correlation)**: Implement multi-instance VMware vCenter correlation (power state, VMware Tools heartbeat, MAC/IP matching) handling the ~90% Windows VM footprint.

### Phase 1C: Classification Engine & Reporting
- **Issue 7 (Classification Engine)**: Implement the rule evaluation engine that combines signals into the 4 target classifications with an explicit evidence trail and configurable thresholds (accounting for Windows VMs blocking ICMP when vCenter/ARP shows active).
- **Issue 8 (CLI & Reporting)**: Build the CLI runner and multi-format report generator (JSON, CSV, Markdown site summaries) with dry-run hooks for Phase 2 SoT write-back/flagging.
