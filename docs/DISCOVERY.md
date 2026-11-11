# Legacy SoT Discovery Mapping & Probing Specifications (`docs/DISCOVERY.md`)

## 1. Overview & Operational Scope

This document defines the canonical discovery mapping, data schemas, security guardrails, and network probing parameters for the `sot-validator` Phase 1 validation pipeline:

- **Legacy Source of Truth (SoT) Access**: No formal REST or GraphQL API exists. Extraction relies on **read-only (`GET`-only) HTML web scraping** and/or **SQL / CSV database exports**.
- **Mutating Endpoint Guardrails**: The legacy SoT web interface embeds operational switch port and PoE control forms directly inside device detail views. Phase 1 strictly forbids any non-`GET`/`HEAD` HTTP methods, form submissions, or requests matching the mutating URL blocklist.
- **Scale & `/24` Addressing Scope**: ~100 sites, each allocated a `10.x.0.0/16` summary prefix (where `x` corresponds to the site number, e.g., `10.42.0.0/16` for `site-042`) containing ~10 active `/24` subnets per site. Active ICMP and SNMP probes must target only recorded SoT IP assignments and allocated `/24` blocks—never full `/16` sweeps.
- **Multi-vCenter Virtualization Footprint**: Multiple VMware vCenter instances manage the virtual fleet where **~90% of VMs run Windows**. Because Windows Defender Firewall commonly drops ICMP echo requests by default, vCenter power state (`poweredOn`), VMware Guest Tools heartbeat (`toolsOk` / `green`), and fresh ARP entries take precedence over failed ICMP probes.
- **Physical Network & Power Fleet**: Network switches are primarily **Extreme Networks** (running ExtremeXOS) and UPS units are primarily **APC** (equipped with Network Management Cards supporting `PowerNet-MIB`).

---

## 2. Legacy SoT Scraping Mapping (`GET`-Only)

### 2.1 Canonical Read-Only URL Patterns

All HTTP scraper requests must use `GET` (or `HEAD`) against the following canonical URL paths:

| View / Resource | URL Pattern | Query Parameters Allowed | Description |
| :--- | :--- | :--- | :--- |
| **Site Index** | `/sites` | `?page={n}` | Paginated directory of all sites and their `10.x.0.0/16` allocations. |
| **Site Overview** | `/sites/{site_id}` | None | Site metadata (`#site-overview`), room list (`.room-list`), `/24` subnets (`table#subnets-table`), IP/ARP table (`table#ip-arp-table`), and site equipment (`table#equipment-table`). |
| **Network Device & Ports** | `/sites/{site_id}/devices/{device_id}` | None | Switch/router detail header (`#device-detail`) and port status/mapping table (`table#ports-table`). |
| **Site Subnets & IP/ARP** | `/sites/{site_id}/subnets` | `?vlan={vlan_id}` | Dedicated `/24` VLAN/subnet and IP/ARP discovery view (`table#subnets-table`, `table#ip-arp-table`). |
| **Site Equipment List** | `/sites/{site_id}/equipment` | `?type={role}` | Dedicated equipment table (`table#equipment-table`) for servers, VMs, SANs, NAS units, and UPSs. |

### 2.2 HTML DOM Selectors & `data-*` Attributes

#### A. `Site` (`#site-overview` on `/sites/{site_id}`)

- **Container Selector**: `section#site-overview`
- **Data Attributes on `section#site-overview`**:
  - `data-site-id`: Primary identifier (e.g., `site-042`)
  - `data-site-name`: Human-readable site name (e.g., `SF Regional Distribution Center 42`)
  - `data-site-prefix`: Site `/16` summary prefix (e.g., `10.42.0.0/16`)
- **Child Field Selectors**:
  - `.site-address`: Street address string
  - `.site-contact-name`: Primary site contact name
  - `.site-contact-email`: Contact email address
  - `.site-contact-phone`: Contact telephone number
  - `ul.room-list > li.room-item[data-room-id]`: Individual room identifiers (joined by `;` in flat SQL/CSV exports, e.g., `MDF-101;IDF-201;UPS-Closet-B`)

#### B. `VLAN` + `Subnet` (`table#subnets-table`)

- **Table Selector**: `table#subnets-table`
- **Row Selector**: `tbody > tr.subnet-row[data-subnet-id]`
- **Cell / Attribute Mapping**:

| Field | Selector / Attribute | Example (`site-042`) |
| :--- | :--- | :--- |
| `subnet_id` | `tr[data-subnet-id]` or `td.col-subnet-id` | `sub-042-010` |
| `site_id` | `tr[data-site-id]` | `site-042` |
| `vlan_id` | `td.col-vlan-id` (`data-vlan-id`) | `10` |
| `vlan_name` | `td.col-vlan-name` | `SERVER-PROD` |
| `cidr` | `td.col-cidr` (`data-cidr`, must be a `/24` inside site `/16`) | `10.42.10.0/24` |
| `gateway_ip` | `td.col-gateway-ip` | `10.42.10.1` |
| `description` | `td.col-description` | `Production Servers & Virtual Machines` |

#### C. `IPAddress` + `ArpEntry` (`table#ip-arp-table`)

- **Table Selector**: `table#ip-arp-table`
- **Row Selector**: `tbody > tr.ip-arp-row[data-ip-id]`
- **Cell / Attribute Mapping**:

| Field | Selector / Attribute | Example (`site-042`) |
| :--- | :--- | :--- |
| `ip_id` | `tr[data-ip-id]` or `td.col-ip-id` | `ip-042-004` |
| `site_id` | `tr[data-site-id]` | `site-042` |
| `subnet_id` | `tr[data-subnet-id]` or `td.col-subnet-id` | `sub-042-010` |
| `ip_address` | `td.col-ip-address` (`data-ip`) | `10.42.10.21` |
| `mac_address` | `td.col-mac-address` (`data-mac`) | `00:50:56:9a:42:11` |
| `assigned_target_type` | `td.col-target-type` (`data-target-type`: `network_device` \| `equipment`) | `equipment` |
| `assigned_target_id` | `td.col-target-id` (`data-target-id`) | `eq-042-vm-win01` |
| `arp_last_seen` | `td.col-arp-last-seen` (`data-arp-last-seen`, ISO-8601 UTC) | `2026-11-11T07:58:00Z` |
| `arp_source_device_id` | `td.col-arp-source` (`data-arp-source-device-id`) | `dev-042-sw01` |

#### D. `Equipment` (`table#equipment-table`)

- **Table Selector**: `table#equipment-table`
- **Row Selector**: `tbody > tr.equipment-row[data-equipment-id]`
- **Cell / Attribute Mapping**:

| Field | Selector / Attribute | Example (`site-042`) |
| :--- | :--- | :--- |
| `equipment_id` | `tr[data-equipment-id]` or `td.col-equipment-id` | `eq-042-vm-win01` |
| `site_id` | `tr[data-site-id]` | `site-042` |
| `hostname` | `td.col-hostname` | `win-dc01.site042.example.internal` |
| `equipment_type` | `td.col-equipment-type` (`Server`, `VM`, `SAN`, `NAS`, `UPS`) | `VM` |
| `vendor` | `td.col-vendor` | `VMware` |
| `model` | `td.col-model` | `Virtual Machine` |
| `primary_ip` | `td.col-primary-ip` (nullable/empty if untracked) | `10.42.10.21` |
| `mac_address` | `td.col-mac-address` (nullable/empty if untracked) | `00:50:56:9a:42:11` |
| `vcenter_instance` | `td.col-vcenter-instance` (`data-vcenter-instance`) | `vcenter-prod-01.example.internal` |
| `vcenter_bios_uuid` | `td.col-vcenter-uuid` (`data-vcenter-uuid`) | `421a0042-0001-4000-8000-0050569a4211` |
| `vcenter_moref` | `td.col-vcenter-moref` (`data-vcenter-moref`) | `vm-10421` |
| `connected_port_id` | `td.col-connected-port` (`data-port-id`) | `port-042-sw01-1` |
| `last_seen` | `td.col-last-seen` (`data-last-seen`, ISO-8601 UTC) | `2026-11-11T07:58:00Z` |

#### E. `NetworkDevice` + `Port` (`section#device-detail` & `table#ports-table` on `/sites/{site_id}/devices/{device_id}`)

- **Device Header Selector**: `section#device-detail[data-device-id]`
  - Attributes: `data-device-id`, `data-site-id`, `data-hostname`, `data-vendor`, `data-model`, `data-role`, `data-mgmt-ip`, `data-mac-address`, `data-room`, `data-os-version`, `data-serial-number`, `data-last-seen`.
- **Port Table Selector**: `table#ports-table`
- **Port Row Selector**: `tbody > tr.port-row[data-port-id]`
- **Cell / Attribute Mapping**:

| Field | Selector / Attribute | Example (`dev-042-sw01`) |
| :--- | :--- | :--- |
| `port_id` | `tr[data-port-id]` or `td.col-port-id` | `port-042-sw01-3` |
| `device_id` | `tr[data-device-id]` | `dev-042-sw01` |
| `port_name` | `td.col-port-name` | `1:3` |
| `if_index` | `td.col-if-index` (`data-if-index`) | `1003` |
| `admin_status` | `td.col-admin-status` (`up` \| `down`) | `up` |
| `oper_status` | `td.col-oper-status` (`up` \| `down`) | `up` |
| `poe_status` | `td.col-poe-status` (`delivering` \| `disabled` \| `searching`) | `delivering` |
| `poe_power_w` | `td.col-poe-power` (`data-poe-watts`) | `12.4` |
| `vlan_id` | `td.col-vlan-id` | `30` |
| `connected_equipment_id` | `td.col-connected-equipment` (`data-equipment-id`) | `eq-042-ups01` |
| `connected_mac` | `td.col-connected-mac` | `00:c0:b7:42:30:01` |
| `description` | `td.col-description` | `APC Smart-UPS NMC3 MDF-101` |
| `last_change` | `td.col-last-change` (`data-last-change`, ISO-8601 UTC) | `2026-10-01T06:00:00Z` |

---

## 3. Mutating Action & Endpoint Blocklist (Phase 1 Read-Only Guardrail)

The legacy SoT embeds operational control forms inside `table#ports-table` and device headers. The scraper adapter must enforce the following hard blocklist before issuing any HTTP request and when parsing DOM nodes:

1. **HTTP Method Restriction**:
   - **Allowed**: `GET`, `HEAD`
   - **Blocked**: `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`
2. **HTML Element Exclusion**:
   - Never serialize, submit, or follow `action` attributes on `<form>`, `<button>`, `<input>`, or `<a data-method="post">` elements.
   - Ignore `td.col-ops-actions` cells inside `table#ports-table`.
3. **Blocked URL Path Patterns**:
   - `/actions/port-admin` (enables/disables switch port administrative state)
   - `/actions/poe-toggle` (enables/disables or cycles port PoE power delivery)
   - `/actions/port-bounce` (bounces switch port link)
   - `/actions/vlan-assign` (modifies port VLAN membership)
   - `/actions/delete` (deletes device, IP, or equipment record)
   - `/api/cmd/*` (legacy operational CLI execution endpoint)
4. **Blocked Query String Patterns**:
   - Any URL query string matching `(?i)(^|[?&])action=(enable|disable|toggle|reset|delete)(\b|&|$)`.

---

## 4. SQL & CSV Export Schemas

When ingesting from a read-only database replica or nightly CSV dump instead of HTML scraping, the following 6 normalized tables/CSVs provide a 1-to-1 field mapping with the HTML DOM selectors above:

### 4.1 `sites` (`sites.csv`)

| Column | SQL Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `site_id` | `TEXT PRIMARY KEY` | No | Canonical site identifier (`site-042`) |
| `name` | `TEXT NOT NULL` | No | Site display name |
| `site_prefix` | `TEXT NOT NULL` | No | Allocated `/16` CIDR (`10.42.0.0/16`) |
| `address` | `TEXT NOT NULL` | No | Physical street address |
| `contact_name` | `TEXT` | Yes | Local site contact |
| `contact_email` | `TEXT` | Yes | Contact email |
| `contact_phone` | `TEXT` | Yes | Contact phone |
| `rooms` | `TEXT NOT NULL` | No | Semicolon-delimited room list (`MDF-101;IDF-201;UPS-Closet-B`) |

### 4.2 `network_devices` (`network_devices.csv`)

| Column | SQL Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `device_id` | `TEXT PRIMARY KEY` | No | Device identifier (`dev-042-sw01`) |
| `site_id` | `TEXT NOT NULL` | No | Foreign key to `sites.site_id` |
| `hostname` | `TEXT NOT NULL` | No | Management FQDN |
| `vendor` | `TEXT NOT NULL` | No | Hardware vendor (`Extreme Networks`) |
| `model` | `TEXT NOT NULL` | No | Switch/router model (`ExtremeSwitching X465-48W`) |
| `role` | `TEXT NOT NULL` | No | Device role (`core-switch`, `access-switch`, `router`) |
| `mgmt_ip` | `TEXT NOT NULL` | No | Management IPv4 address within site `/24` management block |
| `mac_address` | `TEXT NOT NULL` | No | Chassis base MAC address (`aa:bb:cc:dd:ee:ff`) |
| `room` | `TEXT NOT NULL` | No | Room identifier from `sites.rooms` |
| `os_version` | `TEXT` | Yes | Operating system version (`EXOS 31.7.1.4`) |
| `serial_number` | `TEXT` | Yes | Chassis serial number |
| `last_seen` | `TEXT` | Yes | Last poll timestamp in SoT (ISO-8601 UTC) |

### 4.3 `ports` (`ports.csv`)

| Column | SQL Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `port_id` | `TEXT PRIMARY KEY` | No | Unique port record ID (`port-042-sw01-1`) |
| `device_id` | `TEXT NOT NULL` | No | Foreign key to `network_devices.device_id` |
| `port_name` | `TEXT NOT NULL` | No | Switch slot:port name (`1:1`, `1:2`) |
| `if_index` | `INTEGER NOT NULL` | No | SNMP `ifIndex` (`1001`) |
| `admin_status` | `TEXT NOT NULL` | No | Administrative state (`up` \| `down`) |
| `oper_status` | `TEXT NOT NULL` | No | Operational link state (`up` \| `down`) |
| `poe_status` | `TEXT NOT NULL` | No | PoE delivery state (`delivering` \| `disabled` \| `searching`) |
| `poe_power_w` | `REAL NOT NULL` | No | Measured PoE draw in Watts (`0.0` if disabled) |
| `vlan_id` | `INTEGER NOT NULL` | No | Untag/primary VLAN ID |
| `connected_equipment_id` | `TEXT` | Yes | Foreign key to `equipment.equipment_id` (if mapped) |
| `connected_mac` | `TEXT` | Yes | Learned MAC on port |
| `description` | `TEXT` | Yes | Port alias / circuit description |
| `last_change` | `TEXT NOT NULL` | No | Timestamp of last link transition (ISO-8601 UTC) |

### 4.4 `vlans_subnets` (`vlans_subnets.csv`)

| Column | SQL Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `subnet_id` | `TEXT PRIMARY KEY` | No | Unique subnet ID (`sub-042-010`) |
| `site_id` | `TEXT NOT NULL` | No | Foreign key to `sites.site_id` |
| `vlan_id` | `INTEGER NOT NULL` | No | 802.1Q VLAN tag (`10`) |
| `vlan_name` | `TEXT NOT NULL` | No | VLAN short name (`SERVER-PROD`) |
| `cidr` | `TEXT NOT NULL` | No | Allocated `/24` subnet within site's `10.x.0.0/16` (`10.42.10.0/24`) |
| `gateway_ip` | `TEXT NOT NULL` | No | Default gateway IP (`10.42.10.1`) |
| `description` | `TEXT` | Yes | Subnet purpose description |

### 4.5 `ip_arp_entries` (`ip_arp_entries.csv`)

| Column | SQL Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `ip_id` | `TEXT PRIMARY KEY` | No | Unique IP assignment ID (`ip-042-004`) |
| `site_id` | `TEXT NOT NULL` | No | Foreign key to `sites.site_id` |
| `subnet_id` | `TEXT NOT NULL` | No | Foreign key to `vlans_subnets.subnet_id` |
| `ip_address` | `TEXT NOT NULL` | No | Assigned IPv4 address inside `vlans_subnets.cidr` |
| `mac_address` | `TEXT` | Yes | Observed or static MAC address |
| `assigned_target_type` | `TEXT NOT NULL` | No | Target entity class (`network_device` \| `equipment`) |
| `assigned_target_id` | `TEXT NOT NULL` | No | ID in `network_devices` or `equipment` |
| `arp_last_seen` | `TEXT` | Yes | Most recent router/switch ARP timestamp (ISO-8601 UTC) |
| `arp_source_device_id` | `TEXT` | Yes | Device ID that reported the ARP entry |

### 4.6 `equipment` (`equipment.csv`)

| Column | SQL Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `equipment_id` | `TEXT PRIMARY KEY` | No | Equipment primary key (`eq-042-vm-win01`) |
| `site_id` | `TEXT NOT NULL` | No | Foreign key to `sites.site_id` |
| `hostname` | `TEXT NOT NULL` | No | Recorded hostname or asset label |
| `equipment_type` | `TEXT NOT NULL` | No | Asset category (`Server`, `VM`, `SAN`, `NAS`, `UPS`) |
| `vendor` | `TEXT NOT NULL` | No | Manufacturer (`VMware`, `APC`, `Dell`, `NetApp`, `HP`, `Synology`) |
| `model` | `TEXT NOT NULL` | No | Hardware model or `Virtual Machine` |
| `primary_ip` | `TEXT` | Yes | Primary IPv4 address (empty/NULL if unrecorded) |
| `mac_address` | `TEXT` | Yes | Primary NIC MAC address (empty/NULL if unrecorded) |
| `vcenter_instance` | `TEXT` | Yes | Managing vCenter FQDN (for `VM` records) |
| `vcenter_bios_uuid` | `TEXT` | Yes | VM BIOS UUID for cross-vCenter correlation |
| `vcenter_moref` | `TEXT` | Yes | vSphere Managed Object Reference (`vm-10421`) |
| `connected_port_id` | `TEXT` | Yes | Foreign key to `ports.port_id` |
| `last_seen` | `TEXT` | Yes | Last recorded activity timestamp in SoT (ISO-8601 UTC) |

---

## 5. Multi-vCenter Inventory Access & Correlation Schema

### 5.1 Read-Only Connection & Export Parameters

- **Instances**: Multiple regional/cluster vCenter servers (e.g., `vcenter-prod-01.example.internal`, `vcenter-prod-02.example.internal`).
- **Authentication**: Dedicated read-only service principal (`svc-sot-ro@vsphere.local`) bound strictly to the built-in vSphere `Read-Only` role at the root Datacenter folder level (no VM power/configuration privileges).
- **Ingestion Modes**:
  1. **Batch JSON Snapshot (`vcenter_inventory.json`)**: Exported via pyVmomi / vSphere Automation REST API (`GET /api/vcenter/vm`) or scheduled RVTools/PowerCLI JSON collector.
  2. **Correlation Key Priority**:
     1. `bios_uuid` (`vcenter_bios_uuid` in SoT)
     2. (`vcenter_instance`, `vm_moref`)
     3. Primary NIC `mac_address` + `ip_addresses` within the site's allocated `/24` blocks
     4. Normalized `guest_hostname` / `vm_name`

### 5.2 Multi-vCenter Record Schema

Each VM entry in `vcenter_inventory.json` (under the top-level `vms` list) conforms to the following structure:

| Field | Type | Description |
| :--- | :--- | :--- |
| `vcenter_instance` | `string` | Short instance ID (`vcenter-prod-01`, `vcenter-prod-02`) |
| `vcenter_host` | `string` | Full vCenter FQDN (`vcenter-prod-01.example.internal`) |
| `site_id` | `string` | Associated site identifier (`site-042`) |
| `vm_moref` | `string` | vSphere Managed Object ID (`vm-10421`) |
| `bios_uuid` | `string` | Canonical lower-case BIOS UUID (`421a0042-0001-4000-8000-0050569a4211`) |
| `vm_name` | `string` | vCenter inventory display name |
| `guest_hostname` | `string` | Guest OS reported FQDN |
| `guest_os_family` | `string` | `"windows"` (~90% of fleet) or `"linux"` (~10% of fleet) |
| `guest_os_full_name` | `string` | Full guest OS descriptor (`Microsoft Windows Server 2022 (64-bit)`) |
| `power_state` | `string` | `"poweredOn"`, `"poweredOff"`, or `"suspended"` |
| `tools_status` | `string` | `"toolsOk"`, `"toolsOld"`, `"toolsNotRunning"`, or `"toolsNotInstalled"` |
| `tools_heartbeat` | `string` | `"green"`, `"yellow"`, `"red"`, or `"gray"` |
| `nics` | `array<object>` | List of NIC bindings: `{"nic_label", "mac_address", "ip_addresses", "vlan_id", "connected"}` |
| `last_updated` | `string` | Snapshot collection timestamp (ISO-8601 UTC) |

### 5.3 Windows VM Correlation Rule (~90% Windows Footprint)

Approximately **90% of virtual machines run Microsoft Windows Server or Windows Enterprise**, where Windows Defender Firewall drops inbound ICMP Echo Request (`ping`) packets by default. Consequently:
- A Windows VM with `power_state == "poweredOn"` and `tools_status in ("toolsOk", "toolsOld")` (`tools_heartbeat == "green"`) or a recent ARP entry (`<= 7 days`) MUST be classified as **`Confirmed Active`**, even when active ICMP echo probes time out.
- Conversely, a VM with `power_state == "poweredOff"` across all vCenter instances, `tools_heartbeat == "gray"`, and an expired ARP entry (`> 30–90 days`) is classified as **`Stale / Likely Unused`**.

---

## 6. Extreme Networks Switch & APC UPS Probing Parameters

### 6.1 Read-Only SNMP Configuration

- **Supported Versions**:
  - `SNMPv2c`: Read-only community string supplied via environment variable `SOT_SNMP_RO_COMMUNITY` (never write/private communities; `SNMP SET` PDUs are prohibited).
  - `SNMPv3`: `authPriv` (`SHA-256` / `AES-128`) read-only user `sot-validator-ro` for management VLANs requiring encrypted polling.
- **Transport & Concurrency Parameters**:
  - UDP Port: `161`
  - Per-request timeout: `2.0s`
  - Retries: `2`
  - Max concurrent SNMP targets per site batch: `16`

### 6.2 Canonical SNMP OIDs

#### A. Standard MIB-II / `IF-MIB` / `IP-MIB` (All Managed Switches & UPS Units)

| Symbolic Name | Numeric OID | Type | Purpose |
| :--- | :--- | :--- | :--- |
| `SNMPv2-MIB::sysDescr.0` | `1.3.6.1.2.1.1.1.0` | `OCTET STRING` | Hardware & OS version string |
| `SNMPv2-MIB::sysUpTime.0` | `1.3.6.1.2.1.1.3.0` | `TimeTicks` | System uptime ticks since last reboot |
| `SNMPv2-MIB::sysName.0` | `1.3.6.1.2.1.1.5.0` | `OCTET STRING` | Configured system hostname |
| `IF-MIB::ifAdminStatus` | `1.3.6.1.2.1.2.2.1.7` | `INTEGER` | Port admin status (`1=up`, `2=down`, `3=testing`) indexed by `ifIndex` |
| `IF-MIB::ifOperStatus` | `1.3.6.1.2.1.2.2.1.8` | `INTEGER` | Port operational link status (`1=up`, `2=down`, `5=dormant`) indexed by `ifIndex` |
| `IF-MIB::ifLastChange` | `1.3.6.1.2.1.2.2.1.9` | `TimeTicks` | `sysUpTime` value at last port state change |
| `IF-MIB::ifAlias` | `1.3.6.1.2.1.31.1.1.1.18` | `OCTET STRING` | Configured port description / circuit label |
| `IP-MIB::ipNetToMediaPhysAddress` | `1.3.6.1.2.1.4.22.1.2` | `PhysAddress` | IPv4 ARP cache MAC address table |
| `IP-MIB::ipNetToPhysicalPhysAddress` | `1.3.6.1.2.1.4.35.1.4` | `PhysAddress` | IP-version-independent neighbor MAC table |

#### B. Extreme Networks Enterprise MIBs (`1.3.6.1.4.1.1916`)

| Symbolic Name | Numeric OID | Type | Purpose |
| :--- | :--- | :--- | :--- |
| `EXTREME-SYSTEM-MIB::extremeSysVersion` | `1.3.6.1.4.1.1916.1.1.1.13.0` | `DisplayString` | Running ExtremeXOS image version |
| `EXTREME-SYSTEM-MIB::extremeSysSerialNumber` | `1.3.6.1.4.1.1916.1.1.1.16.0` | `DisplayString` | Switch chassis serial number |
| `EXTREME-POE-MIB::extremePethPortOperatorLimit` | `1.3.6.1.4.1.1916.1.27.2.1.1.4` | `INTEGER` | Configured port PoE limit in milliwatts (`mW`) |
| `EXTREME-POE-MIB::extremePethPortMeasuredPower` | `1.3.6.1.4.1.1916.1.27.2.1.1.5` | `Gauge32` | Live measured port PoE draw in milliwatts (`mW`, e.g., `12400` = `12.4W`) |

#### C. APC UPS `PowerNet-MIB` (`1.3.6.1.4.1.318`)

| Symbolic Name | Numeric OID | Type | Purpose |
| :--- | :--- | :--- | :--- |
| `PowerNet-MIB::upsBasicIdentModel` | `1.3.6.1.4.1.318.1.1.1.1.1.1.0` | `DisplayString` | APC UPS model identity (`Smart-UPS SRT 5000`) |
| `PowerNet-MIB::upsBasicStateOutputState` | `1.3.6.1.4.1.318.1.1.1.11.1.1.0` | `OCTET STRING` | 64-bit ASCII status flags (bit 4 `1` = On Line) |
| `PowerNet-MIB::upsAdvBatteryCapacity` | `1.3.6.1.4.1.318.1.1.1.2.2.1.0` | `Gauge32` | Remaining battery charge percentage (`0..100`) |
| `PowerNet-MIB::upsAdvOutputLoad` | `1.3.6.1.4.1.318.1.1.1.4.2.3.0` | `Gauge32` | Current UPS output load percentage (`0..100`) |

### 6.3 Network Probing & `/24` Scoping Constraints

1. **Strict `/24` Subnet & Recorded IP Scoping**:
   - Each site owns a `10.x.0.0/16` summary allocation (e.g., `10.42.0.0/16` for `site-042`), but only ~10 `/24` subnets are provisioned per site (e.g., `10.42.1.0/24`, `10.42.10.0/24`, `10.42.20.0/24`, `10.42.30.0/24`).
   - Active ICMP echo and SNMP probes **must only target**:
     - Explicitly recorded `mgmt_ip`, `primary_ip`, or `ip_address` records in the site batch, or
     - Host addresses within the site's explicitly allocated `/24` entries in `vlans_subnets`.
   - **Never sweep an entire `/16` prefix** (which would generate 65,534 probes per site and trigger IDS/firewall alarms across WAN links).
2. **Bounded Concurrency**:
   - ICMP probing is capped at `32` concurrent in-flight packets per site batch (`count=2`, `timeout=1.0s`).
   - Sites are processed in sequential or bounded-concurrency batches (`10.x.0.0/16` per site) with local snapshot checkpointing between stages.
