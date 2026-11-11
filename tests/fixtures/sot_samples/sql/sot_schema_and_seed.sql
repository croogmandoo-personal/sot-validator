PRAGMA foreign_keys = ON;

CREATE TABLE sites (
    site_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    site_prefix TEXT NOT NULL,
    address TEXT NOT NULL,
    contact_name TEXT,
    contact_email TEXT,
    contact_phone TEXT,
    rooms TEXT NOT NULL
);

CREATE TABLE network_devices (
    device_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    hostname TEXT NOT NULL,
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    role TEXT NOT NULL,
    mgmt_ip TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    room TEXT NOT NULL,
    os_version TEXT,
    serial_number TEXT,
    last_seen TEXT
);

CREATE TABLE ports (
    port_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES network_devices(device_id),
    port_name TEXT NOT NULL,
    if_index INTEGER NOT NULL,
    admin_status TEXT NOT NULL,
    oper_status TEXT NOT NULL,
    poe_status TEXT NOT NULL,
    poe_power_w REAL NOT NULL,
    vlan_id INTEGER NOT NULL,
    connected_equipment_id TEXT,
    connected_mac TEXT,
    description TEXT,
    last_change TEXT NOT NULL
);

CREATE TABLE vlans_subnets (
    subnet_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    vlan_id INTEGER NOT NULL,
    vlan_name TEXT NOT NULL,
    cidr TEXT NOT NULL,
    gateway_ip TEXT NOT NULL,
    description TEXT
);

CREATE TABLE ip_arp_entries (
    ip_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    subnet_id TEXT NOT NULL REFERENCES vlans_subnets(subnet_id),
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    assigned_target_type TEXT NOT NULL,
    assigned_target_id TEXT NOT NULL,
    arp_last_seen TEXT,
    arp_source_device_id TEXT
);

CREATE TABLE equipment (
    equipment_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    hostname TEXT NOT NULL,
    equipment_type TEXT NOT NULL,
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    primary_ip TEXT,
    mac_address TEXT,
    vcenter_instance TEXT,
    vcenter_bios_uuid TEXT,
    vcenter_moref TEXT,
    connected_port_id TEXT REFERENCES ports(port_id),
    last_seen TEXT
);

INSERT INTO sites (site_id, name, site_prefix, address, contact_name, contact_email, contact_phone, rooms) VALUES
    ('site-042', 'SF Regional Distribution Center 42', '10.42.0.0/16', '742 Industrial Pkwy, South San Francisco, CA 94080', 'Jordan Rivera', 'netops-site042@example.internal', '+1-650-555-0142', 'MDF-101;IDF-201;UPS-Closet-B');

INSERT INTO network_devices (device_id, site_id, hostname, vendor, model, role, mgmt_ip, mac_address, room, os_version, serial_number, last_seen) VALUES
    ('dev-042-sw01', 'site-042', 'sw01.site042.example.internal', 'Extreme Networks', 'ExtremeSwitching X465-48W', 'core-switch', '10.42.1.10', '00:04:96:9a:bc:01', 'MDF-101', 'EXOS 31.7.1.4', 'SIM-EX465-04201', '2026-11-11T08:00:00Z'),
    ('dev-042-sw02', 'site-042', 'sw02.site042.example.internal', 'Extreme Networks', 'ExtremeSwitching X440-G2-24p', 'access-switch', '10.42.1.11', '00:04:96:9a:bc:02', 'IDF-201', 'EXOS 31.7.1.4', 'SIM-EX440-04202', '2026-08-01T12:00:00Z');

INSERT INTO ports (port_id, device_id, port_name, if_index, admin_status, oper_status, poe_status, poe_power_w, vlan_id, connected_equipment_id, connected_mac, description, last_change) VALUES
    ('port-042-sw01-1', 'dev-042-sw01', '1:1', 1001, 'up', 'up', 'disabled', 0.0, 10, 'eq-042-esx01', '00:50:56:60:42:01', 'Uplink to ESXi Host esx01 (VM Trunk)', '2026-10-15T09:12:00Z'),
    ('port-042-sw01-2', 'dev-042-sw01', '1:2', 1002, 'up', 'up', 'disabled', 0.0, 20, 'eq-042-san01', '00:a0:98:42:20:01', 'NetApp SAN Controller A', '2026-10-20T14:30:00Z'),
    ('port-042-sw01-3', 'dev-042-sw01', '1:3', 1003, 'up', 'up', 'delivering', 12.4, 30, 'eq-042-ups01', '00:c0:b7:42:30:01', 'APC Smart-UPS NMC3 MDF-101', '2026-10-01T06:00:00Z'),
    ('port-042-sw01-4', 'dev-042-sw01', '1:4', 1004, 'up', 'down', 'disabled', 0.0, 10, 'eq-042-srv-legacy01', '00:1b:21:42:10:99', 'Decommissioned App Server srv-legacy01', '2026-06-15T18:00:00Z'),
    ('port-042-sw01-5', 'dev-042-sw01', '1:5', 1005, 'up', 'up', 'delivering', 15.8, 20, 'eq-042-nas-sec01', '00:11:32:42:20:55', 'Isolated Security Vault NAS', '2026-11-05T11:00:00Z');

INSERT INTO vlans_subnets (subnet_id, site_id, vlan_id, vlan_name, cidr, gateway_ip, description) VALUES
    ('sub-042-001', 'site-042', 1, 'MGMT-NET', '10.42.1.0/24', '10.42.1.1', 'Network & Infrastructure Management'),
    ('sub-042-010', 'site-042', 10, 'SERVER-PROD', '10.42.10.0/24', '10.42.10.1', 'Production Servers & Virtual Machines'),
    ('sub-042-020', 'site-042', 20, 'STORAGE-SAN', '10.42.20.0/24', '10.42.20.1', 'Storage Area Network & Backup'),
    ('sub-042-030', 'site-042', 30, 'FACILITY-UPS', '10.42.30.0/24', '10.42.30.1', 'Facility Power & Environmental Monitoring');

INSERT INTO ip_arp_entries (ip_id, site_id, subnet_id, ip_address, mac_address, assigned_target_type, assigned_target_id, arp_last_seen, arp_source_device_id) VALUES
    ('ip-042-001', 'site-042', 'sub-042-001', '10.42.1.10', '00:04:96:9a:bc:01', 'network_device', 'dev-042-sw01', '2026-11-11T08:00:00Z', 'dev-042-sw01'),
    ('ip-042-002', 'site-042', 'sub-042-001', '10.42.1.11', '00:04:96:9a:bc:02', 'network_device', 'dev-042-sw02', '2026-08-01T12:00:00Z', 'dev-042-sw01'),
    ('ip-042-003', 'site-042', 'sub-042-001', '10.42.1.20', '00:50:56:60:42:01', 'equipment', 'eq-042-esx01', '2026-11-11T07:55:00Z', 'dev-042-sw01'),
    ('ip-042-004', 'site-042', 'sub-042-010', '10.42.10.21', '00:50:56:9a:42:11', 'equipment', 'eq-042-vm-win01', '2026-11-11T07:58:00Z', 'dev-042-sw01'),
    ('ip-042-005', 'site-042', 'sub-042-010', '10.42.10.22', '00:50:56:9a:42:12', 'equipment', 'eq-042-vm-win02', '2026-07-10T04:15:00Z', 'dev-042-sw01'),
    ('ip-042-006', 'site-042', 'sub-042-010', '10.42.10.99', '00:1b:21:42:10:99', 'equipment', 'eq-042-srv-legacy01', '2026-06-15T17:59:00Z', 'dev-042-sw01'),
    ('ip-042-007', 'site-042', 'sub-042-020', '10.42.20.15', '00:a0:98:42:20:01', 'equipment', 'eq-042-san01', '2026-11-11T07:50:00Z', 'dev-042-sw01'),
    ('ip-042-008', 'site-042', 'sub-042-020', '10.42.20.55', '00:11:32:42:20:55', 'equipment', 'eq-042-nas-sec01', '2026-09-20T10:00:00Z', 'dev-042-sw01'),
    ('ip-042-009', 'site-042', 'sub-042-030', '10.42.30.10', '00:c0:b7:42:30:01', 'equipment', 'eq-042-ups01', '2026-11-11T07:59:00Z', 'dev-042-sw01');

INSERT INTO equipment (equipment_id, site_id, hostname, equipment_type, vendor, model, primary_ip, mac_address, vcenter_instance, vcenter_bios_uuid, vcenter_moref, connected_port_id, last_seen) VALUES
    ('eq-042-esx01', 'site-042', 'esx01.site042.example.internal', 'Server', 'Dell', 'PowerEdge R750', '10.42.1.20', '00:50:56:60:42:01', NULL, NULL, NULL, 'port-042-sw01-1', '2026-11-11T07:55:00Z'),
    ('eq-042-vm-win01', 'site-042', 'win-dc01.site042.example.internal', 'VM', 'VMware', 'Virtual Machine', '10.42.10.21', '00:50:56:9a:42:11', 'vcenter-prod-01.example.internal', '421a0042-0001-4000-8000-0050569a4211', 'vm-10421', 'port-042-sw01-1', '2026-11-11T07:58:00Z'),
    ('eq-042-vm-win02', 'site-042', 'win-print02.site042.example.internal', 'VM', 'VMware', 'Virtual Machine', '10.42.10.22', '00:50:56:9a:42:12', 'vcenter-prod-01.example.internal', '421a0042-0002-4000-8000-0050569a4212', 'vm-10422', 'port-042-sw01-1', '2026-07-10T04:15:00Z'),
    ('eq-042-srv-legacy01', 'site-042', 'srv-legacy01.site042.example.internal', 'Server', 'HP', 'ProLiant DL380 Gen9', '10.42.10.99', '00:1b:21:42:10:99', NULL, NULL, NULL, 'port-042-sw01-4', '2026-06-15T18:00:00Z'),
    ('eq-042-san01', 'site-042', 'san01.site042.example.internal', 'SAN', 'NetApp', 'AFF A250', '10.42.20.15', '00:a0:98:42:20:01', NULL, NULL, NULL, 'port-042-sw01-2', '2026-11-11T07:50:00Z'),
    ('eq-042-nas-sec01', 'site-042', 'nas-sec01.site042.example.internal', 'NAS', 'Synology', 'RS1221+', '10.42.20.55', '00:11:32:42:20:55', NULL, NULL, NULL, 'port-042-sw01-5', '2026-09-20T10:00:00Z'),
    ('eq-042-ups01', 'site-042', 'ups01.site042.example.internal', 'UPS', 'APC', 'Smart-UPS SRT 5000VA RM', '10.42.30.10', '00:c0:b7:42:30:01', NULL, NULL, NULL, 'port-042-sw01-3', '2026-11-11T07:59:00Z'),
    ('eq-042-untracked01', 'site-042', 'spare-appliance-closetb', 'Server', 'Dell', 'PowerEdge R640', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
