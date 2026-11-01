"""Builds data_district28/: a 28-asset simulated district (hospital, city power, water, traffic, telecom).

Use it as (1) a performance and layout test before the real dataset arrives, and (2) a fallback demo dataset.
Vulnerability IDs are DEMO-xxx on purpose: they are invented and must never be presented as real CVEs.
Run from project root:  python tools/make_demo_district.py
Then start the app on it:  set CASCADE_DATA=data_district28   (Mac/Linux: export CASCADE_DATA=data_district28)
"""
import csv
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data_district28"

# id, name, type, zone, criticality, exposure, internet_facing, vendor_access, software, version, cves,
# patchable_without_downtime, downtime_hours, config_flags, monitored
ASSETS = [
    ("D01", "HVAC Vendor Portal", "vendor_portal", "vendor", 2, .9, 1, 1, "Facility vendor web portal", "3.2", "DEMO-002", 1, .5, "no_mfa", 0),
    ("D02", "Medical Device Vendor VPN", "vpn_gateway", "vendor", 3, .85, 1, 1, "Vendor remote-access appliance", "6.1", "DEMO-003", 0, 2, "no_mfa", 0),
    ("D03", "Billing Cloud Service", "cloud", "cloud", 2, .7, 1, 1, "Hospital billing SaaS", "2026.2", "DEMO-004", 1, .5, "", 0),
    ("D04", "Main VPN Gateway", "vpn_gateway", "dmz", 3, .8, 1, 0, "Remote-access VPN appliance", "7.0.4", "DEMO-001", 0, 2, "", 0),
    ("D05", "Public Website", "web_server", "dmz", 2, .9, 1, 0, "Content management system", "5.8", "DEMO-005", 1, .5, "open_mgmt_port", 0),
    ("D06", "Telecom Gateway", "telecom_gateway", "dmz", 4, .6, 1, 0, "Carrier edge router", "15.4", "DEMO-006", 0, 3, "", 0),
    ("D07", "Email Server", "mail_server", "dmz", 3, .8, 1, 0, "Mail server", "2019 CU12", "DEMO-007", 1, 1, "", 0),
    ("D08", "Hospital IT Network", "hospital_network", "enterprise", 4, .4, 0, 0, "Windows Server", "2016", "DEMO-008", 1, 1, "flat_network", 0),
    ("D09", "Patient Records Server", "ehr_server", "enterprise", 5, .3, 0, 0, "EHR application server", "11.2", "DEMO-009", 0, 4, "", 1),
    ("D10", "Directory Server", "ad_server", "enterprise", 4, .3, 0, 0, "Active Directory", "2019", "DEMO-010", 1, 1, "", 1),
    ("D11", "Staff Workstations", "workstation", "enterprise", 2, .6, 1, 0, "Windows desktops", "10 22H2", "DEMO-008", 1, 1, "", 0),
    ("D12", "Infusion Pump Network", "medical_iot", "enterprise", 5, .2, 0, 1, "Infusion pump firmware", "4.4", "DEMO-011", 0, 12, "", 0),
    ("D13", "Hospital CCTV", "camera", "enterprise", 1, .7, 1, 0, "IP camera firmware", "2.0.9", "DEMO-012", 1, .5, "default_creds", 0),
    ("D14", "Building Management", "workstation", "enterprise", 3, .3, 0, 1, "Building management system", "8.1", "DEMO-019", 1, 1, "default_creds", 0),
    ("D15", "Grid SCADA Server", "scada", "control", 5, .2, 0, 0, "Grid SCADA", "5.2", "DEMO-013", 0, 6, "default_creds", 0),
    ("D16", "Engineering Workstation", "workstation", "control", 4, .3, 0, 0, "Engineering tools", "2022", "DEMO-008", 1, 1, "no_mfa", 0),
    ("D17", "Water SCADA Server", "pump_scada", "control", 5, .2, 0, 0, "Water SCADA", "4.7", "DEMO-013", 0, 6, "", 0),
    ("D18", "Process Historian", "historian", "control", 3, .2, 0, 0, "Historian server", "2020 R2", "DEMO-015;DEMO-010", 1, 1, "", 0),
    ("D19", "Traffic Control Centre", "traffic_ctrl", "control", 3, .3, 0, 0, "Traffic management system", "9.0", "DEMO-016", 1, 1, "", 0),
    ("D20", "Substation A Controller", "plc", "field", 5, .1, 0, 0, "Protection relay and PLC", "3.4", "DEMO-014", 0, 8, "unencrypted_protocol", 0),
    ("D21", "Substation B Controller", "plc", "field", 4, .1, 0, 0, "Protection relay and PLC", "3.4", "DEMO-014", 0, 8, "unencrypted_protocol", 0),
    ("D22", "Hospital Backup Generator", "generator", "field", 4, .05, 0, 0, "Generator controller", "1.9", "DEMO-018", 0, 4, "", 0),
    ("D23", "Water Treatment Controller", "water_controller", "field", 5, .1, 0, 0, "Treatment PLC", "2.8", "DEMO-014", 0, 8, "unencrypted_protocol", 0),
    ("D24", "Pumping Station Controller", "water_controller", "field", 4, .1, 0, 0, "Pump PLC", "2.8", "DEMO-014", 0, 6, "", 0),
    ("D25", "Street Camera Network", "camera", "field", 1, .6, 1, 0, "IP camera firmware", "2.0.9", "DEMO-012", 1, .5, "default_creds", 0),
    ("D26", "Traffic Signal Controllers", "traffic_ctrl", "field", 3, .1, 0, 0, "Signal controller firmware", "7.1", "DEMO-016", 0, 3, "", 0),
    ("D27", "Hospital Battery Storage", "generator", "field", 4, .05, 0, 0, "Battery management system", "1.2", "DEMO-018", 0, 4, "", 0),
    ("D28", "Smart Meter Gateway", "telecom_gateway", "field", 3, .5, 1, 0, "Meter data gateway", "4.0", "DEMO-017", 1, 1, "open_mgmt_port", 0),
]

# src, dst, link_type, protocol, bidirectional, base_traverse_min, segmented, firewall_level
LINKS = [
    ("D01", "D14", "vendor", "https", 1, 12, 0, 1),     # HVAC vendor reaches building management
    ("D14", "D08", "network", "smb", 1, 15, 0, 0),
    ("D02", "D12", "vendor", "vpn", 1, 10, 0, 1),       # device vendor straight into infusion pumps
    ("D03", "D09", "vendor", "https", 1, 18, 0, 2),
    ("D04", "D08", "network", "vpn", 1, 10, 0, 1),
    ("D04", "D16", "network", "rdp", 1, 14, 0, 1),      # remote engineering access into OT
    ("D05", "D08", "network", "https", 1, 20, 0, 2),
    ("D07", "D11", "network", "smtp", 1, 8, 0, 1),      # phishing path
    ("D11", "D08", "network", "smb", 1, 10, 0, 0),
    ("D06", "D15", "network", "dnp3", 1, 18, 0, 1),
    ("D06", "D19", "network", "ip", 1, 15, 0, 1),
    ("D08", "D09", "network", "https", 1, 12, 0, 0),
    ("D08", "D10", "network", "ldap", 1, 8, 0, 0),
    ("D10", "D09", "network", "kerberos", 1, 8, 0, 0),
    ("D08", "D12", "network", "ip", 1, 15, 0, 1),
    ("D13", "D08", "network", "rtsp", 1, 10, 0, 0),     # cameras on the flat hospital network
    ("D10", "D18", "network", "kerberos", 1, 25, 0, 1), # historian joined to the IT domain: IT/OT bridge
    ("D16", "D15", "network", "rdp", 1, 10, 0, 0),
    ("D16", "D17", "network", "rdp", 1, 12, 0, 0),
    ("D15", "D18", "network", "opc", 1, 10, 0, 0),
    ("D17", "D18", "network", "opc", 1, 10, 0, 0),
    ("D15", "D20", "network", "modbus", 1, 10, 0, 0),
    ("D15", "D21", "network", "modbus", 1, 10, 0, 0),
    ("D15", "D27", "network", "modbus", 1, 12, 0, 1),
    ("D14", "D22", "network", "bacnet", 1, 12, 0, 0),   # building management controls the generator
    ("D17", "D23", "network", "modbus", 1, 10, 0, 0),
    ("D17", "D24", "network", "modbus", 1, 10, 0, 0),
    ("D19", "D26", "network", "ntcip", 1, 10, 0, 0),
    ("D25", "D19", "network", "rtsp", 1, 12, 0, 0),     # street cameras share the traffic network
    ("D28", "D15", "network", "dnp3", 1, 20, 0, 2),
    ("D20", "D08", "dependency", "power", 0, 0, 0, 0),
    ("D20", "D09", "dependency", "power", 0, 0, 0, 0),
]

# service_id, name, population_affected, required_logic, buffer_min
SERVICES = [
    ("S01", "Hospital Power", 5000, "D20 OR D22 OR D27", 20),
    ("S02", "Patient Records", 5000, "D09 AND D10", 15),
    ("S03", "Infusion and ICU Monitoring", 400, "D12 AND D08", 10),
    ("S04", "City Power", 60000, "D20 AND D21", 5),
    ("S05", "Water Supply", 90000, "D23 AND D24", 120),
    ("S06", "Traffic Signals", 40000, "D19 AND D26", 15),
    ("S07", "Emergency Communications", 30000, "D06", 10),
]

# cve_id, cvss, vector, cwe, vendor, product, kev, epss, ics_flag, patch_available, patch_type
VULNS = [
    ("DEMO-001", 9.8, "AV:N/AC:L/PR:N/UI:N", "CWE-287", "Demo", "VPN appliance", 1, .90, 0, 1, "patch"),
    ("DEMO-002", 6.5, "AV:N/AC:L/PR:L/UI:N", "CWE-306", "Demo", "Vendor portal", 0, .05, 0, 1, "patch"),
    ("DEMO-003", 8.8, "AV:N/AC:L/PR:L/UI:N", "CWE-287", "Demo", "Vendor VPN", 1, .60, 0, 1, "patch"),
    ("DEMO-004", 7.5, "AV:N/AC:L/PR:N/UI:N", "CWE-522", "Demo", "Billing SaaS", 0, .10, 0, 1, "patch"),
    ("DEMO-005", 9.8, "AV:N/AC:L/PR:N/UI:N", "CWE-94", "Demo", "CMS", 1, .80, 0, 1, "patch"),
    ("DEMO-006", 8.1, "AV:N/AC:H/PR:N/UI:N", "CWE-20", "Demo", "Edge router", 0, .20, 0, 1, "patch"),
    ("DEMO-007", 9.0, "AV:N/AC:L/PR:N/UI:N", "CWE-502", "Demo", "Mail server", 1, .70, 0, 1, "patch"),
    ("DEMO-008", 7.8, "AV:L/AC:L/PR:L/UI:N", "CWE-269", "Demo", "Windows", 1, .50, 0, 1, "patch"),
    ("DEMO-009", 8.6, "AV:N/AC:L/PR:L/UI:N", "CWE-89", "Demo", "EHR web app", 0, .15, 0, 1, "patch"),
    ("DEMO-010", 8.8, "AV:N/AC:L/PR:L/UI:N", "CWE-287", "Demo", "Directory service", 1, .40, 0, 1, "patch"),
    ("DEMO-011", 7.3, "AV:A/AC:L/PR:N/UI:N", "CWE-319", "Demo", "Infusion pump", 0, .02, 1, 0, "none"),
    ("DEMO-012", 9.1, "AV:N/AC:L/PR:N/UI:N", "CWE-798", "Demo", "IP camera", 1, .70, 0, 1, "patch"),
    ("DEMO-013", 8.2, "AV:N/AC:L/PR:L/UI:N", "CWE-284", "Demo", "SCADA HMI", 0, .10, 1, 1, "patch"),
    ("DEMO-014", 5.3, "AV:A/AC:L/PR:N/UI:N", "CWE-306", "Demo", "PLC Modbus", 0, .03, 1, 0, "none"),
    ("DEMO-015", 7.5, "AV:N/AC:L/PR:N/UI:N", "CWE-22", "Demo", "Historian", 0, .08, 1, 1, "patch"),
    ("DEMO-016", 6.8, "AV:N/AC:L/PR:L/UI:N", "CWE-284", "Demo", "Traffic controller", 0, .05, 1, 1, "workaround"),
    ("DEMO-017", 8.0, "AV:N/AC:L/PR:N/UI:N", "CWE-78", "Demo", "Meter gateway", 0, .10, 0, 1, "patch"),
    ("DEMO-018", 5.9, "AV:A/AC:H/PR:N/UI:N", "CWE-306", "Demo", "Generator controller", 0, .02, 1, 1, "patch"),
    ("DEMO-019", 7.2, "AV:N/AC:L/PR:N/UI:N", "CWE-798", "Demo", "Building management", 0, .12, 1, 1, "patch"),
]


def write(name, header, rows):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    write("assets.csv", ["asset_id", "name", "type", "zone", "criticality", "exposure", "internet_facing", "vendor_access",
                         "software", "version", "cve_ids", "patchable_without_downtime", "downtime_hours_to_patch",
                         "config_flags", "monitored", "layout_x", "layout_y"], [list(a) + ["", ""] for a in ASSETS])
    write("links.csv", ["src", "dst", "link_type", "protocol", "bidirectional", "base_traverse_min", "segmented", "firewall_level"], LINKS)
    write("services.csv", ["service_id", "name", "population_affected", "required_logic", "buffer_min"], SERVICES)
    write("vulns.csv", ["cve_id", "cvss", "vector", "cwe", "vendor", "product", "kev", "epss", "ics_flag", "patch_available", "patch_type"], VULNS)
    print(f"Wrote {len(ASSETS)} assets, {len(LINKS)} links, {len(SERVICES)} services, {len(VULNS)} vulnerabilities to {OUT}")
