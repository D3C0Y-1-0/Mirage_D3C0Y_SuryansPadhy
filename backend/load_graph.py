"""Step 1: load the 4 contract CSVs, validate them, build the infrastructure graph.
Run from the project root:  python backend/load_graph.py
"""
import os
import sys
from pathlib import Path

import networkx as nx
import pandas as pd

# Which dataset folder to use. Default: data/. Switch without editing code:
#   Windows:  set CASCADE_DATA=data_stress      Mac/Linux:  export CASCADE_DATA=data_stress
_ROOT = Path(__file__).resolve().parent.parent
DATA = (_ROOT / os.environ.get("CASCADE_DATA", "data")).resolve()

REQUIRED = {
    "assets.csv": ["asset_id", "name", "type", "zone", "criticality", "exposure", "internet_facing",
                   "vendor_access", "software", "version", "cve_ids", "patchable_without_downtime",
                   "downtime_hours_to_patch", "config_flags"],
    "links.csv": ["src", "dst", "link_type", "protocol", "bidirectional", "base_traverse_min",
                  "segmented", "firewall_level"],
    "services.csv": ["service_id", "name", "population_affected", "required_logic", "buffer_min"],
    "vulns.csv": ["cve_id", "cvss", "kev", "epss", "ics_flag", "patch_available"],
}


def split_list(cell):
    if pd.isna(cell) or str(cell).strip() == "":
        return []
    return [x.strip() for x in str(cell).split(";") if x.strip()]


def load_and_validate(folder=None):
    """folder: optional other dataset folder (used to validate an upload). Default: the active DATA folder."""
    folder = Path(folder) if folder else DATA
    tables, errors = {}, []
    for fname, cols in REQUIRED.items():
        if not (folder / fname).exists():
            errors.append(f"{fname}: file missing")
            continue
        # text columns must stay text: version "5.10" must not become 5.1
        df = pd.read_csv(folder / fname, dtype={"version": str, "cve_ids": str, "config_flags": str,
                                              "asset_id": str, "src": str, "dst": str, "cve_id": str})
        missing = [c for c in cols if c not in df.columns]
        if missing:
            errors.append(f"{fname}: missing columns {missing}")
        tables[fname] = df
    if errors:
        return tables, errors

    assets, links, services, vulns = (tables[k] for k in ["assets.csv", "links.csv", "services.csv", "vulns.csv"])
    ids = set(assets["asset_id"])
    if len(ids) != len(assets):
        errors.append("assets.csv: duplicate asset_id")
    for col in ("src", "dst"):
        bad = set(links[col]) - ids
        if bad:
            errors.append(f"links.csv: {col} refers to unknown assets {sorted(bad)}")
    known_cves = set(vulns["cve_id"])
    for _, row in assets.iterrows():
        bad = set(split_list(row["cve_ids"])) - known_cves
        if bad:
            errors.append(f"assets.csv: {row['asset_id']} lists unknown CVEs {sorted(bad)}")
    if not assets["criticality"].between(1, 5).all():
        errors.append("assets.csv: criticality must be 1-5")
    if not assets["exposure"].between(0, 1).all():
        errors.append("assets.csv: exposure must be 0-1")
    return tables, errors


def build_graph(tables):
    g = nx.DiGraph()
    for _, a in tables["assets.csv"].iterrows():
        attrs = a.to_dict()
        attrs["cve_ids"] = split_list(a["cve_ids"])
        attrs["config_flags"] = split_list(a["config_flags"])
        g.add_node(a["asset_id"], **attrs)
    for _, l in tables["links.csv"].iterrows():
        attrs = l.to_dict()
        g.add_edge(l["src"], l["dst"], **attrs)
        if int(l["bidirectional"]) == 1:
            g.add_edge(l["dst"], l["src"], **attrs)
    return g


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        print("DATA PROBLEMS:")
        for e in errors:
            print(" -", e)
        sys.exit(1)
    g = build_graph(tables)
    print(f"Graph built: {g.number_of_nodes()} assets, {g.number_of_edges()} directed links")
    print(f"Services: {len(tables['services.csv'])}, CVEs: {len(tables['vulns.csv'])}")
    print("Internet-facing assets:", [n for n, d in g.nodes(data=True) if d["internet_facing"] == 1])
