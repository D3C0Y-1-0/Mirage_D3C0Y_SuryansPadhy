"""Pass 3: containment checklist. Answers "if this attack starts now, what must I do, and by when?"

How the deadlines work:
  - The simulation (with nobody stopping it) gives the minute the attacker reaches each asset.
  - To stop it at an asset you must finish the action BEFORE the attacker arrives there:
        deadline = arrival minute - how long the action takes
  - For services: switch to backup or manual operation before the last needed asset falls, and restore the
    service before the backup runs out.
  - The detection time shows when the defenders would actually find out. Any deadline before that is one you
    would miss unless monitoring tells you sooner. That gap is the case for monitoring.

Action wording and durations are templates (assumptions, tunable in ACTIONS).
Run from project root:  python backend/containment.py
"""
from config import HORIZON_MIN
from load_graph import load_and_validate
from simulate import simulate_full, compile_model

# asset type -> (action template, minutes it takes)
ACTIONS = {
    "vendor_portal": ("Suspend the vendor's account and block {name} at the firewall", 5),
    "vpn_gateway": ("Shut remote access through {name} and reset all VPN credentials", 5),
    "telecom_gateway": ("Cut {name} off from internal networks", 5),
    "hospital_network": ("Isolate {name} and move clinical staff to paper downtime procedures", 10),
    "ehr_server": ("Take {name} offline and switch to read-only records", 10),
    "scada": ("Switch {name} to manual control and cut its link to the IT network", 10),
    "plc": ("Put {name} in local manual mode and block its network port", 10),
    "substation": ("Put {name} in local manual mode", 10),
    "generator": ("Start the backup generator by hand and disconnect {name} from the network", 8),
    "camera": ("Disconnect {name} from the network", 3),
    "medical_iot": ("Disconnect {name} and use bedside alarms", 3),
    "water_controller": ("Run {name} in manual mode", 10),
    "pump_scada": ("Run the pumps behind {name} in manual mode", 10),
    "traffic_ctrl": ("Switch traffic lights behind {name} to fixed-time mode", 8),
    "rtu": ("Put {name} in local manual control and cut its remote link", 10),
    "hmi": ("Stop operators using {name}; run from the local panels", 8),
    "pacs": ("Take {name} offline; route urgent imaging to film or a partner site", 10),
    "ad_server": ("Disable compromised accounts on {name} and block new logins from outside", 10),
    "iccc": ("Cut {name} off from field systems; run each service from its own console", 10),
    "emergency_comms": ("Switch {name} to manual radio dispatch", 5),
    "iot_gateway": ("Disconnect {name} from the network", 3),
    "cloud": ("Revoke {name}'s access tokens and block its connections", 5),
    "workstation": ("Unplug {name} from the network", 3),
    "web_server": ("Take {name} offline and show a static page", 5),
    "mail_server": ("Stop outgoing mail and quarantine the inbox on {name}", 8),
    "historian": ("Disconnect {name} from the IT network", 5),
}
DEFAULT_ACTION = ("Isolate {name} from the network", 5)
FAILOVER_MIN = 10     # minutes to switch a service to its backup or manual operation


def containment_plan(tables, entry_points, speed=1.0):
    m = compile_model(tables)
    names = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["name"]))
    types = dict(zip(tables["assets.csv"]["asset_id"], tables["assets.csv"]["type"]))
    free = simulate_full(tables, entry_points, speed, detection=False)      # if nobody stops it
    watched = simulate_full(tables, entry_points, speed, detection=True)    # when defenders would find out
    detected = watched["detected_at"]
    arrive = free["compromised"]

    items = []
    for aid, t in sorted(arrive.items(), key=lambda kv: kv[1]):
        if t > HORIZON_MIN:
            continue
        template, minutes = ACTIONS.get(types[aid], DEFAULT_ACTION)
        is_entry = aid in entry_points
        deadline = 0.0 if is_entry else max(0.0, t - minutes)
        came_from = free["parents"].get(aid)
        why = ("The attacker is already inside here." if is_entry
               else f"The attacker reaches it from {names[came_from]} at T+{t:.0f} min.")
        items.append({"kind": "asset", "target": aid, "target_name": names[aid], "deadline": round(deadline, 1),
                      "arrival": t, "duration_min": minutes, "action": template.format(name=names[aid]), "why": why})

    for name, rule, buffer_min, pop in m["services"]:
        fail = free["failures"].get(name)
        if fail is None or fail > HORIZON_MIN:
            continue
        broken_at = fail - buffer_min
        items.append({"kind": "service", "target": name, "target_name": name, "deadline": round(max(0.0, broken_at - FAILOVER_MIN), 1),
                      "arrival": broken_at, "duration_min": FAILOVER_MIN,
                      "action": f"Prepare {name} to run on backup or manual operation",
                      "why": f"Its last required system falls at T+{broken_at:.0f} min; {int(pop):,} people depend on it."})
        items.append({"kind": "service_deadline", "target": name, "target_name": name, "deadline": round(fail, 1),
                      "arrival": fail, "duration_min": 0,
                      "action": f"Restore {name} before its backup runs out",
                      "why": f"Backup covers {buffer_min:.0f} minutes. After T+{fail:.0f} min the service is lost."})

    items.sort(key=lambda i: (i["deadline"], i["kind"] != "asset"))
    for i in items:
        i["before_detection"] = detected is not None and i["deadline"] < detected
    missed = sum(1 for i in items if i["before_detection"])
    return {"items": items, "detected_at": detected, "contained_at": watched["contained_at"],
            "deadlines_before_detection": missed, "horizon_min": HORIZON_MIN}


if __name__ == "__main__":
    tables, errors = load_and_validate()
    if errors:
        raise SystemExit("Fix data first: " + "; ".join(errors))
    plan = containment_plan(tables, {"A02": 0})
    print(f"Detected at T+{plan['detected_at']}. {plan['deadlines_before_detection']} of {len(plan['items'])} "
          f"deadlines fall before anyone would notice.\n")
    for i, item in enumerate(plan["items"], 1):
        flag = "  (before detection)" if item["before_detection"] else ""
        print(f"{i:>2}. by T+{item['deadline']:>5.1f}  {item['action']}{flag}")
