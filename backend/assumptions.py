"""Assumptions register: every modelled number, what it means, where it comes from, and how it was tested.

Nothing here is a measurement from a real utility. The point of the register is that a reviewer can see every
guess in one place and the honest basis for it.
"""
import config
import recovery

SENS = "Moved ±30% one at a time (Graphs: sensitivity) and all at once 200 times (Exposure: Monte Carlo)."


def register():
    rows = [
        ("MIN_EXPLOIT_FACTOR", config.MIN_EXPLOIT_FACTOR, "Even a fully hardened system can still be reached; sets the slowest crossing speed.",
         "Engineering judgement. No published measurement.", SENS),
        ("FIREWALL_FACTOR", config.FIREWALL_FACTOR, "Each firewall level makes a link this much slower to cross (0.5 = 50% slower).",
         "Engineering judgement. No published measurement of how long a firewall delays a real intruder.", SENS),
        ("SEGMENT_FACTOR", config.SEGMENT_FACTOR, "A segmented link is this many times slower to cross.",
         "Engineering judgement. It is the number that most decides how much 'segment' fixes are worth.", SENS),
        ("TTD_MONITORED_MIN", config.TTD_MONITORED_MIN, "Minutes to detect once a monitored system is compromised.",
         "Assumes an alert that someone reviews within 10 minutes: a staffed security operations centre. Optimistic otherwise.", SENS),
        ("TTD_UNMONITORED_MIN", config.TTD_UNMONITORED_MIN, "Minutes until someone notices when nothing monitored was touched.",
         "Optimistic on purpose. Industry incident reports (e.g. Mandiant M-Trends) put median attacker dwell time in days, "
         "not hours; with a realistic value unmonitored attacks would look worse than shown.", SENS),
        ("RESPONSE_DELAY_MIN", config.RESPONSE_DELAY_MIN, "Minutes from detection until the zone is isolated.",
         "Assumes isolation is pre-approved in a playbook. Without that, hours.", SENS),
        ("HORIZON_MIN", config.HORIZON_MIN, "Harm is counted over this window so every scenario is compared on the same clock.",
         "A choice, not a fact. What happens after it is on the Recovery page.", "Fixed, so runs compare."),
        ("ENTRY_MIN_V", config.ENTRY_MIN_V, "An exposed system with no known CVE can still be a way in (phishing, stolen passwords).",
         "Floor value, judgement.", "Not varied."),
        ("FIX_STAFF_HOURS", config.FIX_STAFF_HOURS, "Staff hours each kind of fix costs; drives the optimiser's budget.",
         "Rough planning figures. Real effort depends on the site.", "Not varied; the budget can be changed on the Optimiser."),
        ("OPERATOR_ACK_MIN", config.OPERATOR_ACK_MIN, "Minutes an on-call operator has to answer before the failsafe acts alone.",
         "Policy choice for the demo, adjustable on the Failsafe page.", "Varied on the Failsafe page."),
        ("FAILSAFE_C2_ASSUMPTION", config.FAILSAFE_C2_ASSUMPTION, "Outside attackers need a live internet command channel, so cutting it stops them.",
         "Holds for interactive intrusions; false for malware that runs on its own once inside (it can be switched off on the Failsafe page).",
         "Toggle on the Failsafe page."),
        ("RESTORE_HOURS", recovery.RESTORE_HOURS, "Hours to restore each kind of system from a tested backup.", recovery.BASIS,
         "Recovery page: crews 1/2/4 with and without backups."),
        ("NO_BACKUP_FACTOR", recovery.NO_BACKUP_FACTOR, "Without a tested offline backup a system takes this many times longer (rebuild).",
         "Judgement.", "Recovery page grid."),
        ("CVE exploit probability", "KEV 0.9, else EPSS, else 0.05", "Chance a CVE is used, per CVE.",
         "Public data: CISA KEV catalogue and FIRST EPSS scores (snapshot in the dataset, not refreshed live).", "Shown per CVE on the ML page."),
    ]
    return {"rows": [{"name": n, "value": v, "meaning": m, "basis": b, "tested": t} for n, v, m, b, t in rows],
            "note": ("Every number used by the model is listed here. None is measured from a real utility; the infrastructure "
                     "itself is simulated. What is real: CVE records, CISA KEV, FIRST EPSS, the BATADAL water dataset and the "
                     "electricity benchmark.")}
