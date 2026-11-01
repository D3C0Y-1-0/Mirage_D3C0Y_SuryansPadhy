"""ALL modelling assumptions in one place.

Every number here is a guess, not a measurement. Say so on the slides.
The sensitivity check (a later step) changes these by about 30 percent and checks that the fix ranking stays stable.
"""

# ---- attack spread (simulate.py) ----
MIN_EXPLOIT_FACTOR = 0.3   # even a hardened asset can eventually be reached
FIREWALL_FACTOR = 0.5      # each firewall level makes a link 50% slower to cross
SEGMENT_FACTOR = 6.0       # a segmented link is 6x slower to cross
SPREAD_LINK_TYPES = {"network", "vendor"}   # 'dependency'/'physical' links are service logic, not attack paths

# ---- detection and containment (simulate.py) ----
TTD_MONITORED_MIN = 10      # time to detect once a MONITORED asset is compromised
TTD_UNMONITORED_MIN = 240   # time to detect otherwise (someone eventually notices)
RESPONSE_DELAY_MIN = 15     # from detection until the network is isolated and the spread stops

# ---- harm measure (harm.py) ----
HORIZON_MIN = 360           # harm counted over a 6-hour window
ENTRY_MIN_V = 0.05          # an exposed asset with no known CVE can still be an entry (phishing, stolen creds)

# ---- fix costs (fixes.py); staff hours per fix ----
FIX_STAFF_HOURS = {"patch": 2, "segment": 4, "monitor": 3, "harden": 1, "restrict_exposure": 4}
# "Remove direct exposure" (put an exposed device behind a private network or VPN) is only offered for OT
# equipment in these zones. A city cannot simply switch off its VPN, vendor portal or hospital gateway.
RESTRICT_EXPOSURE_ZONES = {"field", "control"}

# ---- failsafe and human intervention (failsafe page, water monitoring console) ----
OPERATOR_ACK_MIN = 15       # minutes the on-call operator has to acknowledge an alarm before the failsafe acts alone
FAILSAFE_AUTO = True        # if nobody acknowledges in time, cut internet and vendor access automatically
FAILSAFE_C2_ASSUMPTION = True   # outside attackers need a live internet command channel (cutting it stops them)
