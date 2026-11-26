"""Aggregate known vulnerabilities of the WordPress plugins seen on the surveyed sites.
Usage: plugin_vulns.py <state.json> <vulns.json> <date> -> supplements/plugin_vulnerabilities_<date>.csv and .json
Reads the scanner state and the compact table built from wpvulnerability.com (CC0). Counts only:
no host names, IPs or URLs leave the script, and plugins vulnerable on fewer than 20 hosts are not listed."""
import json, re, sys, csv, collections, os
S = json.load(open(sys.argv[1])); V = json.load(open(sys.argv[2])); date = sys.argv[3]
P, RC = V["p"], V.get("rc", {})
MIN = 20
def vt(v): return tuple(int(n) for n in re.findall(r"\d+", v or "")[:5])
def affects(ver, x):
    def cmp(a, b):
        n = max(len(a), len(b)); a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b)); return (a > b) - (a < b)
    ops = {"lt": lambda c: c < 0, "le": lambda c: c <= 0, "gt": lambda c: c > 0, "ge": lambda c: c >= 0, "eq": lambda c: c == 0}
    v = vt(ver)
    if x[2] and x[3] in ops and not ops[x[3]](cmp(v, vt(x[2]))): return False
    if x[0] and x[1] in ops and not ops[x[1]](cmp(v, vt(x[0]))): return False
    return True
def urgent(x): return bool(x[10] or (x[7] and (x[5] or 0) >= 7 and (x[6] or 0) >= 0.5))
def apex(d): return d[4:] if d.startswith("www.") else d

tot = collections.Counter(); per = collections.defaultdict(lambda: collections.Counter()); top = {}
for d, st in S.items():
    if not st.get("complete") or not st.get("base") or "tech" not in st or st.get("h403"): continue
    if not re.search(r"^WordPress|, WordPress", st.get("tech") or ""): continue
    tot["wordpress"] += 1
    pl = st.get("plugins") or {}
    if not pl: continue
    tot["with_plugins"] += 1
    rc = RC.get(d) or RC.get(apex(d)) or {}
    worst = -1; anyver = False; site_urgent = False; site_closed = False
    for slug, info in pl.items():
        ver = (info or {}).get("version") if isinstance(info, dict) else None
        r = rc.get(slug)
        if r and r[1] == "ok" and r[0]: ver = r[0]          # version re-read from readme.txt a few days later
        if r and r[1] in ("gone", "none"): continue            # plugin no longer there
        rec = P.get(slug) or {}
        if rec.get("c"): site_closed = True; per[slug]["closed"] = 1
        per[slug]["hosts"] += 1
        if not ver or not re.match(r"\d", str(ver)): continue   # '?' = plugin seen, version not disclosed
        anyver = True; per[slug]["with_version"] += 1
        hit = [x for x in rec.get("v", []) if affects(ver, x)]
        if not hit: continue
        mx = max((x[5] or 0) for x in hit); per[slug]["vulnerable"] += 1
        per[slug]["high"] += mx >= 7; per[slug]["critical"] += mx >= 9
        top[slug] = max(top.get(slug, 0), mx)
        if any(urgent(x) for x in hit): site_urgent = True; per[slug]["urgent"] += 1
        worst = max(worst, mx)
    tot["with_plugin_version"] += anyver
    tot["closed_plugin"] += site_closed
    if worst >= 0:
        tot["vulnerable_any"] += 1; tot["vulnerable_high"] += worst >= 7; tot["vulnerable_critical"] += worst >= 9
    tot["vulnerable_urgent"] += site_urgent
rows = sorted(((s, c) for s, c in per.items() if c["vulnerable"] >= MIN), key=lambda x: -x[1]["vulnerable"])
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin_vulnerabilities_%s" % date)
with open(out + ".csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["plugin_slug", "hosts", "hosts_with_version", "hosts_on_vulnerable_version", "share_of_versioned_pct", "of_them_cvss_7_or_higher", "highest_cvss", "closed_on_wordpress_org"])
    for s, c in rows:
        w.writerow([s, c["hosts"], c["with_version"], c["vulnerable"], round(100 * c["vulnerable"] / c["with_version"], 1), c["high"], top.get(s, 0), c["closed"]])
summary = dict(tot); summary.update(date=date, vulnerability_data_at=V.get("at"), plugins_seen=len(per), plugins_listed=len(rows), plugins_with_vulnerable_hosts=sum(1 for c in per.values() if c["vulnerable"]))
json.dump(summary, open(out + ".json", "w"), indent=1)
print(json.dumps(summary, indent=1)); print(*[(s, c["with_version"], c["vulnerable"], top[s]) for s, c in rows[:15]], sep="\n")
