#!/usr/bin/env python3
"""Builds the anonymised public dataset from a scanner state snapshot.
Usage: build.py <state.json> <asn.json> <out_dir>
No domain names, IP addresses, URLs or paths are written to the output."""
import sys, json, re, csv, os, collections, secrets, random

state_path, asn_path, out = sys.argv[1:4]
S = json.load(open(state_path)); ASN = json.load(open(asn_path))
os.makedirs(out + "/data", exist_ok=True)
MIN_NETWORK = 1000   # networks with fewer hosts are merged into "other"
MIN_GROUP = 300      # smaller networks / CMS / servers are merged into "other"

FLAGS = [  # (column, severity, regex over the scanner's finding text)
 ("git_exposed", 3, r"ОТКРЫТ \.git"), ("env_exposed", 3, r"ОТКРЫТ \.env"), ("svn_exposed", 3, r"ОТКРЫТ \.svn"),
 ("wp_debug_log_exposed", 3, r"debug\.log"), ("error_log_exposed", 3, r"error_log|laravel\.log"),
 ("phpinfo_exposed", 3, r"phpinfo"), ("wp_config_backup_exposed", 3, r"wp-config"),
 ("backup_archive_exposed", 3, r"Открыт архив|бэкап БД"),
 ("wp_outdated", 2, r"^WordPress .* устарел"), ("php_7_or_older", 2, r"^Устаревший"),
 ("apache_2_2_or_older", 2, r"^Старый Apache"), ("composer_file_exposed", 2, r"composer\.(json|lock)"),
 ("package_json_exposed", 2, r"package\.json"), ("ds_store_exposed", 2, r"\.DS_Store"),
 ("server_status_exposed", 2, r"server-status"), ("phpmyadmin_login_public", 2, r"phpMyAdmin"),
 ("adminer_login_public", 2, r"Adminer"), ("wp_rest_user_list", 2, r"логины пользователей"),
 ("owncloud_version_disclosed", 2, r"версия наружу"),
 ("csp_missing", 1, r"^нет CSP"), ("hsts_without_subdomains", 1, r"^HSTS без"),
]
# finding texts that describe the check itself or are published in another column / not published at all
IGNORED = re.compile(r"^DMARC слабый|^нет SPF|не отвечает нашему адресу|перестал отвечать|проверка остановлена|"
                     r"^сайт недоступен|^домен не резолвится|порт базы данных|"
                     r"^главная закрыта проверкой|^главная отвечает 403|ограничивает частоту запросов|robots\.txt")

def apex(d): return d[4:] if d.startswith("www.") else d

def status(st):
    if st.get("nodns"): return "no_dns"
    if st.get("redirect_to") and not st.get("base"): return "redirects_to_other_domain"
    if st.get("ipdown") or st.get("dead"): return "partial" if st.get("base") else "no_response"
    if st.get("blocked") or st.get("h403"): return "stopped_by_site"  # h403: the home page answered 403 or a bot challenge, nothing on it was read
    return "checked" if st.get("base") else "no_response"

CMS = [("WordPress", r"^WordPress|, WordPress"), ("Joomla", r"Joomla"), ("Drupal", r"Drupal"), ("PrestaShop", r"PrestaShop"),
       ("Wix", r"Wix\.com"), ("Hostinger Website Builder", r"Hostinger"), ("Verskis", r"Verskis"), ("eshoprent", r"eshoprent"),
       ("BaseKit", r"BaseKit"), ("Next.js", r"Next\.js"), ("Odoo", r"Odoo"), ("Webnode", r"Webnode"),
       ("ImpressPages", r"ImpressPages"), ("TYPO3", r"TYPO3")]
def cms(tech):
    if not tech: return ""
    for name, rx in CMS:
        if re.search(rx, tech): return name
    return "not_detected" if tech.split(" | ")[0] == "—" else "other"

def server(s):
    if s is None: return ""
    s = s.strip().lower()
    if s in ("", "—"): return "not_disclosed"
    return re.split(r"[/ (]", s)[0]

def branch(v):
    m = re.match(r"(\d+)\.(\d+)", v or ""); return f"{m.group(1)}.{m.group(2)}" if m else ""

rows, unmapped, plug = [], collections.Counter(), collections.Counter()
for d, st in S.items():
    if not st.get("complete"): continue
    s = status(st); home = bool(st.get("base")) and "tech" in st and not st.get("h403")
    r = {"status": s, "checked_on": (st.get("at") or "")[:10],
         "host_type": "subdomain" if len(apex(d).split(".")) > 2 else "domain"}
    a = ASN.get(st.get("ip") or "")
    r["_asn"] = (a["asn"], a["name"]) if a and a["asn"] != "NA" else None
    r["has_ip"] = bool(st.get("ip"))
    r["https"] = ("yes" if st["base"].startswith("https://") else "no") if st.get("base") else ""
    r["cms"] = cms(st.get("tech")) if home else ""
    r["wp_branch"] = branch(st.get("wp_version")) if re.match(r"\d\.\d", st.get("wp_version") or "") else ""
    m = re.search(r"PHP/(\d+\.\d+)", (st.get("tech") or "").split(" | ", 1)[1] if " | " in (st.get("tech") or "") else "")
    r["php_branch"] = m.group(1) if m else ""
    r["_server"] = server(st.get("server")) if st.get("base") else ""
    mail = home and r["host_type"] == "domain" and st.get("spf") in ("да", "НЕТ")
    r["spf"] = {"да": "yes", "НЕТ": "no"}[st["spf"]] if mail else ""
    dm = (st.get("dmarc") or "").lower()
    r["dmarc_policy"] = ("no_record" if st.get("dmarc") == "НЕТ" else dm if dm in ("none", "quarantine", "reject") else "invalid") if mail else ""
    fl = dict.fromkeys([f[0] for f in FLAGS], 0)
    for t in set(st.get("findings", [])):
        hit = False
        for col, lv, rx in FLAGS:
            if re.search(rx, t): fl[col] = 1; hit = True; break
        if not hit and not IGNORED.search(t): unmapped[t[:60]] += 1
    r.update(fl if home else dict.fromkeys(fl, ""))
    r["severity"] = max([lv for col, lv, rx in FLAGS if fl[col]] + [1 if r["spf"] == "no" or r["dmarc_policy"] in ("no_record", "none") else 0]) if home else ""
    rows.append(r)
    if r["cms"] == "WordPress":
        for p in st.get("wp_plugins_found") or list(st.get("plugins", {})): plug[p] += 1
assert not unmapped, unmapped.most_common(20)

def coarsen(key, fmt=lambda x: x, k=MIN_GROUP):
    c = collections.Counter(r[key] for r in rows if r[key])
    for r in rows:
        v = r.pop(key)
        r[key.lstrip("_")] = "" if not v else fmt(v) if c[v] >= k else "other"
coarsen("_asn", lambda a: f"AS{a[0]} {a[1].rsplit(',', 1)[0].replace('_', '').strip()}", k=MIN_NETWORK)
for r in rows:
    r["network"] = r.pop("asn") or ("other" if r["has_ip"] else ""); del r["has_ip"]
coarsen("_server")
c = collections.Counter(r["cms"] for r in rows)
for r in rows:
    if r["cms"] and c[r["cms"]] < MIN_GROUP and r["cms"] not in ("other", "not_detected"): r["cms"] = "other"
for key in ("wp_branch", "php_branch"):      # rare version branches would single a site out
    c = collections.Counter(r[key] for r in rows if r[key])
    for r in rows:
        if r[key] and c[r[key]] < 20: r[key] = "rare"

random.Random(secrets.randbits(128)).shuffle(rows)      # order carries no information; seed is not kept
COLS = ["id", "checked_on", "status", "host_type", "network", "https", "server", "cms", "wp_branch", "php_branch",
        "spf", "dmarc_policy"] + [f[0] for f in FLAGS] + ["severity"]
with open(out + "/data/sites.csv", "w", newline="") as f:
    w = csv.DictWriter(f, COLS); w.writeheader()
    for i, r in enumerate(rows, 1): w.writerow(dict(r, id=i))

def table(name, header, data):
    with open(f"{out}/data/{name}.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(data)
N = len(rows); home = [r for r in rows if r["severity"] != ""]
C = collections.Counter
table("summary_status", ["status", "hosts", "share_pct"], [(k, n, round(100*n/N, 1)) for k, n in C(r["status"] for r in rows).most_common()])
table("summary_findings", ["finding", "severity", "hosts", "share_of_inspected_pct"],
      [(col, lv, sum(1 for r in home if r[col]), round(100*sum(1 for r in home if r[col])/len(home), 2)) for col, lv, rx in FLAGS])
table("summary_severity", ["severity", "hosts", "share_of_inspected_pct"], [(k, n, round(100*n/len(home), 1)) for k, n in sorted(C(r["severity"] for r in home).items(), reverse=True)])
def by(key, name):
    g = collections.defaultdict(list)
    for r in home:
        if r[key]: g[r[key]].append(r)
    table(name, [key, "hosts_inspected", "severity_3", "severity_2", "severity_3_pct", "severity_2_or_3_pct"],
          [(k, len(v), sum(r["severity"] == 3 for r in v), sum(r["severity"] == 2 for r in v),
            round(100*sum(r["severity"] == 3 for r in v)/len(v), 1), round(100*sum(r["severity"] >= 2 for r in v)/len(v), 1))
           for k, v in sorted(g.items(), key=lambda x: -len(x[1]))])
by("cms", "summary_by_cms"); by("network", "summary_by_network"); by("server", "summary_by_server")
wp = [r for r in home if r["cms"] == "WordPress" and r["wp_branch"]]
table("summary_wordpress_branches", ["wp_branch", "hosts", "share_pct"],
      [(k, n, round(100*n/len(wp), 1)) for k, n in sorted(C(r["wp_branch"] for r in wp).items(), key=lambda x: [int(p) if p.isdigit() else -1 for p in x[0].split(".")], reverse=True)])
nwp = sum(1 for r in home if r["cms"] == "WordPress")
table("summary_wordpress_plugins", ["plugin_slug", "hosts", "share_of_wordpress_pct"], [(k, n, round(100*n/nwp, 1)) for k, n in plug.most_common() if n >= 50])
ml = [r for r in home if r["spf"]]
table("summary_mail", ["record", "value", "domains", "share_pct"],
      [("spf", k, n, round(100*n/len(ml), 1)) for k, n in C(r["spf"] for r in ml).most_common()] +
      [("dmarc_policy", k, n, round(100*n/len(ml), 1)) for k, n in C(r["dmarc_policy"] for r in ml).most_common()])
dates = sorted(r["checked_on"] for r in rows if r["checked_on"])
json.dump({"hosts": N, "inspected": len(home), "first": dates[0], "last": dates[-1], "wordpress": nwp, "wp_with_version": len(wp),
           "mail_domains": len(ml), "severity": dict(C(r["severity"] for r in home)), "status": dict(C(r["status"] for r in rows)),
           "domains": sum(r["host_type"] == "domain" for r in rows)}, open(out + "/stats.json", "w"), indent=1)
print(open(out + "/stats.json").read())
