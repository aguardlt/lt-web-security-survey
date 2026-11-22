"""Aggregate operating systems disclosed in the Server header. Reads the scanner state, prints CSV.
No host names, IPs or URLs leave the script: rows are counts only, groups under 5 hosts are merged."""
import json, re, sys, collections, csv
REL = {  # (os, package) -> (release, end of standard security support); only unambiguous, long-retired pairs
 ("Ubuntu","Apache/2.2.14"):("Ubuntu 10.04","2013-05-09"),("Ubuntu","Apache/2.2.22"):("Ubuntu 12.04","2017-04-28"),
 ("Ubuntu","Apache/2.4.7"):("Ubuntu 14.04","2019-04-02"),("Ubuntu","nginx/1.4.6"):("Ubuntu 14.04","2019-04-02"),
 ("Ubuntu","Apache/2.4.18"):("Ubuntu 16.04","2021-04-02"),("Ubuntu","nginx/1.10.3"):("Ubuntu 16.04","2021-04-02"),
 ("Ubuntu","Apache/2.4.29"):("Ubuntu 18.04","2023-05-31"),("Ubuntu","nginx/1.14.0"):("Ubuntu 18.04","2023-05-31"),
 ("Ubuntu","Apache/2.4.34"):("Ubuntu 18.10","2019-07-18"),("Ubuntu","Apache/2.4.41"):("Ubuntu 20.04","2025-05-31"),
 ("Debian","Apache/2.2.3"):("Debian 4","2010-02-15"),("Debian","Apache/2.2.9"):("Debian 5","2012-02-06"),
 ("Debian","Apache/2.2.16"):("Debian 6","2016-02-29"),("Debian","Apache/2.2.22"):("Debian 7","2018-05-31"),
 ("Debian","Apache/2.4.10"):("Debian 8","2020-06-30"),("Debian","Apache/2.4.25"):("Debian 9","2022-07-01"),
 ("Debian","Apache/2.4.38"):("Debian 10","2024-06-30"),
 ("CentOS","Apache/2.2.3"):("CentOS 5","2017-03-31"),("CentOS","Apache/2.2.15"):("CentOS 6","2020-11-30"),
 ("CentOS","Apache/2.4.6"):("CentOS 7","2024-06-30"),("CentOS","Apache/2.4.37"):("CentOS 8","2021-12-31"),
 ("Windows","Microsoft-IIS/7.5"):("Windows Server 2008 R2","2020-01-14"),
 ("Windows","Microsoft-IIS/8.5"):("Windows Server 2012 R2","2023-10-10"),
}
NORM = [("Ubuntu",r"^ubuntu"),("Debian",r"^(debian|raspbian)"),("CentOS",r"^centos"),("Red Hat",r"^red hat"),
        ("AlmaLinux",r"^alma"),("Rocky Linux",r"^rocky"),("SUSE",r"suse"),("FreeBSD",r"^freebsd"),("OpenBSD",r"^openbsd"),
        ("Oracle Linux",r"^oracle"),("Amazon Linux",r"^amazon"),("Fedora",r"^fedora"),("Windows",r"^win(32|64)$"),("Unix (unspecified)",r"^unix$")]
d = json.load(open(sys.argv[1]))
rows = collections.defaultdict(lambda: [0, set()]); insp = 0; ips = set()
for x in d.values():
    if not isinstance(x, dict) or not x.get("base"): continue
    insp += 1; ips.add(x.get("ip")); s = str(x.get("server") or "")
    pkg = re.sub(r"\s.*", "", s); m = re.search(r"\(([^)]+)\)", s); o = None
    if m:
        for n, r in NORM:
            if re.search(r, m.group(1).strip(), re.I): o = n; break
    if not o and re.match(r"microsoft-iis", s, re.I): o = "Windows"
    if not o: o = "not_disclosed"; pkg = ""
    if not re.match(r"^(Apache|nginx|Microsoft-IIS)/[\d.]+$", pkg): pkg = "other_or_no_version" if o != "not_disclosed" else ""
    rows[(o, pkg)][0] += 1; rows[(o, pkg)][1].add(x.get("ip"))
small = collections.defaultdict(lambda: [0, set()])
for k in list(rows):
    if rows[k][0] < 5:
        n, i = rows.pop(k); small[(k[0], "other_or_no_version")][0] += n; small[(k[0], "other_or_no_version")][1] |= i
for k, (n, i) in small.items(): rows[k][0] += n; rows[k][1] |= i
w = csv.writer(sys.stdout)
w.writerow(["os", "server_package", "release", "standard_support_ended", "hosts", "ip_addresses"])
w.writerow(["all_inspected", "", "", "", insp, len(ips)])
for (o, p), (n, i) in sorted(rows.items(), key=lambda t: (t[0][0] == "not_disclosed", -t[1][0])):
    rel, end = REL.get((o, p), ("", ""))
    w.writerow([o, p, rel, end, n, len(i)])
