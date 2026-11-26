# Supplementary tables

Tables built from the same scanner state as the snapshots, but outside a numbered snapshot. Counts only: no host names, IP addresses or URLs.

## server_os_2026-11-22.csv

Operating systems that web servers disclose in the `Server` response header, from the scanner state on 22 November 2026 (85,487 hosts with an inspected home page, on 18,297 IP addresses).

| Column | Meaning |
|---|---|
| `os` | System named in the header, for example `Apache/2.4.58 (Ubuntu)`. `Windows` also covers `Microsoft-IIS`. `not_disclosed` means the header names no system. |
| `server_package` | Web server and version from the same header. Combinations on fewer than 5 hosts are `other_or_no_version`. |
| `release` | Distribution release, only where the package version identifies it unambiguously and the release is retired. |
| `standard_support_ended` | End of standard security support for that release, per the vendor's release schedule. Paid extended programmes (Ubuntu Pro, ELTS, ESU) are not considered. |
| `hosts` | Hostnames. |
| `ip_addresses` | Distinct IP addresses behind those hostnames. One shared-hosting address can serve hundreds of hostnames. |

Read it with care: only 2,862 hosts (3.3%) disclose a system, so this is not the operating-system share of .lt. CDNs, managed hosting and hardened servers hide it. What the table does show is the age of the servers that speak: 809 of those 2,862 hosts (401 addresses) report a release whose standard support has ended, including 177 of 180 CentOS hosts.

The same numbers as a readable page, with notes on the method: https://aguard.lt/en/data/server-operating-systems

Release dates: ubuntu.com/about/release-cycle, debian.org/releases and wiki.debian.org/LTS, centos.org/centos-linux-eol, learn.microsoft.com/lifecycle. Rebuild with `server_os.py <state.json>`.

## plugin_vulnerabilities_2026-11-26.csv

WordPress plugins whose detected version has a publicly known vulnerability, from the scanner state of the 2026-11-26 snapshot and the vulnerability list of [wpvulnerability.com](https://www.wpvulnerability.com) (CC0) as of 26 November 2026. One row per plugin that was found on a vulnerable version on at least 20 hosts.

| Column | Meaning |
|---|---|
| `plugin_slug` | Plugin directory name. |
| `hosts` | WordPress hosts where the plugin loads files on the home page. |
| `hosts_with_version` | Of them, hosts where the plugin's version could be read. |
| `hosts_on_vulnerable_version` | Hosts whose version of the plugin has at least one known vulnerability. |
| `share_of_versioned_pct` | The previous column as a share of `hosts_with_version`. |
| `of_them_cvss_7_or_higher` | Hosts where the worst matching vulnerability has a CVSS score of 7 or more. |
| `highest_cvss` | Highest CVSS score among the matches on any host. |
| `closed_on_wordpress_org` | `1` if the plugin has been closed in the WordPress.org directory. |

Totals (`plugin_vulnerabilities_2026-11-26.json`): of 32,929 WordPress hosts, a plugin version could be read on 25,137. 21,522 of those (85.6%) run at least one plugin whose version has a known vulnerability; 17,334 (69.0%) one with CVSS 7 or more; 6,561 (26.1%) one with CVSS 9 or more. 2,102 hosts run a plugin with a vulnerability listed in CISA's Known Exploited Vulnerabilities catalogue, or one that needs no login, has CVSS 7 or more and an EPSS score of 0.5 or more.

Read it with care. Versions were read on the day of the check (mostly 14 and 15 November), the vulnerability list is of 26 November: a host that ran the latest version on the day of the check counts as vulnerable if the fix was released later. Only plugins that load files on the home page are seen. A vulnerable version does not mean the site can be compromised: many flaws need an account or particular settings. Nothing was exploited or attempted. Where a high-risk match was found, the version was read a second time from the plugin's `readme.txt` a few days later and the newer reading is used.

Rebuild with `plugin_vulns.py <state.json> <vulns.json> <date>`.
