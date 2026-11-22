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
