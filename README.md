# Security posture of .lt websites

An anonymised, row-per-host dataset from a passive security survey of websites under the Lithuanian `.lt` top-level domain, collected by [AGuard.lt](https://aguard.lt).

**Snapshot 2026-11-26** covers 143,654 hostnames checked between 14 and 26 November 2026: the complete pass. The home page was inspected on 81,467 of them. The earlier snapshot 2026-11-16 (125,935 hostnames, taken while the pass was still running) stays in the repository and on Zenodo.

The dataset contains no domain names, IP addresses, URLs or file paths. It cannot be used to look up a particular website.

## Headline numbers

Of the 81,467 hosts whose home page was inspected:

| | Hosts | Share |
|---|---|---|
| At least one critical exposure (severity 3) | 1,612 | 2.0% |
| Outdated software or a disclosed admin surface, nothing critical (severity 2) | 16,488 | 20.2% |
| Configuration gaps only (severity 1) | 60,424 | 74.2% |
| None of the listed findings | 2,943 | 3.6% |

- 32,929 hosts run WordPress. Of the 24,291 that disclose a version, 14,351 were behind the release that was current on the day of the check (7.1.4, and 7.1.5 from 18 November).
- 1,214 hosts serve a readable WordPress `debug.log`; 140 expose a `.git` directory; 194 serve a downloadable site or database backup.
- Of 72,724 registered domains with mail records checked, 69.3% publish no DMARC record and 14.0% no SPF record.

## Files

`2026-11-26/sites.csv` has one row per hostname, in random order.

| Column | Meaning |
|---|---|
| `id` | Row number. Random; carries no information and is not stable between snapshots. |
| `checked_on` | Date of the check (UTC). Empty for 330 hosts that did not resolve or respond. |
| `status` | `checked`: all checks ran. `stopped_by_site`: the site answered 401, 403, 429 or a bot challenge, or its `robots.txt` disallows the scanner, and the check was stopped. `partial`: the site stopped responding during the check. `no_response`: no answer to the first request. `redirects_to_other_domain`: the home page redirects to a different domain, which was not followed. `no_dns`: the name does not resolve. |
| `host_type` | `domain` for a registered name (with or without `www`), `subdomain` otherwise. |
| `network` | Autonomous system announcing the host's address. Networks with fewer than 1,000 hosts in the snapshot are `other`. A CDN or proxy such as Cloudflare appears here in place of the origin host. |
| `https` | Whether the home page was served over HTTPS. |
| `server` | Product name from the `Server` header, without version. Values on fewer than 300 hosts are `other`. |
| `cms` | Platform recognised from the home page markup. `not_detected` means none of the signatures matched. |
| `wp_branch` | WordPress branch (for example `6.8`) where the site discloses it. Branches on fewer than 20 hosts are `rare`. |
| `php_branch` | PHP branch where the `X-Powered-By` header discloses it. |
| `spf` | Whether the domain publishes an SPF record. Empty for subdomains. |
| `dmarc_policy` | `no_record`, `none`, `quarantine` or `reject`. Empty for subdomains. |
| `severity` | Highest severity among the findings below: 3, 2, 1, or 0 for none. Empty where the home page was not inspected. |

Finding columns are `1` or `0`, and empty where the home page was not inspected.

| Column | Severity | Meaning |
|---|---|---|
| `git_exposed`, `svn_exposed` | 3 | Version-control metadata is readable over HTTP. |
| `env_exposed` | 3 | An environment file is readable. |
| `wp_debug_log_exposed`, `error_log_exposed` | 3 | An application log is readable. |
| `phpinfo_exposed` | 3 | A `phpinfo()` page is public. |
| `wp_config_backup_exposed` | 3 | A copy of the WordPress configuration file is readable. |
| `backup_archive_exposed` | 3 | A site archive or database dump is downloadable; the file type was confirmed from its first bytes. |
| `wp_outdated` | 2 | The disclosed WordPress version is older than the current release. |
| `php_7_or_older` | 2 | The disclosed PHP version is 7.x or older. |
| `apache_2_2_or_older` | 2 | The `Server` header discloses Apache 2.2 or older. |
| `composer_file_exposed`, `package_json_exposed` | 2 | A dependency manifest is readable. |
| `ds_store_exposed` | 2 | A macOS `.DS_Store` file is readable. |
| `server_status_exposed` | 2 | The Apache status page is public. |
| `phpmyadmin_login_public`, `adminer_login_public` | 2 | A database administration login page is reachable. No login was attempted. |
| `wp_rest_user_list` | 2 | The WordPress REST API lists user names. |
| `owncloud_version_disclosed` | 2 | An ownCloud or Nextcloud instance discloses its version. |
| `csp_missing` | 1 | The home page sends no `Content-Security-Policy` header. |
| `hsts_without_subdomains` | 1 | HSTS is set without `includeSubDomains`. |

A missing SPF record, or a DMARC policy of `no_record` or `none`, also counts as severity 1.

The `summary_*.csv` files are aggregates of `sites.csv`: by status, severity, finding, CMS, network, server, WordPress branch, mail records, and WordPress plugins seen on at least 50 hosts.

## Method

- The host list comes from [Common Crawl](https://commoncrawl.org): `.lt` hostnames, with up to eight subdomains per registered domain. To it were added 7,667 registered `.lt` domains found among the outgoing links of four large Lithuanian websites in a commercial link index (Ahrefs). It is not the registry zone file, so it leans towards sites that are linked from elsewhere.
- Every check is an ordinary unauthenticated HTTP request for a public address, or a DNS lookup. Nothing is submitted, no login is attempted and no ports are scanned. The scanner identifies itself and honours opt-out requests; its address, request list and limits are published at [patikra.aguard.lt](https://patikra.aguard.lt).
- An exposure is recorded only when the response body matches the expected content, not on the status code alone.
- The current WordPress version was taken from `api.wordpress.org` on the day of each check.

## Limitations

- The pass is complete: 143,654 of 143,663 listed hostnames; the remaining 9 kept answering 429. Four in five hosts were checked on 14 and 15 November, the rest by 26 November.
- The scanner changed during the pass. From 23 November it honours `robots.txt`, backs off when a server answers 429, and records a home page that answers 403 or a bot challenge as `stopped_by_site` without reading anything from it. About 10,800 hosts were checked or rechecked under these rules.
- Versions are known only where the site discloses them. A WordPress site that hides its version is never counted as outdated, so `wp_outdated` and `php_7_or_older` are lower bounds.
- Hosts with status `stopped_by_site` or `partial` did not receive every check. Their finding columns are lower bounds too.
- `csp_missing` is evaluated only when the home page answers 200.
- Open-port data from third-party sources is not included.
- Each host was checked once. A finding may have been fixed since.

## Using the data

- Tables for each question, with notes on what a number does and does not mean: [aguard.lt/en/data](https://aguard.lt/en/data) (Lithuanian: [aguard.lt/duomenys](https://aguard.lt/duomenys)).
- Questions for coursework and theses, with the columns each one needs: [research topics](https://aguard.lt/en/data/research-topics) (Lithuanian: [temos darbams](https://aguard.lt/duomenys/temos-darbams)).
- A starter notebook that reproduces the headline numbers: [Kaggle](https://www.kaggle.com/code/aguardlt/getting-started-security-posture-of-lt-websites), source in `kaggle/notebook/`.
- Supplementary table of WordPress plugins found on a version with a known vulnerability: [`supplements/plugin_vulnerabilities_2026-11-26.csv`](supplements/), as a page: [WordPress plugins](https://aguard.lt/en/data/wordpress-plugins).
- Supplementary table of server operating systems named in the `Server` header: [`supplements/`](supplements/), as a page: [server operating systems](https://aguard.lt/en/data/server-operating-systems).

If you use the dataset in a thesis, a class or a publication, write to info@aguard.lt and it will be listed here.

## Licence and citation

Data: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). `build.py`, which produces the files from the scanner's internal state, is included for transparency.

> AGuard.lt (2026). *Security posture of .lt websites, snapshot 2026-11-26* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.24569877. https://aguard.lt

DOI of this snapshot: [10.5281/zenodo.24569877](https://doi.org/10.5281/zenodo.24569877). Snapshot 2026-11-16: [10.5281/zenodo.24282573](https://doi.org/10.5281/zenodo.24282573). DOI that always points to the latest snapshot: [10.5281/zenodo.24282572](https://doi.org/10.5281/zenodo.24282572).

Contact: info@aguard.lt
