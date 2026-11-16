# Security posture of .lt websites

An anonymised, row-per-host dataset from a passive security survey of websites under the Lithuanian `.lt` top-level domain, collected by [AGuard.lt](https://aguard.lt).

**Snapshot 2026-11-16** covers 125,935 hostnames checked between 14 and 16 November 2026. The home page was inspected on 73,386 of them.

The dataset contains no domain names, IP addresses, URLs or file paths. It cannot be used to look up a particular website.

## Headline numbers

Of the 73,386 hosts whose home page was inspected:

| | Hosts | Share |
|---|---|---|
| At least one critical exposure (severity 3) | 1,470 | 2.0% |
| Outdated software or a disclosed admin surface, nothing critical (severity 2) | 15,802 | 21.5% |
| Configuration gaps only (severity 1) | 53,292 | 72.6% |
| None of the listed findings | 2,822 | 3.8% |

- 31,471 hosts run WordPress. Of the 23,322 that disclose a version, 13,699 were behind the current release (7.1.4 on the survey dates).
- 1,123 hosts serve a readable WordPress `debug.log`; 126 expose a `.git` directory; 158 serve a downloadable site or database backup.
- Of 64,910 registered domains with mail records checked, 68.5% publish no DMARC record and 13.4% no SPF record.

## Files

`2026-11-16/sites.csv` has one row per hostname, in random order.

| Column | Meaning |
|---|---|
| `id` | Row number. Random; carries no information and is not stable between snapshots. |
| `checked_on` | Date of the check (UTC). Empty for 330 hosts that did not resolve or respond. |
| `status` | `checked`: all checks ran. `stopped_by_site`: the site answered 401, 403 or 429 and the check was stopped. `partial`: the site stopped responding during the check. `no_response`: no answer to the first request. `redirects_to_other_domain`: the home page redirects to a different domain, which was not followed. `no_dns`: the name does not resolve. |
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

- The host list comes from [Common Crawl](https://commoncrawl.org): `.lt` hostnames, with up to eight subdomains per registered domain. It is not the registry zone file, so it leans towards sites that are linked from elsewhere.
- Every check is an ordinary unauthenticated HTTP request for a public address, or a DNS lookup. Nothing is submitted, no login is attempted and no ports are scanned. The scanner identifies itself and honours opt-out requests; its address, request list and limits are published at [patikra.aguard.lt](https://patikra.aguard.lt).
- An exposure is recorded only when the response body matches the expected content, not on the status code alone.
- The current WordPress version was taken from `api.wordpress.org` on the survey dates.

## Limitations

- This is a snapshot of a pass still in progress: 125,935 of 136,015 listed hostnames. Most of the remainder sits on a few large shared addresses (one Lithuanian hosting provider, Cloudflare, Shopify), so those networks are under-represented.
- Versions are known only where the site discloses them. A WordPress site that hides its version is never counted as outdated, so `wp_outdated` and `php_7_or_older` are lower bounds.
- Hosts with status `stopped_by_site` or `partial` did not receive every check. Their finding columns are lower bounds too.
- `csp_missing` is evaluated only when the home page answers 200.
- Open-port data from third-party sources is not included.
- Each host was checked once. A finding may have been fixed since.

## Licence and citation

Data: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). `build.py`, which produces the files from the scanner's internal state, is included for transparency.

> AGuard.lt (2026). *Security posture of .lt websites, snapshot 2026-11-16* [Data set]. Zenodo. https://doi.org/10.5281/zenodo.24282573. https://aguard.lt

DOI of this snapshot: [10.5281/zenodo.24282573](https://doi.org/10.5281/zenodo.24282573). DOI that always points to the latest snapshot: [10.5281/zenodo.24282572](https://doi.org/10.5281/zenodo.24282572).

Contact: info@aguard.lt
