# Security posture of .lt websites: an anonymised dataset from a passive survey of 125,935 hostnames

Aleksandr Izmalkov (ORCID 0009-0001-9647-2314), AGuard.lt, Lithuania. Correspondence: info@aguard.lt

Data descriptor, version of 22 November 2026.

## Abstract

Measurements of website security usually cover the most visited sites in the world, where small national domains are barely present. This descriptor documents an open dataset from a passive survey of websites under the Lithuanian country-code domain .lt, carried out on 14 to 16 November 2026. The dataset has one row for each of 125,935 hostnames and records how far the check got, the platform and web server the site reports, the versions it discloses, whether internal files such as logs, version-control directories and backups are readable from the web, and whether the domain publishes SPF and DMARC records. Home pages of 73,386 hosts were inspected. Of these, 1,470 (2.0%) had at least one critical exposure and 15,802 (21.5%) ran outdated software or disclosed an administrative surface. Of 64,910 registered domains, 68.5% published no DMARC record. The dataset contains no domain names, IP addresses or URLs, and small groups are merged, so that a row cannot be traced to a website. It is released under CC BY 4.0 with the script that built it.

Keywords: web security, measurement, country-code top-level domain, WordPress, DMARC, exposed files, open data, Lithuania

## 1. Background

Large measurements of the web have shown how security features spread and where they fail. Van Goethem et al. analysed more than 22,000 European websites and related visible security features to vulnerabilities [1]. Lavrenovs and Melón measured HTTP security headers across the top one million sites [2]. For mail, Durumeric et al. and Foster et al. measured how widely transport security, SPF and DMARC were deployed among mail providers and popular domains [3, 4]. Internet-wide scanning made such work repeatable [5], and research-oriented rankings such as Tranco made the samples comparable between studies [6].

These samples are ordered by popularity. The country-code domain of a small country contributes only a small fraction of such a list, mostly banks, media and public institutions. The long tail of a national web, where small businesses, schools and associations keep their sites, is left out. That tail is also where a site is most likely to be maintained by nobody in particular.

This dataset was collected to describe that tail for one country. It is meant for three uses: as a baseline against which later snapshots of the same domain can be compared, as teaching material for courses in data analysis and information security, and as input for comparisons with other national domains.

## 2. Methods

### 2.1 Host list

The list of hostnames comes from the Common Crawl web graph: every hostname under .lt, with at most eight subdomains kept for each registered domain. The list held 136,015 hostnames. It is not the registry zone file, which is not public, so it leans towards sites that are linked from elsewhere.

### 2.2 Checks

Each host was checked once. The scanner resolves the name, requests the home page, and then requests a fixed list of addresses where internal files are commonly left by mistake. For registered domains it also looks up the SPF and DMARC records in DNS. Every request is an ordinary unauthenticated GET for a public address, or a DNS query. Nothing is submitted, no login is attempted and no ports are scanned.

The platform is recognised from the markup of the home page. The web server is taken from the Server response header and the PHP branch from X-Powered-By. A WordPress version is recorded where the site discloses it, and compared with the release that api.wordpress.org reported as current on the survey dates (7.1.4).

An exposure is recorded only when the body of the response matches the content expected for that file. A status code of 200 alone is not enough, because many sites answer every address with the same page. For archives and database dumps the file type is confirmed from the first bytes, and the download is then stopped.

When a site answers 401, 403 or 429, the check stops and the host is marked `stopped_by_site`. The scanner identifies itself in its User-Agent, limits its rate per address, and honours requests to be left out. Its address, the full list of requests and the limits are published at https://patikra.aguard.lt

### 2.3 Severity

Each finding has a level. Level 3 is a critical exposure: a readable application log, a version-control directory, an environment file, a copy of a configuration file, a public phpinfo() page or a downloadable backup. Level 2 is outdated software or a disclosed administrative surface, for example an outdated WordPress, PHP 7 or older, a readable dependency manifest, or a database administration login page that anyone can reach. Level 1 is a configuration gap, such as a missing Content-Security-Policy header, or a domain with no SPF record or no enforcing DMARC policy. The `severity` column holds the highest level found for the host.

### 2.4 Anonymisation

The dataset was built for publication, and the build removes everything that could point to a website:

- domain names, IP addresses, URLs, page titles and file paths are dropped;
- rows are shuffled and numbered again, so the row number carries no information;
- networks announcing fewer than 1,000 hosts are merged into `other`, as are platforms and servers seen on fewer than 300 hosts and WordPress branches seen on fewer than 20;
- exact versions are reduced to branches.

The build script, `build.py`, is published with the data.

### 2.5 Ethics

The survey follows the principles commonly applied to network measurement: requests that any visitor could make, a low rate, a scanner that says who it is, and an opt-out. Findings about particular websites are not published. Where a critical exposure was found, the owner of the site could be told directly; the dataset itself is limited to counts and coarse categories so that it cannot serve as a list of targets.

## 3. Data records

The snapshot is archived at Zenodo (https://doi.org/10.5281/zenodo.24282573) and mirrored on GitHub (https://github.com/aguardlt/lt-web-security-survey). It consists of `sites.csv` and nine summary files. A persistent identifier, an open licence, plain CSV files and a published build script are meant to keep the data findable and reusable in the sense of the FAIR principles [7].

`sites.csv` has 125,935 rows and 34 columns:

| Group | Columns |
|---|---|
| Identity of the row | `id`, `checked_on`, `status`, `host_type` |
| What answers | `network`, `https`, `server`, `cms`, `wp_branch`, `php_branch` |
| Mail records | `spf`, `dmarc_policy` |
| Critical exposures | `git_exposed`, `svn_exposed`, `env_exposed`, `wp_debug_log_exposed`, `error_log_exposed`, `phpinfo_exposed`, `wp_config_backup_exposed`, `backup_archive_exposed` |
| Outdated or disclosed | `wp_outdated`, `php_7_or_older`, `apache_2_2_or_older`, `composer_file_exposed`, `package_json_exposed`, `ds_store_exposed`, `server_status_exposed`, `phpmyadmin_login_public`, `adminer_login_public`, `wp_rest_user_list`, `owncloud_version_disclosed` |
| Configuration | `csp_missing`, `hsts_without_subdomains` |
| Summary | `severity` |

Finding columns hold 1 or 0, and are empty where the home page was not inspected. The summary files aggregate `sites.csv` by status, severity, finding, platform, network, server, WordPress branch, mail records, and WordPress plugins seen on at least 50 hosts.

Table 1. Outcome of the check for each hostname.

| Status | Hosts | Share |
|---|---|---|
| All checks ran | 65,581 | 52.1% |
| Name does not resolve | 30,659 | 24.3% |
| Stopped by the site (401, 403, 429) | 10,014 | 8.0% |
| No response | 9,608 | 7.6% |
| Redirects to another domain | 8,368 | 6.6% |
| Partial | 1,705 | 1.4% |

Table 2. Highest severity among the 73,386 hosts whose home page was inspected.

| Severity | Hosts | Share |
|---|---|---|
| 3, critical exposure | 1,470 | 2.0% |
| 2, outdated software or disclosed surface | 15,802 | 21.5% |
| 1, configuration gaps only | 53,292 | 72.6% |
| 0, none of the listed findings | 2,822 | 3.8% |

Table 3. Selected findings.

| Finding | Hosts |
|---|---|
| WordPress behind the current release | 13,699 of 23,322 that disclose a version |
| PHP 7 or older disclosed | 3,247 |
| Readable WordPress debug.log | 1,123 |
| Readable composer.json | 653 |
| Downloadable site or database backup | 158 |
| Readable .git directory | 126 |
| Public phpinfo() page | 98 |

WordPress was recognised on 31,471 inspected hosts (42.9%), and 48.0% of them had a finding of level 2 or 3, against 5.4% of hosts where no platform was recognised. Two networks announce 62.7% of the inspected hosts. Of 64,910 registered domains, 86.6% publish an SPF record, 68.5% publish no DMARC record, 25.3% publish a monitoring-only policy, and 6.2% publish a policy of quarantine or reject.

## 4. Technical validation

Three properties of the method limit false positives. First, an exposure needs matching content, so a site that answers every address with its home page produces no findings. Second, archives are confirmed by file signature. Third, version findings rely only on what a site states about itself.

The same choices make several columns lower bounds. A WordPress site that hides its version is never counted as outdated. Hosts with the status `stopped_by_site` or `partial` did not receive every check. `csp_missing` is evaluated only where the home page answers 200.

The snapshot covers 125,935 of the 136,015 listed hostnames; the pass was still in progress when it was taken. Most of the remainder sits on a few large shared addresses, so those networks are under-represented. Each host was checked once, and a finding may have been fixed since.

## 5. Usage notes

The file opens in any spreadsheet and loads into pandas or R without conversion. A starter notebook that reproduces the tables above is published at https://www.kaggle.com/code/aguardlt/getting-started-security-posture-of-lt-websites

Readable tables for each question, with notes on what a number does and does not mean, are at https://aguard.lt/en/data. Questions suited to coursework and theses, with the columns each one needs, are at https://aguard.lt/en/data/research-topics

Two cautions apply to any analysis. The network column names what answers the request, so a site behind a CDN is attributed to the CDN and not to its host. And the dataset is one point in time: it describes a state, and a trend needs a second snapshot. Later snapshots will be published under the concept DOI https://doi.org/10.5281/zenodo.24282572

## Data and code availability

Data and the build script: https://doi.org/10.5281/zenodo.24282573 (CC BY 4.0). Mirrors: GitHub, Hugging Face, Kaggle, the Internet Archive and the Lithuanian national research data archive MIDAS (https://doi.org/10.18279/MIDAS.566816).

## Competing interests

The author runs AGuard.lt, a website security service in Lithuania, which operates the scanner and funded the survey. No external funding was received.

## References

1. van Goethem T, Chen P, Nikiforakis N, Desmet L, Joosen W. Large-Scale Security Analysis of the Web: Challenges and Findings. In: Trust and Trustworthy Computing. Lecture Notes in Computer Science. Springer; 2014. p. 110-126. https://doi.org/10.1007/978-3-319-08593-7_8
2. Lavrenovs A, Melón FJR. HTTP security headers analysis of top one million websites. In: 2018 10th International Conference on Cyber Conflict (CyCon). 2018. p. 345-370. https://doi.org/10.23919/CYCON.2018.8405025
3. Durumeric Z, Adrian D, Mirian A, Kasten J, Bursztein E, Lidzborski N, et al. Neither Snow Nor Rain Nor MITM...: An Empirical Analysis of Email Delivery Security. In: Proceedings of the 2015 Internet Measurement Conference. 2015. p. 27-39. https://doi.org/10.1145/2815675.2815695
4. Foster ID, Larson J, Masich M, Snoeren AC, Savage S, Levchenko K. Security by Any Other Name: On the Effectiveness of Provider Based Email Security. In: Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security. 2015. p. 450-464. https://doi.org/10.1145/2810103.2813607
5. Durumeric Z, Adrian D, Mirian A, Bailey M, Halderman JA. A Search Engine Backed by Internet-Wide Scanning. In: Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security. 2015. p. 542-553. https://doi.org/10.1145/2810103.2813703
6. Le Pochat V, Van Goethem T, Tajalizadehkhoob S, Korczyński M, Joosen W. Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation. In: Proceedings 2019 Network and Distributed System Security Symposium. 2019. https://doi.org/10.14722/ndss.2019.23386
7. Wilkinson MD, Dumontier M, Aalbersberg IJ, Appleton G, Axton M, Baak A, et al. The FAIR Guiding Principles for scientific data management and stewardship. Scientific Data. 2016;3:160018. https://doi.org/10.1038/sdata.2016.18
