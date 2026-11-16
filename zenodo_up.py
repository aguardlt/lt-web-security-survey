#!/usr/bin/env python3
"""Uploads a snapshot folder to Zenodo. Usage: zenodo_up.py <snapshot_dir> [--publish]
Token: ZENODO_AGUARD_TOKEN in the environment."""
import sys, os, json, requests
snap = sys.argv[1].rstrip("/"); date = os.path.basename(snap)
H = {"Authorization": "Bearer " + os.environ["ZENODO_AGUARD_TOKEN"]}
A = "https://zenodo.org/api/deposit/depositions"
st = json.load(open("stats.json"))
desc = (f"<p>An anonymised, row-per-host dataset from a passive security survey of websites under the Lithuanian <code>.lt</code> "
        f"top-level domain, collected by <a href=\"https://aguard.lt\">AGuard.lt</a>.</p>"
        f"<p>Snapshot {date}: {st['hosts']:,} hostnames checked between {st['first']} and {st['last']}; the home page was inspected on "
        f"{st['inspected']:,} of them. For each host the dataset records its status, network, server product, CMS, WordPress and PHP "
        f"branch where disclosed, SPF and DMARC records, and 21 yes/no findings such as an exposed <code>.git</code> directory, "
        f"a readable debug log, a downloadable backup or an outdated WordPress version.</p>"
        f"<p>The dataset contains no domain names, IP addresses, URLs or file paths. Column definitions, method and limitations are in "
        f"<code>README.md</code>. Every check was an ordinary unauthenticated HTTP request or DNS lookup; the scanner's address, "
        f"request list and limits are published at <a href=\"https://patikra.aguard.lt\">patikra.aguard.lt</a>.</p>")
meta = {"metadata": {
    "title": f"Security posture of .lt websites, snapshot {date}", "upload_type": "dataset", "description": desc,
    "creators": [{"name": "AGuard.lt"}], "publication_date": date, "version": date, "language": "eng",
    "access_right": "open", "license": "cc-by-4.0",
    "keywords": ["web security", "Lithuania", ".lt", "WordPress", "DMARC", "SPF", "exposed files", "internet measurement"],
    "related_identifiers": [
        {"identifier": "https://github.com/aguardlt/lt-web-security-survey", "relation": "isSupplementedBy", "resource_type": "software"},
        {"identifier": "https://aguard.lt", "relation": "isDocumentedBy"}]}}
r = requests.post(A, json=meta, headers=H); r.raise_for_status(); d = r.json()
files = ["README.md", "build.py"] + sorted(os.path.join(snap, f) for f in os.listdir(snap))
for p in files:
    with open(p, "rb") as f:
        requests.put(f"{d['links']['bucket']}/{os.path.basename(p)}", data=f, headers=H).raise_for_status()
got = {f["filename"]: f["filesize"] for f in requests.get(f"{A}/{d['id']}/files", headers=H).json()}
assert got == {os.path.basename(p): os.path.getsize(p) for p in files}, got
print("draft", d["id"], d["links"]["html"], "reserved DOI", d["metadata"].get("prereserve_doi", {}).get("doi"))
if "--publish" in sys.argv:
    r = requests.post(f"{A}/{d['id']}/actions/publish", headers=H); print(r.status_code); r.raise_for_status()
    j = r.json(); print("PUBLISHED", j["doi"], j["links"].get("record_html") or j["links"].get("html"), "concept", j.get("conceptdoi"))
