#!/usr/bin/env python3
"""New version of the existing Zenodo record. Usage: zenodo_newversion.py <record_id> <snapshot_dir> [extra files...] [--publish]
Step 1 (no --publish): creates/reuses the draft, prints the reserved DOI. Put that DOI into README.md, then run with --publish."""
import sys, os, json, requests
args = [a for a in sys.argv[1:] if a != "--publish"]; rec, snap, extra = args[0], args[1].rstrip("/"), args[2:]
date = os.path.basename(snap); H = {"Authorization": "Bearer " + os.environ["ZENODO_AGUARD_TOKEN"]}
A = "https://zenodo.org/api/deposit/depositions"
r = requests.post(f"{A}/{rec}/actions/newversion", headers=H)
if r.status_code == 400:   # a draft of the new version already exists: reuse it
    r = requests.get(f"{A}/{rec}", headers=H)
r.raise_for_status()
d = requests.get(f"{A}/{os.environ['ZENODO_DRAFT']}" if os.environ.get("ZENODO_DRAFT") else r.json()["links"]["latest_draft"], headers=H).json()
assert str(d["id"]) != str(rec) and not d.get("submitted"), ("not a draft of a new version", d.get("id"), d.get("submitted"))
print("draft", d["id"], "reserved DOI", d["metadata"].get("prereserve_doi", {}).get("doi"))
if "--publish" not in sys.argv: sys.exit()
st = json.load(open("stats.json")); m = d["metadata"]
m["title"] = f"Security posture of .lt websites, snapshot {date}"; m["publication_date"] = date; m["version"] = date
m["description"] = (f"<p>An anonymised, row-per-host dataset from a passive security survey of websites under the Lithuanian <code>.lt</code> "
    f"top-level domain, collected by <a href=\"https://aguard.lt\">AGuard.lt</a>.</p>"
    f"<p>Snapshot {date}: {st['hosts']:,} hostnames checked between {st['first']} and {st['last']} (the complete pass); the home page was inspected on "
    f"{st['inspected']:,} of them. For each host the dataset records its status, network, server product, CMS, WordPress and PHP "
    f"branch where disclosed, SPF and DMARC records, and 21 yes/no findings such as an exposed <code>.git</code> directory, "
    f"a readable debug log, a downloadable backup or an outdated WordPress version. A supplementary table counts WordPress plugins found on a version with a known vulnerability.</p>"
    f"<p>The dataset contains no domain names, IP addresses, URLs or file paths. Column definitions, method and limitations are in "
    f"<code>README.md</code>. Every check was an ordinary unauthenticated HTTP request or DNS lookup; the scanner's address, "
    f"request list and limits are published at <a href=\"https://patikra.aguard.lt\">patikra.aguard.lt</a>.</p>")
for k in ("doi", "prereserve_doi"): m.pop(k, None)
requests.put(f"{A}/{d['id']}", json={"metadata": m}, headers=H).raise_for_status()
for f in requests.get(f"{A}/{d['id']}/files", headers=H).json():
    requests.delete(f"{A}/{d['id']}/files/{f['id']}", headers=H).raise_for_status()
files = ["README.md", "build.py"] + sorted(os.path.join(snap, f) for f in os.listdir(snap)) + extra
for p in files:
    with open(p, "rb") as f: requests.put(f"{d['links']['bucket']}/{os.path.basename(p)}", data=f, headers=H).raise_for_status()
got = {f["filename"]: f["filesize"] for f in requests.get(f"{A}/{d['id']}/files", headers=H).json()}
assert got == {os.path.basename(p): os.path.getsize(p) for p in files}, got
r = requests.post(f"{A}/{d['id']}/actions/publish", headers=H); print(r.status_code, r.text[:300] if r.status_code >= 300 else ""); r.raise_for_status()
j = r.json(); print("PUBLISHED", j["doi"], j["links"].get("record_html") or j["links"].get("html"), "concept", j.get("conceptdoi"))
