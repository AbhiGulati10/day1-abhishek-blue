#!/usr/bin/env python3
"""Detect directory enumeration in an Nginx/Apache combined access log."""
import re, sys, collections
from datetime import datetime

LOG = sys.argv[1] if len(sys.argv) > 1 else "access.log"
RX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+) "([^"]*)" "([^"]*)"$')
THRESH_404 = 50          # 404s from one IP
WINDOW_SEC = 300         # inside a 5-minute window

recs = []
for ln in open(LOG):
    m = RX.match(ln.strip())
    if m:
        ip, t, meth, path, st, size, ref, ua = m.groups()
        recs.append(dict(ip=ip, t=datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z"), m=meth, p=path, s=int(st), b=int(size), ua=ua))
print(f"[*] Parsed {len(recs)} requests\n")

by_ip = collections.defaultdict(list)
for r in recs: by_ip[r["ip"]].append(r)

print("== Top 5 IPs by 404 count ==")
rows = []
for ip, rs in by_ip.items():
    n404 = [r for r in rs if r["s"] == 404]
    rows.append((len(n404), ip, len(rs), len({r['p'] for r in n404})))
for n404, ip, tot, uniq in sorted(rows, reverse=True)[:5]:
    print(f"{ip:<16} 404s={n404:<5} total_reqs={tot:<5} unique_404_paths={uniq:<5} 404_ratio={n404/tot:.0%}")

print("\n== Detection: >=%d 404s within %ds ==" % (THRESH_404, WINDOW_SEC))
suspects = []
for ip, rs in by_ip.items():
    ts404 = sorted(r["t"] for r in rs if r["s"] == 404)
    j = 0
    for i in range(len(ts404)):
        while (ts404[i] - ts404[j]).total_seconds() > WINDOW_SEC: j += 1
        if i - j + 1 >= THRESH_404:
            suspects.append(ip); break
print("Suspects:", suspects or "none")

for ip in suspects:
    rs = sorted(by_ip[ip], key=lambda r: r["t"])
    n404 = [r for r in rs if r["s"] == 404]
    dur = (rs[-1]["t"] - rs[0]["t"]).total_seconds()
    print(f"\n=== Profile of {ip} ===")
    print(f"First seen : {rs[0]['t']}   Last seen: {rs[-1]['t']}")
    print(f"Requests   : {len(rs)} total, {len(n404)} x 404, {len({r['p'] for r in n404})} unique 404 paths")
    p1 = [r for r in rs if r['ua'].lower().startswith('gobuster')]
    if p1:
        d = (p1[-1]['t'] - p1[0]['t']).total_seconds() or 1
        print(f"Enumeration burst: {p1[0]['t'].time()} -> {p1[-1]['t'].time()}  ({len(p1)} reqs in {d:.0f}s = {len(p1)/d:.1f} req/s)")
    print("\nUser-Agents used:")
    for ua, c in collections.Counter(r["ua"] for r in rs).most_common(): print(f"  {c:>5}  {ua}")
    print("\nStatus codes:", dict(collections.Counter(r["s"] for r in rs)))
    print("\nSample of 404 paths:", ", ".join(r["p"] for r in n404[:10]))
    print("\nNon-404 hits during enumeration (successful discoveries):")
    seen = set()
    for r in rs:
        if r["s"] != 404 and r["m"] == "GET" and r["p"] not in seen and r["ua"].startswith("gobuster"):
            seen.add(r["p"]); print(f"  {r['t'].time()}  {r['s']}  {r['b']:>8} B  {r['p']}")
    posts = [r for r in rs if r["m"] == "POST"]
    if posts:
        print(f"\nFollow-up: {len(posts)} POST {posts[0]['p']}  -> statuses {dict(collections.Counter(r['s'] for r in posts))}")
        print(f"  Last POST status {posts[-1]['s']} at {posts[-1]['t'].time()}  (possible successful login!)")
