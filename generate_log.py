#!/usr/bin/env python3
"""Generate a SYNTHETIC Nginx 'combined' access log with an embedded
directory-enumeration attack. All IPs are from RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) -> not routable, not real."""
import random
from datetime import datetime, timedelta, timezone

random.seed(1337)
START = datetime(2026, 11, 24, 9, 0, 0, tzinfo=timezone.utc)
END   = datetime(2026, 11, 24, 18, 0, 0, tzinfo=timezone.utc)
ATTACKER_IP = "198.51.100.77"
CRAWLER_IP  = "192.0.2.50"

UAS = [
 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
 "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
 "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
GOOD_PATHS = ["/", "/index.html", "/about", "/products", "/products/widget-a", "/products/widget-b",
 "/contact", "/blog", "/blog/2026/security-tips", "/blog/2026/new-release", "/login", "/pricing",
 "/static/css/main.css", "/static/js/app.js", "/images/logo.png", "/favicon.ico"]
STALE_PATHS = ["/old-promo", "/blog/2019/legacy-post", "/apple-touch-icon.png", "/robots.txt"]

def ts(dt): return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
def line(ip, dt, method, path, status, size, ua, ref="-"):
    return (dt, f'{ip} - - [{ts(dt)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"')

rows = []
# --- 1. Normal users ---
pool = [f"203.0.113.{i}" for i in range(2, 40)] + [f"192.0.2.{i}" for i in range(2, 30)]
span = int((END - START).total_seconds())
for _ in range(4200):
    ip = random.choice(pool); ua = UAS[sum(map(ord, ip)) % len(UAS)]
    dt = START + timedelta(seconds=random.randint(0, span))
    r = random.random()
    if r < 0.03:
        rows.append(line(ip, dt, "GET", random.choice(STALE_PATHS), 404, 153, ua))
    elif r < 0.06:
        rows.append(line(ip, dt, "POST", "/login", random.choice([200, 302]), random.randint(200, 900), ua, "https://shop.example.test/login"))
    else:
        p = random.choice(GOOD_PATHS)
        rows.append(line(ip, dt, "GET", p, random.choice([200]*8+[304]), random.randint(600, 48000), ua, "https://shop.example.test/"))

# --- 2. Decoy: benign crawler with a few 404s (false-positive test) ---
t = START + timedelta(hours=2)
for i in range(120):
    t += timedelta(seconds=random.randint(20, 60))
    ok = random.random() > 0.1
    rows.append(line(CRAWLER_IP, t, "GET", random.choice(GOOD_PATHS) if ok else f"/blog/2018/post-{i}", 200 if ok else 404,
                     random.randint(800, 30000) if ok else 153, "Mozilla/5.0 (compatible; ExampleBot/2.1; +https://bot.example.test)"))

# --- 3. ATTACKER phase 1: gobuster-style directory enumeration ---
words = """admin administrator login panel dashboard cpanel manager backup backups bak old new test dev staging
uploads upload files images img css js scripts include includes inc lib libs vendor config conf configuration
setup install installer db database sql dump logs log tmp temp cache private secret secrets internal api api/v1
api/v2 console phpmyadmin pma mysql wp-admin wp-login.php wp-content xmlrpc.php server-status server-info
.git .git/HEAD .git/config .env .htaccess .htpasswd .svn .DS_Store backup.zip backup.sql db.sql dump.sql
site.zip www.zip config.php config.php.bak web.config robots.txt sitemap.xml crossdomain.xml readme.txt
README.md CHANGELOG.md LICENSE composer.json package.json Dockerfile docker-compose.yml debug status health
metrics swagger swagger.json openapi.json actuator actuator/health jenkins gitlab grafana kibana portal
user users account accounts profile register signup signin logout reset password forgot support help docs
doc download downloads public static assets media data export import report reports invoice invoices
shop store cart checkout order orders payment payments customer customers client clients member members
staff employee employees hr finance billing sales marketing intranet extranet vpn mail webmail email
test1 test2 demo sample examples archive archives dev1 beta alpha prod production release releases""".split()
words = list(dict.fromkeys(words))
extra = [f"{w}.{e}" for w in ["index","admin","login","test","info","backup","upload"] for e in ["php","bak","old","txt","asp","jsp"]]
wordlist = words + extra
random.shuffle(wordlist)
found = {  # path: (status, size)
 "admin": (301, 169), "uploads": (301, 169), "backup": (403, 153), "server-status": (403, 153),
 ".git/HEAD": (200, 23), "config.php.bak": (200, 1874), "backup.sql": (200, 2483921),
 "robots.txt": (200, 112), "login": (200, 2210), "api": (301, 169), ".env": (403, 153),
}
GB_UA = "gobuster/3.6"
t = START + timedelta(hours=5, minutes=32, seconds=5)
for w in wordlist:
    t += timedelta(milliseconds=random.randint(40, 110))
    st, sz = found.get(w, (404, 153))
    rows.append(line(ATTACKER_IP, t, "GET", "/" + w, st, sz, GB_UA))
phase1_end = t

# --- 4. ATTACKER phase 2: UA switched, follow-up on discoveries ---
BROWSER_UA = UAS[0]
t = phase1_end + timedelta(minutes=3)
for p, st, sz in [("/admin/", 200, 3120), ("/admin/login", 200, 2760), ("/backup.sql", 200, 2483921), ("/config.php.bak", 200, 1874)]:
    t += timedelta(seconds=random.randint(4, 15))
    rows.append(line(ATTACKER_IP, t, "GET", p, st, sz, BROWSER_UA))
for i in range(30):                       # credential-guessing against /admin/login
    t += timedelta(seconds=random.randint(1, 3))
    rows.append(line(ATTACKER_IP, t, "POST", "/admin/login", 401 if i < 29 else 302, 1040 if i < 29 else 0, BROWSER_UA, "https://shop.example.test/admin/login"))

rows.sort(key=lambda r: r[0])
with open("access.log", "w") as f:
    for _, l in rows: f.write(l + "\n")
print(f"Wrote {len(rows)} lines -> access.log")
