"""ShadowX - Phase 1: URL scanner (FastAPI) for Vercel.
Optional env keys (set in Vercel > Settings > Environment Variables): VT_API_KEY (VirusTotal), GSB_API_KEY (Google Safe Browsing)
"""
import asyncio, base64, ipaddress, os, re, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="ShadowX")
VT_KEY = os.getenv("VT_API_KEY")
GSB_KEY = os.getenv("GSB_API_KEY")

BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google", "amazon",
          "flipkart", "paypal", "microsoft", "apple", "netflix", "instagram", "facebook",
          "whatsapp", "irctc", "uidai", "incometax"]
RISKY_TLDS = {"xyz", "top", "click", "icu", "buzz", "tk", "ml", "ga", "cf", "gq", "work",
              "loan", "rest", "cyou", "sbs", "lol", "zip", "mov"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "goo.gl"}
SCAM_WORDS = ["kyc", "urgent", "verify your account", "account suspended", "account blocked",
              "lottery", "you have won", "claim your prize", "otp", "digital arrest",
              "free gift", "pan card update", "aadhaar update", "limited time"]
TWO_PART = {"co.in", "org.in", "gov.in", "net.in", "ac.in", "co.uk", "com.au", "com.br"}
UA = {"User-Agent": "Mozilla/5.0 (ShadowX scanner)"}


class ScanIn(BaseModel):
    url: str


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_public_host(host: str) -> bool:
    """SSRF guard: never fetch private/internal addresses."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def add(findings, level, text, points=0):
    findings.append({"level": level, "text": text, "points": points})


def url_checks(url, host, reg, findings):
    p = urlparse(url)
    if p.scheme != "https":
        add(findings, "warn", "Site HTTPS use nahi kar rahi (data secure nahi hota).", 15)
    try:
        ipaddress.ip_address(host)
        add(findings, "danger", "Link domain ki jagah seedha IP address hai.", 30)
    except ValueError:
        pass
    if "@" in p.netloc:
        add(findings, "danger", "URL mein '@' hai - ye asli site chhupane ki trick hoti hai.", 30)
    if host.startswith("xn--") or ".xn--" in host:
        add(findings, "danger", "Domain mein punycode hai (dikhne mein same, asal mein alag letters).", 30)
    if reg in SHORTENERS:
        add(findings, "warn", "Short link hai - asli destination chhupa hua hai.", 15)
    if reg.split(".")[-1] in RISKY_TLDS:
        add(findings, "warn", f"Domain ending '.{reg.split('.')[-1]}' scams mein bahut use hoti hai.", 15)
    if host.count("-") >= 3 or host.count(".") >= 4:
        add(findings, "warn", "Domain bahut lamba / hyphens ya subdomains se bhara hai.", 10)
    label = reg.split(".")[0]
    for b in BRANDS:
        if b in host and label != b:
            add(findings, "danger", f"Domain mein '{b}' naam hai par ye asli {b} ka domain nahi lagta (lookalike).", 35)
            break


async def domain_age(reg, findings):
    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
        r = await c.get(f"https://rdap.org/domain/{reg}")
    if r.status_code != 200:
        return
    for ev in r.json().get("events", []):
        if ev.get("eventAction") == "registration":
            d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - d).days
            if days < 30:
                add(findings, "danger", f"Domain sirf {days} din purana hai - naye domain scam mein common hain.", 30)
            elif days < 180:
                add(findings, "warn", f"Domain sirf {days} din purana hai.", 15)
            else:
                add(findings, "ok", f"Domain {days // 365} saal+ purana hai." if days >= 365 else f"Domain {days} din purana hai.")
            return


def _tls_expiry(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
    return datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


async def tls_check(host, findings):
    try:
        exp = await asyncio.to_thread(_tls_expiry, host)
        left = (exp - datetime.now(timezone.utc)).days
        if left < 0:
            add(findings, "danger", "SSL certificate expire ho chuka hai.", 25)
        else:
            add(findings, "ok", f"SSL certificate valid hai ({left} din bacha).")
    except ssl.SSLCertVerificationError:
        add(findings, "danger", "SSL certificate invalid hai.", 30)
    except OSError:
        pass  # no HTTPS available; already flagged above


async def page_check(url, findings):
    html, cur = "", url
    async with httpx.AsyncClient(timeout=8, headers=UA, follow_redirects=False) as c:
        for _ in range(4):
            if not is_public_host(urlparse(cur).hostname or ""):
                return
            r = await c.get(cur)
            if r.is_redirect and "location" in r.headers:
                cur = urljoin(cur, r.headers["location"])
                continue
            html = r.text[:300_000]
            break
    if cur != url and urlparse(cur).hostname != urlparse(url).hostname:
        add(findings, "warn", f"Link doosri site pe redirect karta hai: {urlparse(cur).hostname}", 10)
    low = html.lower()
    hits = [w for w in SCAM_WORDS if w in low]
    if hits:
        add(findings, "warn", "Page mein scam wale words mile: " + ", ".join(hits[:5]), min(10 + 5 * len(hits), 25))
    if re.search(r"type=[\"']?password", low):
        add(findings, "warn", "Page par password / login form hai - sirf tabhi daalo jab site 100% asli ho.", 10)
        for m in re.finditer(r"<form[^>]+action=[\"']?(https?://[^\"'\s>]+)", low):
            if urlparse(m.group(1)).hostname != urlparse(cur).hostname:
                add(findings, "danger", "Login form ka data doosri site pe ja raha hai.", 30)
                break


async def virustotal(url, findings):
    if not VT_KEY:
        return
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": VT_KEY})
    if r.status_code == 200:
        s = r.json()["data"]["attributes"]["last_analysis_stats"]
        bad = s.get("malicious", 0) + s.get("suspicious", 0)
        if bad:
            add(findings, "danger", f"VirusTotal pe {bad} security engines ne isse flag kiya.", min(30 + 5 * bad, 60))
        else:
            add(findings, "ok", "VirusTotal pe koi engine ne flag nahi kiya.")


async def safe_browsing(url, findings):
    if not GSB_KEY:
        return
    body = {"client": {"clientId": "shadowx", "clientVersion": "0.1"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}", json=body)
    if r.status_code == 200 and r.json().get("matches"):
        add(findings, "danger", "Google Safe Browsing ne ise phishing/malware list mein daala hai.", 60)


@app.post("/api/index")
@app.post("/api/scan/url")
async def scan_url(body: ScanIn):
    raw = body.url.strip()
    if not raw:
        raise HTTPException(400, "Link khaali hai.")
    url = raw if re.match(r"^https?://", raw, re.I) else "http://" + raw
    host = (urlparse(url).hostname or "").lower()
    if not host or "." not in host:
        raise HTTPException(400, "Ye valid link nahi lag raha.")
    reg = registered_domain(host)
    findings: list = []
    url_checks(url, host, reg, findings)

    tasks = [domain_age(reg, findings), virustotal(url, findings), safe_browsing(url, findings)]
    if is_public_host(host):
        tasks += [tls_check(host, findings), page_check(url, findings)]
    else:
        add(findings, "warn", "Ye domain resolve nahi ho raha ya internal address hai, isliye page scan nahi hua.", 10)
    await asyncio.gather(*tasks, return_exceptions=True)

    score = min(100, sum(f["points"] for f in findings))
    verdict = "safe" if score < 25 else "suspicious" if score < 55 else "dangerous"
    findings.sort(key=lambda f: -f["points"])
    return {"url": url, "host": host, "score": score, "verdict": verdict, "findings": findings,
            "apis": {"virustotal": bool(VT_KEY), "safe_browsing": bool(GSB_KEY)}}


PAGE = r'''<!DOCTYPE html>
<html lang="hi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowX - Scam aur fraud scanner</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🕶️</text></svg>">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600;800&family=Hind:wght@400;500&display=swap">
<style>
:root{--bg:#14131f;--panel:#1e1c2e;--line:#322f4a;--text:#ebe8f7;--muted:#9c98b8;--accent:#aa9dff;
--safe:#5bd1a5;--warn:#f2b14c;--danger:#f0645e;--c:var(--accent)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 Hind,system-ui,sans-serif}
main{max-width:720px;margin:0 auto;padding:48px 20px 80px}
.brand{font:800 22px Sora,sans-serif;letter-spacing:-.5px}
.brand b{color:var(--accent)}
h1{font:800 clamp(30px,6vw,46px)/1.12 Sora,sans-serif;letter-spacing:-1px;margin:40px 0 12px;max-width:16ch}
.sub{color:var(--muted);margin:0 0 28px;max-width:50ch}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.tab{background:none;border:1px solid var(--line);color:var(--muted);padding:8px 14px;border-radius:999px;font:inherit;cursor:not-allowed}
.tab.on{background:var(--accent);border-color:var(--accent);color:#14131f;font-weight:500;cursor:default}
.tab small{opacity:.7;margin-left:4px}
form{display:flex;gap:8px;flex-wrap:wrap}
input{flex:1 1 280px;background:var(--panel);border:1px solid var(--line);color:var(--text);padding:14px 16px;border-radius:12px;font:inherit}
input:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button.go{background:var(--accent);color:#14131f;border:0;padding:14px 22px;border-radius:12px;font:600 16px Sora,sans-serif;cursor:pointer}
button.go:disabled{opacity:.6;cursor:wait}
#out{margin-top:36px}
.res{display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.ring{--c:var(--accent);width:132px;height:132px;border-radius:50%;flex:none;display:grid;place-items:center;
background:conic-gradient(var(--c) calc(var(--p)*1%),var(--line) 0);box-shadow:14px 14px 0 -2px color-mix(in srgb,var(--c) 22%,transparent)}
.ring span{width:104px;height:104px;border-radius:50%;background:var(--bg);display:grid;place-items:center;font:800 34px Sora,sans-serif}
.verdict{font:800 28px Sora,sans-serif;color:var(--c)}
.host{color:var(--muted);word-break:break-all}
ul{list-style:none;padding:0;margin:28px 0 0;display:grid;gap:8px}
li{background:var(--panel);border-left:4px solid var(--line);padding:12px 14px;border-radius:8px}
li.danger{border-color:var(--danger)}li.warn{border-color:var(--warn)}li.ok{border-color:var(--safe)}
.note{color:var(--muted);font-size:14px;margin-top:24px}
.note a{color:var(--accent)}
.err{color:var(--danger)}
@media(prefers-reduced-motion:no-preference){.ring{transition:background .6s}}
</style>
</head>
<body>
<main>
  <div class="brand">Shadow<b>X</b></div>
  <h1>Bharosa karne se pehle scan karo.</h1>
  <p class="sub">Koi bhi link daalo. ShadowX bataega ki wo safe hai, suspicious hai ya scam, aur kyun.</p>

  <div class="tabs">
    <button class="tab on" type="button">Website / Link</button>
    <button class="tab" type="button" disabled>Screenshot <small>Phase 2</small></button>
    <button class="tab" type="button" disabled>APK file <small>Phase 3</small></button>
  </div>

  <form id="f">
    <input id="u" type="text" placeholder="Link paste karo, jaise sbi-login-secure.xyz" autocomplete="off" required>
    <button class="go" id="b">Scan karo</button>
  </form>

  <section id="out" aria-live="polite"></section>
</main>

<script>
const out = document.getElementById('out'), btn = document.getElementById('b');
const LABEL = {safe:'Safe lag raha hai', suspicious:'Suspicious hai', dangerous:'Khatarnak hai'};
const COLOR = {safe:'var(--safe)', suspicious:'var(--warn)', dangerous:'var(--danger)'};

document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault();
  btn.disabled = true; btn.textContent = 'Scan ho raha hai...'; out.textContent = '';
  try {
    const r = await fetch('/api/index', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({url: document.getElementById('u').value})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Scan fail ho gaya.');
    render(d);
  } catch (err) {
    const p = document.createElement('p'); p.className = 'err'; p.textContent = err.message; out.append(p);
  }
  btn.disabled = false; btn.textContent = 'Scan karo';
});

function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }

function render(d) {
  const res = el('div', 'res'), ring = el('div', 'ring');
  ring.style.setProperty('--p', d.score); ring.style.setProperty('--c', COLOR[d.verdict]);
  ring.append(el('span', null, d.score));
  const info = el('div'); info.style.setProperty('--c', COLOR[d.verdict]);
  info.append(el('div', 'verdict', LABEL[d.verdict]), el('div', 'host', d.host), el('div', 'host', 'Risk score: ' + d.score + '/100'));
  res.append(ring, info);

  const ul = el('ul');
  d.findings.forEach(f => ul.append(el('li', f.level, f.text)));
  if (!d.findings.length) ul.append(el('li', 'ok', 'Koi red flag nahi mila.'));

  const keys = [];
  if (!d.apis.virustotal) keys.push('VirusTotal');
  if (!d.apis.safe_browsing) keys.push('Google Safe Browsing');
  const note = el('p', 'note', 'Koi bhi scanner 100% pakka nahi hota. Shak ho to paise ya OTP mat do. ');
  if (keys.length) note.append(keys.join(' aur ') + ' ki API key abhi set nahi hai, isliye wo check skip hue. ');
  const a = el('a', null, 'Scam hua? cybercrime.gov.in ya 1930 pe report karo.');
  a.href = 'https://cybercrime.gov.in'; a.target = '_blank'; a.rel = 'noopener';
  note.append(a);
  out.append(res, ul, note);
}
</script>
</body>
</html>
'''


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE
