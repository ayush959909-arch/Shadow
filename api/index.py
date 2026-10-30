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
from typing import Optional

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


class Req(BaseModel):
    kind: str = "url"
    url: str = ""
    text: str = ""
    apk: Optional[dict] = None


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


def finish(host, findings):
    score = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    verdict = "safe" if score < 25 else "suspicious" if score < 55 else "dangerous"
    return {"host": host, "score": score, "verdict": verdict, "findings": findings,
            "apis": {"virustotal": bool(VT_KEY), "safe_browsing": bool(GSB_KEY)}}


async def analyze_url(raw: str):
    raw = raw.strip()
    if not raw:
        raise HTTPException(400, "Link khaali hai.")
    url = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
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
    r = finish(host, findings)
    r["url"] = url
    return r


# ---------- Phase 2: screenshot text analysis ----------
TEXT_RULES = [
    (r"\bkyc\b|account (?:will be )?(?:blocked|suspended|closed|deactivated)|pan (?:card )?(?:update|expired)|aadhaar (?:update|link)",
     "danger", "KYC ya account band hone ka darr dikhaya gaya hai. Banks aise link se KYC nahi karte.", 30),
    (r"lottery|you have won|you won|lucky draw|\bprize\b|\bkbc\b|congratulations",
     "danger", "Lottery ya inaam ka laalach. Ye sabse common scam hai.", 30),
    (r"digital arrest|\bcbi\b|narcotics|customs|enforcement directorate|cyber ?crime branch|arrest warrant|parcel",
     "danger", "Police, CBI ya courier ke naam pe dhamki. Digital arrest scam jaisa lagta hai. Asli police video call pe arrest nahi karti.", 35),
    (r"work from home|part[- ]time job|earn (?:rs\.?|inr)?\s?\d|daily income|per day|like (?:and|&) subscribe|\btasks?\b",
     "warn", "Ghar baithe kamai ya job ka offer. Fake job scam ka pattern.", 25),
    (r"\botp\b|\bcvv\b|\bpin\b|password|card number",
     "danger", "OTP, PIN, CVV ya password maanga ja raha hai. Ye kabhi kisi ko mat batao.", 25),
    (r"urgent|immediately|within \d+ ?(?:hours|hrs|minutes|mins)|last chance|expires? (?:today|soon)",
     "warn", "Jaldi karne ka dabav. Scammers sochne ka time nahi dete.", 10),
    (r"refund|cashback|reward points|claim now",
     "warn", "Refund ya cashback ka laalach.", 15),
    (r"\.apk\b|download (?:the )?app|install (?:the )?app",
     "danger", "App install karne ko kaha ja raha hai. Play Store ke bahar ki app se phone hack ho sakta hai.", 30),
    (r"electricity|bijli|power (?:will be )?(?:cut|disconnect)|disconnect(?:ed|ion)",
     "danger", "Bijli connection kaatne ki dhamki. Common fake bill scam.", 30),
    (r"payment (?:successful|received|sent)|transaction id|\butr\b|paid to|credited",
     "warn", "Ye payment screenshot lagta hai. Screenshot nakli ho sakta hai, paisa apne bank app mein check karo.", 10),
]
TLDS = "com|in|xyz|top|click|icu|buzz|tk|ml|ga|cf|gq|work|loan|rest|cyou|sbs|lol|net|org|co|info|online|site|link|app|me|live|shop"
LINK_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:" + TLDS + r")\b(?:/[^\s<>\"']*)?", re.I)
UPI_RE = re.compile(r"\b[\w.\-]{2,}@(?:ok\w+|ybl|ibl|axl|paytm|upi|apl|sbi|hdfcbank|icici|axisbank|pnb|barodampay|fam|freecharge)\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{9}(?!\d)")


async def analyze_text(text: str):
    if len(text.strip()) < 10:
        raise HTTPException(400, "Screenshot se text nahi nikla. Saaf aur bada screenshot try karo.")
    text = text[:5000]
    low = text.lower()
    findings: list = []
    for pat, lvl, msg, pts in TEXT_RULES:
        if re.search(pat, low):
            add(findings, lvl, msg, pts)
    links = []
    for m in LINK_RE.findall(text):
        m = m.strip(".,;:)]}>\"'")
        if m.lower() not in [x.lower() for x in links] and "@" not in m:
            links.append(m)
    upi = list(dict.fromkeys(UPI_RE.findall(text)))[:5]
    phones = list(dict.fromkeys(re.sub(r"\D", "", p)[-10:] for p in PHONE_RE.findall(text)))[:5]
    results = await asyncio.gather(*[analyze_url(l) for l in links[:3]], return_exceptions=True)
    for l, r in zip(links[:3], results):
        if isinstance(r, dict) and r["verdict"] != "safe":
            lab = "Khatarnak" if r["verdict"] == "dangerous" else "Suspicious"
            add(findings, "danger" if r["verdict"] == "dangerous" else "warn",
                f"Screenshot ka link {r['host']} scan kiya: {lab} (risk {r['score']}/100).", 40 if r["verdict"] == "dangerous" else 20)
        elif isinstance(r, dict):
            add(findings, "ok", f"Screenshot ka link {r['host']} safe lag raha hai.")
    if links: add(findings, "info", "Screenshot mein mile links: " + ", ".join(links[:5]), 0)
    if upi: add(findings, "info", "UPI ID mili: " + ", ".join(upi) + ". Unknown UPI ID pe paisa mat bhejo.", 0)
    if phones: add(findings, "info", "Phone number mile: " + ", ".join(phones) + ". Unknown number pe bharosa mat karo.", 0)
    if not findings:
        add(findings, "ok", "Koi scam pattern nahi mila. Phir bhi paisa ya OTP dene se pehle sochna.")
    return finish("Screenshot scan", findings)


# ---------- Phase 3: APK analysis (file stays in the browser; only metadata comes here) ----------
APK_PERMS = {
    "READ_SMS": (20, "SMS padh sakti hai. OTP chori ho sakte hain."),
    "RECEIVE_SMS": (15, "Aane wale SMS dekh sakti hai (OTP chori ka risk)."),
    "SEND_SMS": (15, "Aapke naam se SMS bhej sakti hai (premium SMS fraud)."),
    "BIND_ACCESSIBILITY_SERVICE": (25, "Accessibility control maangti hai. Banking trojan screen padh ke paisa nikaal sakte hain."),
    "SYSTEM_ALERT_WINDOW": (15, "Doosri apps ke upar overlay dikha sakti hai (fake login screen)."),
    "BIND_DEVICE_ADMIN": (25, "Device admin banna chahti hai. Uninstall karna mushkil ho sakta hai."),
    "BIND_NOTIFICATION_LISTENER_SERVICE": (20, "Saare notifications padh sakti hai (OTP bhi)."),
    "READ_CALL_LOG": (15, "Call history padh sakti hai."),
    "PROCESS_OUTGOING_CALLS": (15, "Aapki calls ko monitor ya redirect kar sakti hai."),
    "READ_CONTACTS": (10, "Aapke saare contacts padh sakti hai."),
    "RECORD_AUDIO": (10, "Mic se recording kar sakti hai."),
    "REQUEST_INSTALL_PACKAGES": (10, "Aur apps install kar sakti hai."),
    "MANAGE_EXTERNAL_STORAGE": (10, "Phone ki saari files ka access maangti hai."),
    "QUERY_ALL_PACKAGES": (5, "Phone mein installed saari apps ki list dekh sakti hai."),
}
BENIGN = {"google.com", "googleapis.com", "gstatic.com", "android.com", "w3.org", "apache.org", "xmlpull.org",
          "mozilla.org", "facebook.com", "firebaseio.com", "firebase.com", "crashlytics.com", "googleusercontent.com",
          "googlesyndication.com", "doubleclick.net", "unity3d.com", "adjust.com", "appsflyer.com", "microsoft.com",
          "sentry.io", "openssl.org", "oracle.com", "jetbrains.com", "kotlinlang.org", "example.com", "slf4j.org",
          "ietf.org", "github.com", "whatsapp.com", "amazon.com", "amazonaws.com", "play.google.com"}


async def analyze_apk(a: dict):
    sha = str(a.get("sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise HTTPException(400, "APK ka hash galat hai.")
    pkg = str(a.get("package") or "unknown")[:120]
    perms = [p for p in (a.get("permissions") or []) if isinstance(p, str) and re.fullmatch(r"android\.permission\.[A-Z_]+", p)][:100]
    urls = [u for u in (a.get("urls") or []) if isinstance(u, str)][:80]
    names = {p.split(".")[-1] for p in perms}
    findings: list = []
    for n, (pts, msg) in APK_PERMS.items():
        if n in names:
            add(findings, "danger" if pts >= 20 else "warn", msg, pts)
    if names & {"READ_SMS", "RECEIVE_SMS"} and names & {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "BIND_NOTIFICATION_LISTENER_SERVICE"}:
        add(findings, "danger", "SMS access ke saath screen ya notification control. Banking trojan jaisa pattern.", 20)
    add(findings, "info", f"Package: {pkg}. Permissions: {len(perms)}. SHA-256: {sha[:16]}...", 0)
    if VT_KEY:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": VT_KEY})
            if r.status_code == 200:
                s = r.json()["data"]["attributes"]["last_analysis_stats"]
                bad = s.get("malicious", 0) + s.get("suspicious", 0)
                if bad:
                    add(findings, "danger", f"VirusTotal pe {bad} security engines ne is APK ko flag kiya.", min(40 + 5 * bad, 70))
                else:
                    add(findings, "ok", "VirusTotal pe is file ko kisi engine ne flag nahi kiya.")
            elif r.status_code == 404:
                add(findings, "info", "VirusTotal pe ye file pehle kabhi scan nahi hui (nayi ya rare file).", 0)
        except Exception:
            pass
    hosts = {}
    for u in urls:
        h = (urlparse(u).hostname or "").lower().rstrip(".")
        if h and "." in h and registered_domain(h) not in BENIGN:
            hosts.setdefault(h, u)
    bad_hosts = []
    for h, u in list(hosts.items())[:15]:
        tmp: list = []
        url_checks(u, h, registered_domain(h), tmp)
        if sum(f["points"] for f in tmp) >= 30:
            bad_hosts.append(h)
    for h in bad_hosts[:2]:
        add(findings, "danger", f"APK ke andar suspicious link mila: {h}", 20)
    if hosts:
        add(findings, "info", "APK ke andar mile domains: " + ", ".join(list(hosts)[:8]), 0)
    if not any(f["points"] for f in findings):
        add(findings, "ok", "Koi khaas khatarnak permission ya link nahi mila.")
    return finish(pkg, findings)



@app.post("/api/index")
@app.post("/api/scan/url")
async def scan(body: Req):
    if body.kind == "text":
        return await analyze_text(body.text)
    if body.kind == "apk":
        return await analyze_apk(body.apk or {})
    return await analyze_url(body.url)


PAGE = r'''<!DOCTYPE html>
<html lang="hi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowX - Scam aur fraud scanner</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🕶️</text></svg>">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600;800&family=Hind:wght@400;500&display=swap">
<script src="https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script>
<style>
:root{--bg:#14131f;--panel:#1e1c2e;--line:#322f4a;--text:#ebe8f7;--muted:#9c98b8;--accent:#aa9dff;
--safe:#5bd1a5;--warn:#f2b14c;--danger:#f0645e;--c:var(--accent)}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 Hind,system-ui,sans-serif}
main{max-width:720px;margin:0 auto;padding:48px 20px 80px}
.brand{font:800 22px Sora,sans-serif;letter-spacing:-.5px}.brand b{color:var(--accent)}
h1{font:800 clamp(30px,6vw,46px)/1.12 Sora,sans-serif;letter-spacing:-1px;margin:40px 0 12px;max-width:16ch}
.sub{color:var(--muted);margin:0 0 28px;max-width:50ch}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.tab{background:none;border:1px solid var(--line);color:var(--muted);padding:8px 14px;border-radius:999px;font:inherit;cursor:pointer}
.tab.on{background:var(--accent);border-color:var(--accent);color:#14131f;font-weight:500}
form{display:flex;gap:8px;flex-wrap:wrap}
input[type=text]{flex:1 1 280px;background:var(--panel);border:1px solid var(--line);color:var(--text);padding:14px 16px;border-radius:12px;font:inherit}
input:focus,button:focus-visible,.drop:focus-within{outline:2px solid var(--accent);outline-offset:2px}
button.go{background:var(--accent);color:#14131f;border:0;padding:14px 22px;border-radius:12px;font:600 16px Sora,sans-serif;cursor:pointer}
button.go:disabled{opacity:.6;cursor:wait}
.drop{display:block;border:2px dashed var(--line);border-radius:14px;padding:30px 18px;text-align:center;cursor:pointer;background:var(--panel)}
.drop:hover{border-color:var(--accent)}
.drop input{position:absolute;opacity:0;width:1px;height:1px}
.hint{color:var(--muted);font-size:14px;margin:10px 0 0}
.status{color:var(--accent);min-height:24px;margin:14px 0 0}
#out{margin-top:24px}
.res{display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.ring{--c:var(--accent);width:132px;height:132px;border-radius:50%;flex:none;display:grid;place-items:center;
background:conic-gradient(var(--c) calc(var(--p)*1%),var(--line) 0);box-shadow:14px 14px 0 -2px color-mix(in srgb,var(--c) 22%,transparent)}
.ring span{width:104px;height:104px;border-radius:50%;background:var(--bg);display:grid;place-items:center;font:800 34px Sora,sans-serif}
.verdict{font:800 28px Sora,sans-serif;color:var(--c)}
.host{color:var(--muted);word-break:break-all}
ul{list-style:none;padding:0;margin:28px 0 0;display:grid;gap:8px}
li{background:var(--panel);border-left:4px solid var(--line);padding:12px 14px;border-radius:8px;word-break:break-word}
li.danger{border-color:var(--danger)}li.warn{border-color:var(--warn)}li.ok{border-color:var(--safe)}li.info{border-color:var(--accent)}
.note{color:var(--muted);font-size:14px;margin-top:24px}.note a{color:var(--accent)}
.err{color:var(--danger)}
</style>
</head>
<body>
<main>
  <div class="brand">Shadow<b>X</b></div>
  <h1>Bharosa karne se pehle scan karo.</h1>
  <p class="sub">Link, screenshot ya APK file daalo. ShadowX bataega ki wo safe hai, suspicious hai ya scam, aur kyun.</p>

  <div class="tabs">
    <button class="tab on" type="button" data-t="url">Website / Link</button>
    <button class="tab" type="button" data-t="shot">Screenshot</button>
    <button class="tab" type="button" data-t="apk">APK file</button>
  </div>

  <div id="p-url">
    <form id="f">
      <input id="u" type="text" placeholder="Link paste karo, jaise sbi-login-secure.xyz" autocomplete="off" required>
      <button class="go" id="b">Scan karo</button>
    </form>
  </div>

  <div id="p-shot" hidden>
    <label class="drop">
      <input type="file" id="fs" accept="image/*">
      Screenshot chuno, ya Ctrl + V se paste karo
    </label>
    <p class="hint">Screenshot tere browser mein hi padha jaata hai. Image server pe upload nahi hoti, sirf nikla hua text check hota hai.</p>
  </div>

  <div id="p-apk" hidden>
    <label class="drop">
      <input type="file" id="fa" accept=".apk,application/vnd.android.package-archive">
      APK file chuno
    </label>
    <p class="hint">APK kabhi chalayi nahi jaati. File tere browser mein hi khulti hai, server ko sirf permissions, links aur hash jaate hain.</p>
  </div>

  <p class="status" id="st" aria-live="polite"></p>
  <section id="out" aria-live="polite"></section>
</main>

<script>
const $ = id => document.getElementById(id), out = $('out'), st = $('st');
const LABEL = {safe:'Safe lag raha hai', suspicious:'Suspicious hai', dangerous:'Khatarnak hai'};
const COLOR = {safe:'var(--safe)', suspicious:'var(--warn)', dangerous:'var(--danger)'};
function el(tag, cls, text){ const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }

function setTab(t){
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('on', b.dataset.t === t));
  ['url','shot','apk'].forEach(k => $('p-' + k).hidden = (k !== t));
  out.textContent = ''; st.textContent = '';
}
document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => setTab(b.dataset.t)));

async function call(payload){
  const r = await fetch('/api/index', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  let d = {}; try { d = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error(d.detail || 'Scan fail ho gaya.');
  return d;
}
function fail(e){ out.textContent = ''; out.append(el('p', 'err', e.message)); }

// ---- link scan
$('f').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('b'); btn.disabled = true; btn.textContent = 'Scan ho raha hai...'; out.textContent = '';
  try { render(await call({kind:'url', url:$('u').value})); } catch (err) { fail(err); }
  btn.disabled = false; btn.textContent = 'Scan karo';
});

// ---- screenshot scan (OCR runs in the browser)
async function doShot(file){
  if (!file || !file.type.startsWith('image/')) return;
  out.textContent = ''; st.textContent = 'Screenshot padh raha hai... 0%';
  try {
    if (!window.Tesseract) throw new Error('OCR library load nahi hui. Internet check karo aur page refresh karo.');
    const res = await Tesseract.recognize(file, 'eng', {logger: m => {
      if (m.status === 'recognizing text') st.textContent = 'Screenshot padh raha hai... ' + Math.round(m.progress * 100) + '%';
    }});
    st.textContent = 'Text mil gaya, check ho raha hai...';
    render(await call({kind:'text', text: res.data.text}));
  } catch (err) { fail(err); }
  st.textContent = '';
}
$('fs').addEventListener('change', e => { doShot(e.target.files[0]); e.target.value = ''; });
document.addEventListener('paste', e => {
  const f = e.clipboardData && e.clipboardData.files && e.clipboardData.files[0];
  if (f && !$('p-shot').hidden) doShot(f);
});

// ---- APK scan (parsed in the browser)
// <<AXML
function parseManifest(buf){
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const strings = [], perms = new Set(); let pkg = '', off = 8;
  while (off + 8 <= buf.length){
    const type = v.getUint16(off, true), size = v.getUint32(off + 4, true);
    if (size < 8) break;
    if (type === 0x0001){
      const n = v.getUint32(off + 8, true), flags = v.getUint32(off + 16, true), sStart = v.getUint32(off + 20, true);
      for (let i = 0; i < n; i++){
        let p = off + sStart + v.getUint32(off + 28 + i * 4, true);
        if (flags & 0x100){
          if (buf[p] & 0x80) p += 2; else p += 1;
          let bl = buf[p];
          if (bl & 0x80){ bl = ((bl & 0x7f) << 8) | buf[p + 1]; p += 2; } else p += 1;
          strings.push(new TextDecoder().decode(buf.subarray(p, p + bl)));
        } else {
          let l = v.getUint16(p, true); p += 2;
          if (l & 0x8000){ l = ((l & 0x7fff) << 16) | v.getUint16(p, true); p += 2; }
          let s = ''; for (let k = 0; k < l; k++) s += String.fromCharCode(v.getUint16(p + k * 2, true));
          strings.push(s);
        }
      }
    } else if (type === 0x0102){
      const aStart = v.getUint16(off + 24, true), aSize = v.getUint16(off + 26, true) || 20, aCount = v.getUint16(off + 28, true);
      for (let i = 0; i < aCount; i++){
        const a = off + 16 + aStart + i * aSize;
        const name = strings[v.getUint32(a + 4, true)], raw = v.getUint32(a + 8, true), dt = v.getUint8(a + 15);
        const val = raw !== 0xFFFFFFFF ? strings[raw] : (dt === 3 ? strings[v.getUint32(a + 16, true)] : null);
        if (name === 'package' && val) pkg = val;
        if (val && /^android\.permission\.[A-Z_]+$/.test(val)) perms.add(val);
      }
    }
    off += size;
  }
  return {pkg, perms: [...perms]};
}
// AXML>>

async function doApk(file){
  if (!file) return;
  out.textContent = '';
  try {
    if (!window.JSZip) throw new Error('JSZip load nahi hua. Internet check karo aur page refresh karo.');
    st.textContent = 'APK khol raha hai...';
    const buf = await file.arrayBuffer();
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', buf))].map(b => b.toString(16).padStart(2, '0')).join('');
    const zip = await JSZip.loadAsync(buf);
    const mf = zip.file('AndroidManifest.xml');
    if (!mf) throw new Error('Ye valid APK nahi lag rahi (AndroidManifest nahi mila).');
    const m = parseManifest(await mf.async('uint8array'));
    st.textContent = 'Andar ke links dhoondh raha hai...';
    const urls = new Set();
    for (const f of zip.file(/^classes\d*\.dex$/).slice(0, 3)){
      const txt = new TextDecoder('latin1').decode(await f.async('uint8array'));
      for (const u of (txt.match(/https?:\/\/[\w.~:\/?#@!$&*+,;=%-]{4,120}/g) || [])) urls.add(u);
    }
    st.textContent = 'Report ban raha hai...';
    render(await call({kind:'apk', apk:{name:file.name, size:file.size, sha256:hash, package:m.pkg, permissions:m.perms, urls:[...urls].slice(0, 80)}}));
  } catch (err) { fail(err); }
  st.textContent = '';
}
$('fa').addEventListener('change', e => { doApk(e.target.files[0]); e.target.value = ''; });

// ---- result
function render(d){
  out.textContent = '';
  const res = el('div', 'res'), ring = el('div', 'ring');
  ring.style.setProperty('--p', d.score); ring.style.setProperty('--c', COLOR[d.verdict]);
  ring.append(el('span', null, d.score));
  const info = el('div'); info.style.setProperty('--c', COLOR[d.verdict]);
  info.append(el('div', 'verdict', LABEL[d.verdict]), el('div', 'host', d.host), el('div', 'host', 'Risk score: ' + d.score + '/100'));
  res.append(ring, info);
  const ul = el('ul');
  d.findings.forEach(f => ul.append(el('li', f.level, f.text)));
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
