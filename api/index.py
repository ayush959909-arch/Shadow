"""ShadowX - URL / screenshot / SMS / email / APK scanner (FastAPI) for Vercel.
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
from email import message_from_string, policy
from email.utils import parseaddr
import html as html_lib

app = FastAPI(title="ShadowX")
VT_KEY = os.getenv("VT_API_KEY")
GSB_KEY = os.getenv("GSB_API_KEY")

BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google", "amazon",
          "flipkart", "paypal", "microsoft", "apple", "netflix", "instagram", "facebook",
          "whatsapp", "irctc", "uidai", "incometax"]
RISKY_TLDS = {"xyz", "top", "click", "icu", "buzz", "tk", "ml", "ga", "cf", "gq", "work",
              "loan", "rest", "cyou", "sbs", "lol", "zip", "mov"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "goo.gl"}
TWO_PART = {"co.in", "org.in", "gov.in", "net.in", "ac.in", "co.uk", "com.au", "com.br"}
UA = {"User-Agent": "Mozilla/5.0 (ShadowX scanner)"}


class Req(BaseModel):
    kind: str = "url"
    url: str = ""
    text: str = ""
    sender: str = ""
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
    except (socket.gaierror, UnicodeError):
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


async def public_host(host: str) -> bool:
    # getaddrinfo is blocking, so run it in a thread
    return await asyncio.to_thread(is_public_host, host)


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


# Context-based page signals (instead of a plain scam-word list)
PAGE_SIGNALS = [
    (r"<input[^>]+(?:name|id|placeholder)=[\"'][^\"']*(?:otp|cvv|card ?number|upi ?pin|atm ?pin|aadhaar)",
     "danger", "Page ke form mein OTP / CVV / card / Aadhaar jaisi sensitive detail maangi ja rahi hai. Asli bank ya company ye details link wale page pe nahi leti.", 25),
    (r"\b(?:account|card|sim|connection)\b[^.<]{0,40}\b(?:blocked|suspended|deactivated|disconnected)\b|\bkyc\b[^.<]{0,40}\b(?:expired|pending|update)",
     "warn", "Page account band hone ya KYC expire hone ka darr dikha raha hai, taaki aap bina soche details daal do.", 20),
    (r"you have won|you won|claim your (?:prize|reward)|lucky draw|lottery",
     "warn", "Page inaam ya lottery ka laalach de raha hai. Jis contest mein aapne hissa nahi liya, wahan jeetna scam ka pattern hai.", 20),
    (r"(?:within|in) \d+ ?(?:hours|hrs|minutes|mins)|last chance|act now",
     "warn", "Page jaldi karne ka dabav daal raha hai. Scammers sochne ka time nahi dete.", 8),
]


async def page_check(url, findings):
    html, cur = "", url
    async with httpx.AsyncClient(timeout=8, headers=UA, follow_redirects=False) as c:
        for _ in range(4):
            if not await public_host(urlparse(cur).hostname or ""):
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
    hit = 0
    for pat, lvl, msg, pts in PAGE_SIGNALS:
        if re.search(pat, low):
            add(findings, lvl, msg, pts)
            hit += 1
    if hit >= 2:
        add(findings, "danger", "Ek hi page par darr, laalach aur details ki maang ek saath hain. Ye phishing pages ka classic combination hai.", 15)
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
    # Score uses ALL findings; display shows only the top 3 risk reasons + info/ok lines
    score = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    risky = [f for f in findings if f["points"] > 0][:3]
    rest = [f for f in findings if f["points"] == 0]
    verdict = "safe" if score < 25 else "suspicious" if score < 55 else "dangerous"
    return {"host": host, "score": score, "verdict": verdict, "findings": risky + rest,
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
    if await public_host(host):
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
    (r"lottery|you have won|you won|lucky draw|claim (?:your )?prize|prize money|\bkbc\b|congratulations[^.]{0,40}(?:won|prize|selected)",
     "danger", "Lottery ya inaam ka laalach. Ye sabse common scam hai.", 30),
    (r"digital arrest|\bcbi\b|narcotics|enforcement directorate|cyber ?crime branch|arrest warrant|parcel[^.]{0,60}(?:seized|arrest|customs|illegal|drugs)|customs[^.]{0,40}(?:seized|duty|parcel)",
     "danger", "Police, CBI ya courier ke naam pe dhamki. Digital arrest scam jaisa lagta hai. Asli police video call pe arrest nahi karti.", 35),
    (r"work from home|part[- ]time job|earn[^.]{0,20}(?:rs\.?|inr|₹)?\s?\d|daily income|(?:complete|finish) (?:\d+ )?tasks?|task (?:reward|commission)|like (?:and|&) subscribe",
     "warn", "Ghar baithe kamai ya job ka offer. Fake job scam ka pattern.", 25),
    (r"\botp\b|\bcvv\b|(?:upi|atm|card) pin|card number|share[^.]{0,20}password",
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


async def text_findings(text: str, extra_links=None):
    """Shared scam-pattern + link scan used by screenshot, SMS and email."""
    low = text.lower()
    findings: list = []
    for pat, lvl, msg, pts in TEXT_RULES:
        if re.search(pat, low):
            add(findings, lvl, msg, pts)
    links = list(extra_links or [])
    for m in LINK_RE.findall(text):
        m = m.strip(".,;:)]}>\"'")
        if "@" not in m and m.lower() not in [x.lower() for x in links]:
            links.append(m)
    upi = list(dict.fromkeys(UPI_RE.findall(text)))[:5]
    phones = list(dict.fromkeys(re.sub(r"\D", "", p)[-10:] for p in PHONE_RE.findall(text)))[:5]
    results = await asyncio.gather(*[analyze_url(l) for l in links[:3]], return_exceptions=True)
    for l, r in zip(links[:3], results):
        if isinstance(r, dict) and r["verdict"] != "safe":
            lab = "Khatarnak" if r["verdict"] == "dangerous" else "Suspicious"
            add(findings, "danger" if r["verdict"] == "dangerous" else "warn",
                f"Link {r['host']} scan kiya: {lab} (risk {r['score']}/100).", 40 if r["verdict"] == "dangerous" else 20)
        elif isinstance(r, dict):
            add(findings, "ok", f"Link {r['host']} safe lag raha hai.")
    if links:
        add(findings, "info", "Mile hue links: " + ", ".join(links[:5]), 0)
    if upi:
        add(findings, "info", "UPI ID mili: " + ", ".join(upi) + ". Unknown UPI ID pe paisa mat bhejo.", 0)
    if phones:
        add(findings, "info", "Phone number mile: " + ", ".join(phones) + ". Unknown number pe bharosa mat karo.", 0)
    return findings


async def analyze_text(text: str):
    if len(text.strip()) < 10:
        raise HTTPException(400, "Screenshot se text nahi nikla. Saaf aur bada screenshot try karo.")
    findings = await text_findings(text[:5000])
    if not findings:
        add(findings, "ok", "Koi scam pattern nahi mila. Phir bhi paisa ya OTP dene se pehle sochna.")
    return finish("Screenshot scan", findings)


# ---------- SMS ----------
SENDER_RE = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{3,8}(?:-[A-Za-z])?$")


async def analyze_sms(text: str, sender: str):
    if len(text.strip()) < 5:
        raise HTTPException(400, "SMS ka text paste karo.")
    text, sender = text[:2000], sender.strip()[:40]
    findings = await text_findings(text)
    low = text.lower()
    claims = any(b in low for b in BRANDS) or any(f["level"] == "danger" for f in findings)
    if sender:
        digits = re.sub(r"[\s-]", "", sender)
        if SENDER_RE.match(sender):
            add(findings, "info", f"Sender ID {sender} company wale format jaisa hai. Format asli ho sakta hai, par spoof bhi hota hai.", 0)
        elif re.fullmatch(r"\+?(?:91)?0?[6-9]\d{9}", digits):
            add(findings, "warn", "SMS normal mobile number se aaya hai. Banks aur companies apne official sender ID (jaise VM-HDFCBK) se SMS bhejti hain.", 20 if claims else 8)
        elif digits.startswith("+") and not digits.startswith("+91"):
            add(findings, "warn", "SMS international number se aaya hai.", 12)
    if re.search(r"dear (?:customer|user|sir|madam|account holder|valued)", low):
        add(findings, "warn", "Generic greeting (Dear customer). Asli bank aapka naam use karta hai.", 8)
    if not findings:
        add(findings, "ok", "Koi scam pattern nahi mila. Phir bhi link ya OTP ke liye sochna.")
    return finish("SMS scan", findings)


# ---------- Email ----------
FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "rediffmail.com",
            "proton.me", "protonmail.com", "icloud.com"}
BAD_EXT = {"exe", "scr", "bat", "cmd", "apk", "js", "vbs", "jar", "iso", "img", "lnk", "msi", "ps1"}
RISKY_EXT = {"html", "htm", "zip", "rar", "7z", "docm", "xlsm", "pptm"}


def parse_email(raw: str):
    info = {"name": "", "addr": "", "reply": "", "auth": "", "subject": "", "text": "", "anchors": [], "files": [], "headers": False}
    if not re.search(r"^(?:from|subject|received|return-path|message-id|authentication-results):", raw, re.I | re.M):
        info["text"] = raw
        return info
    info["headers"] = True
    msg = message_from_string(raw, policy=policy.default)
    info["name"], info["addr"] = parseaddr(str(msg.get("From", "")))
    info["reply"] = parseaddr(str(msg.get("Reply-To", "")))[1]
    info["subject"] = str(msg.get("Subject", ""))
    info["auth"] = " ".join(str(x) for x in (msg.get_all("Authentication-Results") or [])) + " " + str(msg.get("Received-SPF", ""))
    texts = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            info["files"].append(str(fn))
            continue
        ct = part.get_content_type()
        if ct in ("text/plain", "text/html"):
            try:
                s = part.get_content()
            except Exception:
                continue
            if ct == "text/html":
                for href, inner in re.findall(r"<a\s[^>]*?href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", s, re.I | re.S):
                    info["anchors"].append((html_lib.unescape(re.sub(r"<[^>]+>", "", inner)).strip(), html_lib.unescape(href)))
                s = re.sub(r"<(?:script|style).*?</(?:script|style)>", " ", s, flags=re.I | re.S)
                s = html_lib.unescape(re.sub(r"<[^>]+>", " ", s))
            texts.append(s)
    info["text"] = "\n".join(texts)
    return info


async def analyze_email(raw: str):
    if len(raw.strip()) < 20:
        raise HTTPException(400, "Email paste karo (poora ya sirf body).")
    try:
        e = parse_email(raw[:200000])
    except Exception:
        e = {"name": "", "addr": "", "reply": "", "auth": "", "subject": "", "text": raw[:20000], "anchors": [], "files": [], "headers": False}
    findings: list = []
    dom = e["addr"].split("@")[-1].lower() if "@" in e["addr"] else ""
    if not e["headers"]:
        add(findings, "info", "Sirf email ki body paste hui hai, isliye sender aur headers check nahi hue. Poora email (Show original) paste karoge to zyada accurate hoga.", 0)
    if dom:
        reg = registered_domain(dom)
        tmp: list = []
        url_checks("https://" + dom, dom, reg, tmp)
        for f in tmp:
            if f["points"]:
                add(findings, f["level"], "Sender domain: " + f["text"], f["points"])
        try:
            age: list = []
            await domain_age(reg, age)
            for f in age:
                add(findings, f["level"], "Sender " + f["text"][0].lower() + f["text"][1:], f["points"])
        except Exception:
            pass
        nm = e["name"].lower()
        for b in BRANDS:
            if b in nm and b not in dom:
                add(findings, "danger", f"Sender ka naam '{e['name']}' hai par email {dom} se aaya hai.", 30)
                break
        else:
            if dom in FREEMAIL and any(b in (nm + " " + e["subject"].lower()) for b in BRANDS):
                add(findings, "warn", "Bank ya company ke naam ka email free email service se aaya hai. Asli companies apne domain se bhejti hain.", 20)
        if e["reply"] and "@" in e["reply"] and registered_domain(e["reply"].split("@")[-1].lower()) != reg:
            add(findings, "warn", f"Reply-To address ({e['reply']}) sender se alag domain ka hai. Jawab scammer ke paas jaayega.", 20)
    auth = e["auth"].lower()
    if re.search(r"\b(?:spf|dkim|dmarc)=(?:fail|softfail|none|permerror|temperror)", auth):
        add(findings, "danger", "Email authentication fail hua (SPF/DKIM/DMARC). Ye email us domain se nahi aaya ho sakta jo dikh raha hai.", 25)
    elif re.search(r"\b(?:spf|dkim|dmarc)=pass", auth):
        add(findings, "ok", "SPF/DKIM/DMARC pass hua. Matlab email us domain se aaya, par domain asli hai ya nahi, ye alag dekhna padta hai.")
    for fn in e["files"][:10]:
        ext = fn.lower().rsplit(".", 1)[-1] if "." in fn else ""
        if ext in BAD_EXT:
            add(findings, "danger", f"Khatarnak attachment: {fn}. Ise kabhi open mat karo.", 30)
        elif ext in RISKY_EXT:
            add(findings, "warn", f"Risky attachment type: {fn}. Unknown sender ki aisi file mat kholo.", 20)

    # Links: check that the visible text matches where the link really goes
    hrefs, mismatch = [], False
    for shown, href in e["anchors"]:
        hh = (urlparse(href).hostname or "").lower()
        if not hh:
            continue
        sm = LINK_RE.search(shown)
        if sm and not mismatch:
            s = sm.group(0)
            sh = (urlparse(s if s.lower().startswith("http") else "https://" + s).hostname or "").lower()
            if sh and registered_domain(sh) != registered_domain(hh):
                add(findings, "danger", f"Link par '{sh}' likha hai par asal mein {hh} pe le jaata hai. Ye phishing ki classic trick hai.", 30)
                mismatch = True
        if href not in hrefs:
            hrefs.append(href)

    body = (e["subject"] + "\n" + e["text"])[:5000]
    findings += await text_findings(body, extra_links=hrefs[:3])
    if not any(f["points"] for f in findings):
        add(findings, "ok", "Koi bada scam sign nahi mila. Phir bhi link ya attachment kholne se pehle sender confirm kar lo.")
    return finish(dom or "Email scan", findings)


# ---------- APK ----------
DANGEROUS_PERMS = {
    "READ_SMS": ("danger", "App aapke SMS padh sakti hai (OTP chori ho sakte hain).", 25),
    "RECEIVE_SMS": ("warn", "App incoming SMS dekh sakti hai (OTP chori ho sakte hain).", 15),
    "SEND_SMS": ("warn", "App aapke naam se SMS bhej sakti hai (premium SMS fraud).", 15),
    "BIND_ACCESSIBILITY_SERVICE": ("danger", "App Accessibility access maangti hai. Isse screen padhi aur control ki ja sakti hai, banking trojans yahi use karte hain.", 30),
    "SYSTEM_ALERT_WINDOW": ("warn", "App doosri apps ke upar fake screen dikha sakti hai (overlay attack).", 15),
    "REQUEST_INSTALL_PACKAGES": ("warn", "App chupke se aur apps install kar sakti hai.", 15),
    "BIND_DEVICE_ADMIN": ("danger", "App Device Admin access maangti hai, uninstall karna mushkil ho sakta hai.", 25),
    "READ_CALL_LOG": ("warn", "App aapka call history padh sakti hai.", 10),
    "READ_CONTACTS": ("warn", "App aapke saare contacts padh sakti hai.", 8),
    "RECORD_AUDIO": ("warn", "App mic se recording kar sakti hai.", 8),
}


async def analyze_apk(apk: Optional[dict]):
    if not apk:
        raise HTTPException(400, "APK ki details nahi mili.")
    findings: list = []
    name = str(apk.get("name") or apk.get("label") or "")[:80]
    pkg = str(apk.get("package") or apk.get("pkg") or "")[:120].lower()
    perms = [str(p).split(".")[-1].upper() for p in (apk.get("permissions") or [])][:200]
    for p, (lvl, msg, pts) in DANGEROUS_PERMS.items():
        if p in perms:
            add(findings, lvl, msg, pts)
    for b in BRANDS:
        if (b in name.lower() or b in pkg) and not pkg.startswith(("com." + b, "in." + b, "net." + b, "org." + b)) and "." in pkg:
            add(findings, "danger", f"App ka naam/package '{b}' jaisa hai par package {pkg} hai. Asli app ka package alag hota hai.", 30)
            break
    sensitive = {"READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE"} & set(perms)
    if len(sensitive) >= 2:
        add(findings, "danger", "SMS aur Accessibility jaisi permissions ek saath hain. Ye banking malware ka common combination hai.", 15)
    if not findings:
        add(findings, "ok", "Koi risky permission nahi mili. Phir bhi app sirf Play Store se hi install karo.")
    return finish(name or pkg or "APK scan", findings)


# ---------- Routes ----------
INDEX_HTML = """<!doctype html><html lang="hi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ShadowX</title>
<style>body{font-family:system-ui;max-width:640px;margin:2rem auto;padding:0 1rem}
textarea,input,select,button{width:100%;margin:.4rem 0;padding:.6rem;font-size:1rem;box-sizing:border-box}
.f{padding:.5rem;margin:.3rem 0;border-radius:6px;background:#eee}.danger{background:#fdd}.warn{background:#ffe9b8}.ok{background:#d9f5dd}</style></head>
<body><h2>ShadowX</h2>
<select id="k"><option value="url">Link</option><option value="sms">SMS</option><option value="email">Email</option><option value="text">Screenshot text</option></select>
<input id="s" placeholder="Sender (sirf SMS ke liye)"><textarea id="t" rows="6" placeholder="Link ya text yahan paste karo"></textarea>
<button onclick="go()">Scan</button><div id="o"></div>
<script>
async function go(){const k=document.getElementById('k').value,v=document.getElementById('t').value;
const b={kind:k,url:k==='url'?v:'',text:k!=='url'?v:'',sender:document.getElementById('s').value};
const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
const d=await r.json(),o=document.getElementById('o');
if(!r.ok){o.textContent=d.detail||'Error';return}
o.innerHTML='<h3>'+d.verdict.toUpperCase()+' ('+d.score+'/100)</h3>'+d.findings.map(f=>'<div class="f '+f.level+'">'+f.text.replace(/</g,'&lt;')+'</div>').join('')}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


@app.post("/api/scan")
@app.post("/scan")
async def scan(req: Req):
    k = req.kind.lower()
    if k == "url":
        return await analyze_url(req.url)
    if k in ("text", "image", "screenshot"):
        return await analyze_text(req.text)
    if k == "sms":
        return await analyze_sms(req.text, req.sender)
    if k == "email":
        return await analyze_email(req.text)
    if k == "apk":
        return await analyze_apk(req.apk)
    raise HTTPException(400, "Unknown scan type.")
