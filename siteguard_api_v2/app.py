from flask import Flask, request, jsonify, Response
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import requests, re
from flask_cors import CORS

app = Flask(__name__)

# Allow cross-origin requests from the extension and anywhere else
CORS(app)

# Force headers so the app can be embedded in an iframe (your extension's sandbox page)
@app.after_request
def allow_iframe(resp):
    # Allow this API to be framed by any origin (needed for the extension sandbox iframe)
    resp.headers["X-Frame-Options"] = "ALLOWALL"
    # Allow any site to embed this API in an iframe (extension -> API -> target site)
    resp.headers["Content-Security-Policy"] = "frame-ancestors *"
    # Reasonable caching
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ----------------- Heuristic Scanner -----------------

WEIGHTS = {
    "mixedContent": 25, "metaRefresh": 10, "manyInlineHandlers": 10,
    "suspiciousInlineJS": 20, "dataURIScripts": 10, "shortenerLinks": 15,
    "ipLinks": 10, "suspiciousTLDs": 10, "execDownloads": 20,
    "formsToHTTP": 20, "hiddenIframes": 10, "thirdPartyScripts": 10,
    "onBeforeUnload": 10, "fingerprintingAPIs": 10, "base64InLinks": 10
}

SHORTENERS = {"bit.ly","t.co","goo.gl","tinyurl.com","ow.ly","buff.ly","cutt.ly","is.gd","adf.ly"}
DL_EXTS = (".exe",".apk",".msi",".bat",".cmd",".scr",".zip",".rar",".js",".jar",".7z")
INLINE_EVENTS = {"onclick","onload","onerror","onmouseover","onfocus","onmouseleave",
                 "onmouseenter","onkeydown","onkeyup","onbeforeunload"}
SUSP_TLDS = {".zip",".click",".country",".gq",".tk",".ml",".ga",".cf",".top",".work",".xyz"}

UA = {"User-Agent": "SiteGuard/1.1 (+sandbox proxy)"}

def normalize_url(base, value):
    try:
        return urljoin(base, value)
    except Exception:
        return None

def collect_features(page_url, html):
    soup = BeautifulSoup(html or "", "html.parser")
    origin = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"
    https = page_url.lower().startswith("https:")
    f = {
        "mixedContent": False, "metaRefresh": False, "inlineHandlers": 0,
        "suspiciousInlineJS": 0, "dataURIScripts": 0, "shortenerLinks": 0,
        "ipLinks": 0, "suspiciousTLDs": 0, "execDownloads": [],
        "formsToHTTP": 0, "hiddenIframes": 0, "thirdPartyScripts": 0,
        "onBeforeUnload": False, "fingerprintingAPIs": 0, "base64InLinks": 0
    }

    if https:
        for el in soup.select("[src],[href]"):
            v = el.get("src") or el.get("href")
            if v and v.strip().lower().startswith("http://"):
                f["mixedContent"] = True
                break

    if soup.select_one('meta[http-equiv="refresh"], meta[http-equiv="Refresh"]'):
        f["metaRefresh"] = True

    for el in soup.find_all(True):
        for a in INLINE_EVENTS:
            if el.has_attr(a):
                f["inlineHandlers"] += 1

    susp_re = re.compile(r"(eval\(|new Function\(|document\.write\(|atob\()", re.I)
    for s in soup.find_all("script"):
        if not s.get("src"):
            txt = s.get_text() or ""
            if susp_re.search(txt): f["suspiciousInlineJS"] += 1
            if re.search(r"data:\s*text/javascript", txt, re.I): f["dataURIScripts"] += 1

    for a in soup.select("a[href]"):
        href = normalize_url(page_url, a.get("href",""))
        if not href: continue
        p = urlparse(href)
        host = p.hostname or ""
        if host in SHORTENERS: f["shortenerLinks"] += 1
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host): f["ipLinks"] += 1
        if any(host.endswith(t) for t in SUSP_TLDS): f["suspiciousTLDs"] += 1
        if "base64," in href.lower(): f["base64InLinks"] += 1
        if a.has_attr("download") or any(href.lower().endswith(x) for x in DL_EXTS):
            f["execDownloads"].append(href)

    for fm in soup.select("form[action]"):
        act = normalize_url(page_url, fm.get("action",""))
        if act and act.lower().startswith("http://"):
            f["formsToHTTP"] += 1

    for i in soup.find_all("iframe"):
        style = (i.get("style") or "").lower()
        if "display:none" in style or "visibility:hidden" in style or i.get("width")=="0" or i.get("height")=="0":
            f["hiddenIframes"] += 1

    for s in soup.find_all("script", src=True):
        try:
            u = urlparse(normalize_url(page_url, s["src"]))
            if f"{u.scheme}://{u.netloc}" != origin:
                f["thirdPartyScripts"] += 1
        except Exception:
            pass

    if "onbeforeunload" in (html or "").lower():
        f["onBeforeUnload"] = True
    if re.search(r"CanvasRenderingContext2D|WebGLRenderingContext|RTCPeerConnection|deviceMemory|hardwareConcurrency", html or ""):
        f["fingerprintingAPIs"] = 1

    return f

def score_features(f):
    s = 0
    issues = []
    def add(msg, w):
        nonlocal s
        s += w
        issues.append(f"{msg} (+{w})")
    if f["mixedContent"]: add("Mixed content on HTTPS", WEIGHTS["mixedContent"])
    if f["metaRefresh"]: add("Meta refresh redirect", WEIGHTS["metaRefresh"])
    if f["inlineHandlers"] > 20: add("Many inline event handlers", WEIGHTS["manyInlineHandlers"])
    if f["suspiciousInlineJS"] > 0: add("Suspicious inline JS (eval/new Function/atob)", WEIGHTS["suspiciousInlineJS"])
    if f["dataURIScripts"] > 0: add("Data-URI scripts", WEIGHTS["dataURIScripts"])
    if f["shortenerLinks"] > 3: add("Multiple shortener links", WEIGHTS["shortenerLinks"])
    if f["ipLinks"] > 0: add("Links to raw IPs", WEIGHTS["ipLinks"])
    if f["suspiciousTLDs"] > 0: add("Suspicious TLDs used", WEIGHTS["suspiciousTLDs"])
    if len(f["execDownloads"]) > 0: add("Executable/archived downloads present", WEIGHTS["execDownloads"])
    if f["formsToHTTP"] > 0: add("Forms submit to HTTP", WEIGHTS["formsToHTTP"])
    if f["hiddenIframes"] > 0: add("Hidden/zero-size iframes", WEIGHTS["hiddenIframes"])
    if f["thirdPartyScripts"] > 10: add("High number of third-party scripts", WEIGHTS["thirdPartyScripts"])
    if f["onBeforeUnload"]: add("onbeforeunload trap", WEIGHTS["onBeforeUnload"])
    if f["fingerprintingAPIs"] > 0: add("Fingerprinting APIs present", WEIGHTS["fingerprintingAPIs"])
    if f["base64InLinks"] > 0: add("Base64 found in links", WEIGHTS["base64InLinks"])
    s = min(s, 100)
    level = "High" if s >= 70 else "Medium" if s >= 40 else "Low"
    return s, level, issues

@app.route("/api/scan")
def api_scan():
    url = request.args.get("url","").strip()
    if not url:
        return jsonify(error="missing url"), 400
    try:
        r = requests.get(url, timeout=12, headers=UA)
        html = r.text
    except Exception as e:
        return jsonify(error="fetch_error", detail=str(e)), 500
    feats = collect_features(url, html)
    score, level, issues = score_features(feats)
    return jsonify(score=score, level=level, issues=issues, features=feats, url=url)

# ----------------- Sandbox Proxy -----------------

@app.route("/sandbox")
def sandbox_proxy():
    url = request.args.get("url", "").strip()
    if not url:
        return "missing url", 400
    try:
        r = requests.get(url, headers=UA, timeout=12)
        content_type = r.headers.get("Content-Type", "text/html; charset=utf-8")
        html = r.text
    except Exception as e:
        return f"fetch error: {e}", 502

    soup = BeautifulSoup(html, "html.parser")

    # Ensure a <head> exists and add a <base> so relative URLs work
    if not soup.head:
        soup.head = soup.new_tag("head")
        soup.insert(0, soup.head)
    base = soup.new_tag("base", href=url)
    soup.head.insert(0, base)

    # Remove inline CSP that prevents framing
    for m in soup.find_all("meta"):
        if m.get("http-equiv","").lower() == "content-security-policy":
            m.decompose()

    out = str(soup)

    resp = Response(out, status=200, mimetype=(content_type or "text/html").split(";")[0])
    # Re-assert the same iframe-friendly headers for this response too
    resp.headers["X-Frame-Options"] = "ALLOWALL"
    resp.headers["Content-Security-Policy"] = "frame-ancestors *"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/")
def index():
    return "<h2>✅ SiteGuard API v2 Online</h2><p>Use /api/scan?url=... and /sandbox?url=...</p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
