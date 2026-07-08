"""
LinkGuard – backend API
------------------------
A heuristic link-safety scanner. It doesn't rely on any paid third-party
API, so it works out of the box. Every check is transparent: the response
tells the user exactly *why* a link was scored the way it was.

Run:
    pip install -r requirements.txt
    python app.py
Then open frontend/index.html in a browser (it calls http://localhost:5000).
"""

import re
import socket
from urllib.parse import urlparse, unquote

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# Reference data used by the heuristics
# ---------------------------------------------------------------------------

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc", "s.id",
    "shorturl.at", "rb.gy", "bl.ink",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "support", "gq", "loan", "win", "review", "download", "zip", "country",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "password", "signin", "webscr", "billing", "suspend", "unlock", "invoice",
}

# Popular brand domains used for typosquatting comparison (name -> real domain)
POPULAR_BRANDS = {
    "google": "google.com", "paypal": "paypal.com", "amazon": "amazon.com",
    "apple": "apple.com", "microsoft": "microsoft.com", "facebook": "facebook.com",
    "netflix": "netflix.com", "instagram": "instagram.com", "bankofamerica": "bankofamerica.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "linkedin": "linkedin.com",
    "twitter": "twitter.com", "x": "x.com", "dropbox": "dropbox.com",
    "coinbase": "coinbase.com", "binance": "binance.com", "steamcommunity": "steamcommunity.com",
    "ebay": "ebay.com", "outlook": "outlook.com", "office365": "office.com",
    "whatsapp": "whatsapp.com", "adobe": "adobe.com", "yahoo": "yahoo.com",
    "hsbc": "hsbc.com", "citibank": "citibank.com",
}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance, used for typosquatting detection."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def add_check(checks, name, ok, weight, message):
    checks.append({"name": name, "passed": ok, "weight": weight, "message": message})
    return weight if not ok else 0


def analyze_url(raw_url: str) -> dict:
    original = raw_url.strip()
    url = original if re.match(r"^https?://", original, re.I) else f"http://{original}"

    parsed = urlparse(url)
    domain = parsed.netloc.split("@")[-1].split(":")[0].lower()
    path_and_query = unquote((parsed.path or "") + "?" + (parsed.query or "")).lower()

    checks = []
    deductions = 0

    # 1. HTTPS
    deductions += add_check(
        checks, "Encryption (HTTPS)", parsed.scheme == "https", 8,
        "Site does not use HTTPS encryption." if parsed.scheme != "https"
        else "Uses HTTPS encryption."
    )

    # 2. IP address instead of a domain name
    is_ip = bool(IPV4_RE.match(domain))
    deductions += add_check(
        checks, "Domain type", not is_ip, 25,
        "Link uses a raw IP address instead of a domain name." if is_ip
        else "Uses a normal domain name."
    )

    # 3. '@' symbol trick (browsers ignore everything before '@')
    has_at = "@" in original
    deductions += add_check(
        checks, "'@' symbol", not has_at, 25,
        "Contains an '@' symbol, which can hide the real destination." if has_at
        else "No '@' symbol trick detected."
    )

    # 4. Excessive URL length
    long_url = len(original) > 90
    deductions += add_check(
        checks, "URL length", not long_url, 8,
        "Unusually long URL, often used to hide suspicious parts." if long_url
        else "Reasonable URL length."
    )

    # 5. Excessive subdomains
    subdomain_count = max(domain.count(".") - 1, 0)
    too_many_subs = subdomain_count > 3
    deductions += add_check(
        checks, "Subdomain count", not too_many_subs, 12,
        f"Has {subdomain_count} subdomains, more than expected." if too_many_subs
        else "Normal subdomain structure."
    )

    # 6. Excessive hyphens (common in look-alike domains)
    many_hyphens = domain.count("-") > 2
    deductions += add_check(
        checks, "Hyphen usage", not many_hyphens, 8,
        "Domain contains many hyphens, a common phishing pattern." if many_hyphens
        else "Normal hyphen usage."
    )

    # 7. Known URL shortener
    base_domain = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
    is_shortener = base_domain in KNOWN_SHORTENERS or domain in KNOWN_SHORTENERS
    deductions += add_check(
        checks, "URL shortener", not is_shortener, 12,
        "This is a shortened link, so the real destination is hidden." if is_shortener
        else "Not a link-shortening service."
    )

    # 8. Suspicious keywords in path/query, only flagged on non-popular domains
    is_popular_exact = base_domain in POPULAR_BRANDS.values()
    found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in path_and_query]
    flag_keywords = bool(found_keywords) and not is_popular_exact
    deductions += add_check(
        checks, "Suspicious wording", not flag_keywords, 10,
        f"Contains alarming/urgent wording ({', '.join(found_keywords[:3])}) on an unfamiliar domain."
        if flag_keywords else "No manipulative wording detected."
    )

    # 9. Suspicious top-level domain
    tld = domain.split(".")[-1] if "." in domain else ""
    bad_tld = tld in SUSPICIOUS_TLDS
    deductions += add_check(
        checks, "Domain extension", not bad_tld, 10,
        f"Uses a top-level domain (.{tld}) frequently abused for scams." if bad_tld
        else "Domain extension has no bad reputation on record."
    )

    # 10. Punycode / homograph attack
    is_punycode = "xn--" in domain
    deductions += add_check(
        checks, "Punycode check", not is_punycode, 20,
        "Domain uses punycode encoding, often used to fake familiar brand names." if is_punycode
        else "No punycode/homograph trickery detected."
    )

    # 11. Typosquatting against popular brands
    typo_hit = None
    domain_core = domain.split(".")[0]
    for brand, real_domain in POPULAR_BRANDS.items():
        if base_domain == real_domain:
            continue  # it's the real thing
        dist = levenshtein(domain_core, brand)
        if 0 < dist <= 2 and len(brand) > 3:
            typo_hit = (brand, real_domain)
            break
        if brand in domain and base_domain != real_domain:
            typo_hit = (brand, real_domain)
            break
    deductions += add_check(
        checks, "Brand impersonation", typo_hit is None, 30,
        f"Domain closely mimics '{typo_hit[1]}' but is not the real site." if typo_hit
        else "No brand impersonation pattern detected."
    )

    # 12. Digit-heavy domain
    digit_ratio = sum(c.isdigit() for c in domain_core) / max(len(domain_core), 1)
    digit_heavy = digit_ratio > 0.3
    deductions += add_check(
        checks, "Digit density", not digit_heavy, 6,
        "Domain name contains an unusually high number of digits." if digit_heavy
        else "Normal character composition."
    )

    # 13. DNS resolution sanity check (best-effort, ignored if offline)
    resolves = True
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname(domain)
    except Exception:
        resolves = False
    deductions += add_check(
        checks, "Domain resolves", resolves, 15,
        "Domain name could not be resolved / does not appear to exist." if not resolves
        else "Domain resolves to a live server."
    )

    score = max(0, min(100, 100 - deductions))

    if score >= 80:
        verdict, level = "Safe", "safe"
    elif score >= 50:
        verdict, level = "Suspicious", "suspicious"
    else:
        verdict, level = "Dangerous", "dangerous"

    return {
        "url": original,
        "domain": domain,
        "score": score,
        "verdict": verdict,
        "level": level,
        "checks": checks,
    }


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL is too long."}), 400
    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as exc:  # pragma: no cover
        return jsonify({"error": f"Could not analyze this URL ({exc})."}), 500


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
