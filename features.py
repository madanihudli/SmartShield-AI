from urllib.parse import urlparse
import re, math, ipaddress

def extract_url_features(raw):
    raw=str(raw or "").strip()
    candidate=raw if re.match(r"^https?://",raw,re.I) else "http://"+raw
    p=urlparse(candidate)
    host=p.hostname or ""
    path=(p.path or "")+"?"+(p.query or "")
    full=host+path
    try: ipaddress.ip_address(host); is_ip=1
    except Exception: is_ip=0
    digits=sum(c.isdigit() for c in raw)
    letters=sum(c.isalpha() for c in raw)
    special=sum(not c.isalnum() for c in raw)
    tokens=["login","verify","account","secure","update","bank","wallet","password","signin","confirm","free","bonus","claim","invoice","payment"]
    suspicious=sum(1 for t in tokens if t in full.lower())
    return [
        len(raw),len(host),len(host.split(".")),is_ip,int(p.scheme=="https"),
        len(p.query),len(p.path),digits,letters,special,
        digits/max(1,len(raw)),special/max(1,len(raw)),raw.count("@"),
        raw.count("-"),raw.count("_"),raw.count("="),raw.count("&"),raw.count("%"),
        int("xn--" in host),int(host.startswith("www.")),int(bool(p.query)),
        suspicious,int(any(t in host.lower() for t in tokens)),
        int(len(host)>35),int(len(raw)>100),int(len(raw)>180),
        int("://" not in raw),int(host.count(".")>=3),
        int(bool(re.search(r"(paypal|google|microsoft|apple|amazon|bank)",host.lower()) and re.search(r"(login|verify|secure|account)",path.lower()))),
    ]
FEATURE_NAMES=[
"url_length","host_length","subdomain_count","is_ip","is_https","query_length","path_length",
"digit_count","letter_count","special_count","digit_ratio","special_ratio","at_count",
"hyphen_count","underscore_count","equals_count","ampersand_count","percent_count","punycode",
"www_prefix","has_query","sensitive_token_count","sensitive_host_token","long_host","long_url",
"very_long_url","missing_scheme","many_dots","brand_plus_login_path"
]
