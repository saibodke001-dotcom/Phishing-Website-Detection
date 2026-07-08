import re
import urllib.parse
import requests
import whois
import datetime
import socket

# Suspicious words commonly found in phishing URLs
SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'signin', 'support', 'service', 'confirm', 'billing', 'password', 'recover', 'auth', 'webscr']

# Common URL shortening services
SHORTENERS = [
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl", "tr.im",
    "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac",
    "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm", "post.ly",
    "Just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com", "short.ie",
    "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.co", "lnkd.in",
    "db.tt", "qr.ae", "adf.ly", "goo.gl", "bitly.com", "cur.lv", "tinyurl.com", "ow.ly",
    "bit.ly", "ity.im", "q.gs", "is.gd", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp",
    "buzurl.com", "cutt.us", "u.bb", "yourls.org", "x.co", "prettylinkpro.com", "scrnch.me",
    "filoops.info", "vzturl.com", "qr.net", "1url.com", "tweez.me", "v.gd", "tr.im", "link.zip.net"
]

def having_ip_address(url):
    """Checks if the URL uses an IP address instead of a domain name."""
    try:
        # IPv4 and IPv6 regex
        ip_regex = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])|' # IPv4
            r'((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))))' # IPv6
        )
        domain = urllib.parse.urlparse(url).netloc
        if ip_regex.search(domain):
            return 1
        return 0
    except:
        return 0

def url_length(url):
    """Returns 1 if URL is too long (> 54 chars) and might be suspicious, else 0."""
    return 1 if len(url) > 54 else 0

def having_at_symbol(url):
    """Checks for '@' symbol in URL."""
    return 1 if '@' in url else 0

def prefix_suffix_dash(url):
    """Checks for '-' in the domain part."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        return 1 if '-' in domain else 0
    except:
        return 0

def multi_subdomains(url):
    """Checks if there are multiple subdomains (e.g., > 3 dots in domain)."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        # Exclude 'www' from the count if present
        domain = domain.replace('www.', '')
        dots = domain.count('.')
        return 1 if dots >= 2 else 0
    except:
        return 0

def https_token(url):
    """Checks if 'https' is part of the domain name (not the scheme)."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        return 1 if 'https' in domain else 0
    except:
        return 0

def has_https(url):
    """Checks if the URL uses HTTPS."""
    try:
        scheme = urllib.parse.urlparse(url).scheme
        return 1 if scheme == 'https' else 0
    except:
        return 0

def shortining_service(url):
    """Checks if the URL uses a known URL shortening service."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        for shortener in SHORTENERS:
            if shortener in domain:
                return 1
        return 0
    except:
        return 0

def count_dots(url):
    """Counts total number of dots in the URL."""
    return url.count('.')

def count_digits(url):
    """Counts total number of digits in the URL."""
    return sum(c.isdigit() for c in url)

def count_special_chars(url):
    """Counts special characters like ? = % & in the URL."""
    special_chars = "?=%&_;"
    return sum(url.count(c) for c in special_chars)

def has_suspicious_words(url):
    """Checks if URL contains words commonly used in phishing."""
    url_lower = url.lower()
    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            return 1
    return 0

def domain_age(url):
    """
    Checks if domain age is < 6 months (phishing domains are often young).
    This function uses WHOIS. If WHOIS fails, it defaults to returning 1 (suspicious).
    """
    try:
        domain = urllib.parse.urlparse(url).netloc
        domain = domain.replace('www.', '')
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.datetime.strptime(creation_date, '%Y-%m-%d')
            except:
                return 1 # Cannot parse date, flag as suspicious
        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            return 1 if age < 180 else 0 # Suspicious if < 6 months
        return 1
    except Exception as e:
        return 1 # WHOIS failed, flag as suspicious (or return -1 for missing)

def mock_favicon_mismatch(url):
    """Mock API for favicon mismatch since it requires downloading the page."""
    return 0 # Assume no mismatch for simple feature vector

def mock_redirects(url):
    """Mock API for redirect count. We could use requests to follow, but it's slow."""
    return 0 # Assume no excessive redirects

def extract_features(url):
    """
    Extracts all features from the given URL and returns them as a dictionary.
    This structure matches the columns of the synthetic training dataset.
    """
    # Ensure URL has a scheme for proper parsing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    features = {}
    features['having_ip_address'] = having_ip_address(url)
    features['url_length'] = url_length(url)
    features['having_at_symbol'] = having_at_symbol(url)
    features['prefix_suffix_dash'] = prefix_suffix_dash(url)
    features['multi_subdomains'] = multi_subdomains(url)
    features['https_token'] = https_token(url)
    features['has_https'] = has_https(url)
    features['shortining_service'] = shortining_service(url)
    features['count_dots'] = count_dots(url)
    features['count_digits'] = count_digits(url)
    features['count_special_chars'] = count_special_chars(url)
    features['has_suspicious_words'] = has_suspicious_words(url)
    features['domain_age'] = domain_age(url)
    features['favicon_mismatch'] = mock_favicon_mismatch(url)
    features['redirects'] = mock_redirects(url)
    
    return features
