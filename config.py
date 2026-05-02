"""
KAXIE Scanner - Yapılandırma Modülü
"""

import os
import random
import time

# API Base URL
API_BASE_URL = "http://medpi.gotdns.ch/v1"

# Tarama ayarları
SCAN_CONFIG = {
    "timeout": 15,
    "max_retries": 3,
    "retry_delay": (1, 5),
    "concurrent_requests": 25,
    "rate_limit_delay": 0.3,
    "follow_redirects": True,
    "verify_ssl": False,
    "max_depth": 5,
    "stealth_mode": True,
}

# User-Agent havuzu
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# Proxy havuzu (kullanıcı tarafından doldurulur)
PROXY_LIST = [
    # "http://127.0.0.1:8080",
    # "socks5://127.0.0.1:9050",
]

# Zafiyet kategorileri
VULN_CATEGORIES = [
    "SQL_INJECTION",
    "XSS",
    "RCE",
    "LFI",
    "RFI",
    "SSRF",
    "XXE",
    "CSRF",
    "DOS",
    "IDOR",
    "SSRF",
    "OPEN_REDIRECT",
    "INFO_DISCLOSURE",
    "CVE_2026",
    "AUTH_BYPASS",
    "WAF_BYPASS",
]

# Renk kodları
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
