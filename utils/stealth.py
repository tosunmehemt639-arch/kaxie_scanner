"""
KAXIE Scanner - Gizlilik ve Anti-Dedeksiyon Modülü
"""

import random
import time
import hashlib
import threading
from config import USER_AGENTS, PROXY_LIST, SCAN_CONFIG, Colors


class StealthManager:
    """Tarama gizliliğini yöneten sınıf."""

    def __init__(self):
        self.request_count = 0
        self.session_fingerprints = set()
        self._lock = threading.Lock()

    def get_random_delay(self):
        """Rastgele gecikme süresi üretir."""
        if SCAN_CONFIG["stealth_mode"]:
            return random.uniform(0.1, 2.5)
        return SCAN_CONFIG["rate_limit_delay"]

    def get_headers(self, base_url=""):
        """Her istek için benzersiz, gerçekçi header'lar üretir."""
        ua = random.choice(USER_AGENTS)

        accept_langs = [
            "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "en-US,en;q=0.9,tr;q=0.8",
            "en-GB,en;q=0.9,en-US;q=0.8",
            "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        ]

        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(accept_langs),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        if base_url:
            headers["Referer"] = base_url

        with self._lock:
            self.request_count += 1

        return headers

    def get_proxy(self):
        """Rastgele proxy seçer."""
        if PROXY_LIST:
            proxy = random.choice(PROXY_LIST)
            return {"http": proxy, "https": proxy}
        return None

    def rotate_fingerprint(self):
        """Tarayıcı parmak izini döndürür."""
        fp = hashlib.md5(
            f"{random.random()}{time.time()}{random.randint(1000,9999)}".encode()
        ).hexdigest()[:16]

        with self._lock:
            self.session_fingerprints.add(fp)

        return fp

    def jitter_delay(self):
        """İstekler arası rastgele jitter uygular."""
        if SCAN_CONFIG["stealth_mode"]:
            base = SCAN_CONFIG["rate_limit_delay"]
            jitter = random.uniform(0, base * 3)
            time.sleep(base + jitter)

    def get_tor_session(self):
        """Tor ağı üzerinden oturum oluşturur (SOCKS5 proxy gerekli)."""
        try:
            import requests
            session = requests.Session()
            session.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }
            return session
        except Exception:
            return None
