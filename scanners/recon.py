"""
KAXIE Scanner - Keşif ve Bilgi Toplama Modülü
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG, USER_AGENTS, Colors
from utils.stealth import StealthManager


class ReconScanner:
    """Hedef hakkında kapsamlı bilgi toplar."""

    def __init__(self, target, reporter, ai_engine=None):
        self.target = target
        self.reporter = reporter
        self.ai_engine = ai_engine
        self.stealth = StealthManager()
        self.session = requests.Session()
        self.session.verify = SCAN_CONFIG["verify_ssl"]
        self.links = []
        self.forms = []
        self.headers_info = {}
        self.tech_stack = []
        self.interesting_paths = []
        self.cookies = {}
        self.robots_txt = ""
        self.sitemap_xml = ""
        self.dns_info = {}
        self.open_ports = []
        self.subdomains = []
        self.js_files = []
        self.api_endpoints = []
        self.emails = []
        self.comments = []

        self.interesting_paths_list = [
            "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/.htaccess",
            "/.git/config", "/wp-admin/", "/wp-login.php", "/administrator/",
            "/admin/", "/admin/login", "/phpmyadmin/", "/server-status",
            "/server-info", "/.svn/entries", "/backup/", "/backup.zip",
            "/backup.sql", "/db.sql", "/database.sql", "/.DS_Store",
            "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/elmah.axd", "/trace.axd", "/swagger-ui.html", "/api-docs",
            "/graphql", "/graphiql", "/.well-known/security.txt",
            "/security.txt", "/actuator", "/actuator/health",
            "/actuator/env", "/actuator/beans", "/console/",
            "/debug/", "/test/", "/temp/", "/tmp/", "/upload/",
            "/uploads/", "/files/", "/static/", "/assets/",
            "/cgi-bin/", "/cgi/", "/.bash_history", "/id_rsa",
            "/id_rsa.pub", "/.ssh/", "/config.php", "/config.yml",
            "/config.json", "/settings.py", "/.vscode/", "/.idea/",
            "/package.json", "/composer.json", "/Gemfile",
            "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
            "/nginx.conf", "/httpd.conf", "/web.config",
            "/.well-known/openid-configuration", "/.well-known/jwks.json",
            "/oauth/token", "/oauth/authorize", "/.github/",
            "/jenkins/", "/ci/", "/bamboo/", "/teamcity/",
            "/solr/", "/kibana/", "/elasticsearch/", "/grafana/",
            "/prometheus/", "/zipkin/", "/jaeger/",
        ]

    def run(self):
        """Tüm keşif taramalarını çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] KEŞİF VE BİLGİ TOPLAMA BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._get_headers()
        self._detect_tech_stack()
        self._crawl_links()
        self._extract_forms()
        self._check_interesting_paths()
        self._get_robots_txt()
        self._get_sitemap_xml()
        self._extract_js_files()
        self._extract_api_endpoints()
        self._extract_emails()
        self._extract_comments()
        self._check_security_headers()

        recon_data = self._compile_results()
        self.reporter.recon_data = recon_data

        if self.ai_engine and self.ai_engine.selected_model:
            print(f"\n{Colors.MAGENTA}  [*] AI strateji önerisi alınıyor...{Colors.RESET}")
            strategy = self.ai_engine.suggest_scan_strategy(self.target, recon_data)
            if strategy:
                print(f"\n{Colors.MAGENTA}  ═══ AI TARAMA STRATEJİSİ ═══{Colors.RESET}")
                print(f"{Colors.MAGENTA}{strategy}{Colors.RESET}")

        return recon_data

    def _make_request(self, url, method="GET", data=None, headers=None, allow_redirects=True):
        """Gizli istek yapar."""
        if headers is None:
            headers = self.stealth.get_headers(self.target)
        self.stealth.jitter_delay()

        try:
            resp = self.session.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                timeout=SCAN_CONFIG["timeout"],
                verify=False,
                allow_redirects=allow_redirects,
                proxies=self.stealth.get_proxy(),
            )
            self.reporter.scan_stats["total_requests"] += 1
            return resp
        except requests.exceptions.TooManyRedirects:
            return None
        except requests.exceptions.SSLError:
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    timeout=SCAN_CONFIG["timeout"],
                    verify=False,
                    allow_redirects=allow_redirects,
                    proxies=self.stealth.get_proxy(),
                )
                self.reporter.scan_stats["total_requests"] += 1
                return resp
            except Exception:
                return None
        except Exception:
            return None

    def _get_headers(self):
        """HTTP yanıt başlıklarını toplar."""
        print(f"\n  {Colors.BLUE}[*] HTTP başlıkları çekiliyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return
        self.headers_info = dict(resp.headers)
        server = resp.headers.get("Server", "Bilinmiyor")
        powered = resp.headers.get("X-Powered-By", "Bilinmiyor")
        print(f"    Server: {server}")
        print(f"    X-Powered-By: {powered}")
        print(f"    Status: {resp.status_code}")

    def _detect_tech_stack(self):
        """Teknoloji yığınını tespit eder."""
        print(f"\n  {Colors.BLUE}[*] Teknoloji tespiti yapılıyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return

        tech_signatures = {
            "PHP": [".php", "X-Powered-By: PHP", "PHPSESSID", "phpsessid"],
            "ASP.NET": ["X-AspNet-Version", "X-Powered-By: ASP.NET", "__VIEWSTATE", ".aspx"],
            "Java/Spring": ["X-Application-Context", "JSESSIONID", "Spring", ".do", ".action"],
            "Node.js": ["X-Powered-By: Express", "connect.sid", "X-Request-Id"],
            "Django": ["csrftoken", "django", "X-Frame-Options: DENY"],
            "Ruby on Rails": ["X-Request-Id", "X-Runtime", "_session_id"],
            "Laravel": ["laravel_session", "XSRF-TOKEN", "laravel"],
            "Flask": ["Werkzeug", "flask", "session"],
            "Nginx": ["Server: nginx"],
            "Apache": ["Server: Apache"],
            "IIS": ["Server: Microsoft-IIS", "Server: IIS"],
            "Cloudflare": ["cf-ray", "cloudflare", "Server: cloudflare"],
            "WordPress": ["wp-content", "wp-includes", "WordPress"],
            "Joomla": ["/media/jui/", "Joomla", "joomla"],
            "Drupal": ["Drupal", "drupal", "X-Drupal-Cache"],
            "jQuery": ["jquery", "jQuery"],
            "React": ["react", "reactjs", "__NEXT_DATA__"],
            "Vue.js": ["vue", "vuejs", "v-cloak"],
            "Angular": ["ng-version", "angular", "ng-app"],
        }

        page_text = resp.text.lower()
        headers_text = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        combined = page_text + " " + headers_text

        for tech, sigs in tech_signatures.items():
            for sig in sigs:
                if sig.lower() in combined:
                    if tech not in self.tech_stack:
                        self.tech_stack.append(tech)
                        print(f"    {Colors.GREEN}[+] {tech} tespit edildi{Colors.RESET}")
                    break

        if self.cookies:
            for cookie_name in self.cookies:
                cl = cookie_name.lower()
                if "phpsessid" in cl and "PHP" not in self.tech_stack:
                    self.tech_stack.append("PHP")
                    print(f"    {Colors.GREEN}[+] PHP tespit edildi (cookie){Colors.RESET}")
                elif "jsessionid" in cl and "Java/Spring" not in self.tech_stack:
                    self.tech_stack.append("Java/Spring")
                    print(f"    {Colors.GREEN}[+] Java/Spring tespit edildi (cookie){Colors.RESET}")
                elif "laravel" in cl and "Laravel" not in self.tech_stack:
                    self.tech_stack.append("Laravel")
                    print(f"    {Colors.GREEN}[+] Laravel tespit edildi (cookie){Colors.RESET}")

    def _crawl_links(self, max_pages=30):
        """Sayfadaki bağlantıları tarar."""
        print(f"\n  {Colors.BLUE}[*] Bağlantılar taranıyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return

        parsed_base = urlparse(self.target)
        base_domain = parsed_base.netloc

        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]

        found = set()
        for pattern in link_patterns:
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            found.update(matches)

        for link in found:
            full_url = urljoin(self.target, link)
            parsed = urlparse(full_url)
            if parsed.netloc == base_domain or not parsed.netloc:
                if full_url not in self.links:
                    self.links.append(full_url)
            if len(self.links) >= max_pages:
                break

        print(f"    {Colors.GREEN}[+] {len(self.links)} bağlantı bulundu{Colors.RESET}")

    def _extract_forms(self):
        """Sayfadaki formları çıkarır."""
        print(f"\n  {Colors.BLUE}[*] Formlar çıkarılıyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return

        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        select_pattern = re.compile(r'<select[^>]*>', re.IGNORECASE)
        textarea_pattern = re.compile(r'<textarea[^>]*>', re.IGNORECASE)

        forms = form_pattern.findall(resp.text)

        for i, form_html in enumerate(forms):
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            full_action = urljoin(self.target, action) if action else self.target

            inputs = []
            for inp in input_pattern.findall(form_html):
                name_match = re.search(r'name=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                inputs.append({
                    "name": name_match.group(1) if name_match else "",
                    "type": type_match.group(1) if type_match else "text",
                    "value": value_match.group(1) if value_match else "",
                })

            for sel in select_pattern.findall(form_html):
                name_match = re.search(r'name=["\']([^"\']*)["\']', sel, re.IGNORECASE)
                inputs.append({
                    "name": name_match.group(1) if name_match else "",
                    "type": "select",
                    "value": "",
                })

            for ta in textarea_pattern.findall(form_html):
                name_match = re.search(r'name=["\']([^"\']*)["\']', ta, re.IGNORECASE)
                inputs.append({
                    "name": name_match.group(1) if name_match else "",
                    "type": "textarea",
                    "value": "",
                })

            self.forms.append({
                "index": i,
                "action": full_action,
                "method": method,
                "inputs": inputs,
            })
            print(f"    {Colors.GREEN}[+] Form {i}: {method} {full_action} ({len(inputs)} alan){Colors.RESET}")

    def _check_interesting_paths(self):
        """İlginç yolları ve hassas dosyaları kontrol eder."""
        print(f"\n  {Colors.BLUE}[*] Hassas yollar kontrol ediliyor...{Colors.RESET}")
        found_count = 0

        def check_path(path):
            url = urljoin(self.target, path)
            resp = self._make_request(url, allow_redirects=False)
            if resp and resp.status_code in [200, 301, 302, 403]:
                return (path, resp.status_code, len(resp.content))
            return None

        with ThreadPoolExecutor(max_workers=SCAN_CONFIG["concurrent_requests"]) as executor:
            futures = {executor.submit(check_path, p): p for p in self.interesting_paths_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, status, size = result
                    self.interesting_paths.append({"path": path, "status": status, "size": size})
                    found_count += 1

                    severity = "INFO"
                    if any(x in path for x in [".env", ".git", ".ssh", "id_rsa", ".bash_history"]):
                        severity = "CRITICAL"
                    elif any(x in path for x in ["backup", ".sql", "db.sql", "phpmyadmin", "admin"]):
                        severity = "HIGH"
                    elif any(x in path for x in ["swagger", "api-docs", "actuator", "debug", "server-status"]):
                        severity = "MEDIUM"

                    if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                        self.reporter.add_finding(
                            vuln_type="INFO_DISCLOSURE",
                            severity=severity,
                            title=f"Hassas yol tespit edildi: {path}",
                            description=f"Hassas veya bilgi sızdıran bir yola erişim mümkün: {path}",
                            evidence=f"Status: {status}, Size: {size}",
                            url=urljoin(self.target, path),
                        )
                    else:
                        print(f"    {Colors.DIM}[{status}] {path} ({size} bytes){Colors.RESET}")

        print(f"    {Colors.GREEN}[+] {found_count} ilginç yol bulundu{Colors.RESET}")

    def _get_robots_txt(self):
        """robots.txt dosyasını çeker ve analiz eder."""
        print(f"\n  {Colors.BLUE}[*] robots.txt kontrol ediliyor...{Colors.RESET}")
        url = urljoin(self.target, "/robots.txt")
        resp = self._make_request(url)
        if resp and resp.status_code == 200:
            self.robots_txt = resp.text
            disallowed = re.findall(r'Disallow:\s*(.+)', resp.text, re.IGNORECASE)
            if disallowed:
                print(f"    {Colors.GREEN}[+] robots.txt bulundu, {len(disallowed)} Disallow kuralı{Colors.RESET}")
                for d in disallowed[:10]:
                    print(f"      {Colors.DIM}- {d.strip()}{Colors.RESET}")
                    full_url = urljoin(self.target, d.strip())
                    if full_url not in self.links:
                        self.links.append(full_url)
        else:
            print(f"    {Colors.DIM}[-] robots.txt bulunamadı{Colors.RESET}")

    def _get_sitemap_xml(self):
        """sitemap.xml dosyasını çeker."""
        print(f"\n  {Colors.BLUE}[*] sitemap.xml kontrol ediliyor...{Colors.RESET}")
        url = urljoin(self.target, "/sitemap.xml")
        resp = self._make_request(url)
        if resp and resp.status_code == 200:
            self.sitemap_xml = resp.text
            locs = re.findall(r'<loc>(.+?)</loc>', resp.text, re.IGNORECASE)
            if locs:
                print(f"    {Colors.GREEN}[+] sitemap.xml bulundu, {len(locs)} URL{Colors.RESET}")
                for loc in locs[:20]:
                    if loc not in self.links:
                        self.links.append(loc)
        else:
            print(f"    {Colors.DIM}[-] sitemap.xml bulunamadı{Colors.RESET}")

    def _extract_js_files(self):
        """JavaScript dosyalarını çıkarır."""
        print(f"\n  {Colors.BLUE}[*] JavaScript dosyaları çıkarılıyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return

        js_pattern = re.compile(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', re.IGNORECASE)
        matches = js_pattern.findall(resp.text)

        for m in matches:
            full_url = urljoin(self.target, m)
            if full_url not in self.js_files:
                self.js_files.append(full_url)

        api_pattern = re.compile(r'["\'](/api/[^"\']+)["\']', re.IGNORECASE)
        api_matches = api_pattern.findall(resp.text)
        for am in api_matches:
            full_url = urljoin(self.target, am)
            if full_url not in self.api_endpoints:
                self.api_endpoints.append(full_url)

        print(f"    {Colors.GREEN}[+] {len(self.js_files)} JS dosyası bulundu{Colors.RESET}")

    def _extract_api_endpoints(self):
        """API uç noktalarını tespit eder."""
        print(f"\n  {Colors.BLUE}[*] API uç noktaları aranıyor...{Colors.RESET}")

        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/graphiql", "/rest", "/v1", "/v2",
            "/swagger-ui.html", "/swagger-ui/", "/api-docs",
            "/api/swagger", "/openapi.json", "/openapi.yaml",
        ]

        for path in api_paths:
            url = urljoin(self.target, path)
            resp = self._make_request(url)
            if resp and resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if any(t in content_type for t in ["json", "html", "yaml", "text"]):
                    self.api_endpoints.append(url)
                    print(f"    {Colors.GREEN}[+] API uç noktası: {url}{Colors.RESET}")

        print(f"    {Colors.GREEN}[+] Toplam {len(self.api_endpoints)} API uç noktası{Colors.RESET}")

    def _extract_emails(self):
        """Sayfadaki e-posta adreslerini çıkarır."""
        print(f"\n  {Colors.BLUE}[*] E-posta adresleri aranıyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return

        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        found = email_pattern.findall(resp.text)

        self.emails = list(set(found))
        if self.emails:
            print(f"    {Colors.GREEN}[+] {len(self.emails)} e-posta adresi bulundu{Colors.RESET}")
            for e in self.emails[:5]:
                print(f"      {Colors.DIM}- {e}{Colors.RESET}")
            self.reporter.add_finding(
                vuln_type="INFO_DISCLOSURE",
                severity="LOW",
                title="E-posta adresi sızıntısı",
                description="Sayfa kaynağında e-posta adresleri tespit edildi.",
                evidence=", ".join(self.emails[:5]),
                url=self.target,
            )

    def _extract_comments(self):
        """HTML yorumlarını çıkarır."""
        print(f"\n  {Colors.BLUE}[*] HTML yorumları aranıyor...{Colors.RESET}")
        resp = self._make_request(self.target)
        if not resp:
            return

        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        found = comment_pattern.findall(resp.text)

        sensitive_keywords = [
            "password", "passwd", "secret", "key", "token", "api",
            "debug", "test", "temp", "todo", "fixme", "hack",
            "admin", "root", "database", "db_", "mysql", "postgres",
        ]

        for comment in found:
            comment_stripped = comment.strip()
            if not comment_stripped:
                continue

            self.comments.append(comment_stripped)
            comment_lower = comment_stripped.lower()
            for kw in sensitive_keywords:
                if kw in comment_lower:
                    self.reporter.add_finding(
                        vuln_type="INFO_DISCLOSURE",
                        severity="MEDIUM",
                        title="Hassas HTML yorumu tespit edildi",
                        description=f"HTML yorumunda hassas anahtar kelime: {kw}",
                        evidence=comment_stripped[:200],
                        url=self.target,
                    )
                    break

        print(f"    {Colors.GREEN}[+] {len(self.comments)} HTML yorumu bulundu{Colors.RESET}")

    def _check_security_headers(self):
        """Güvenlik başlıklarını kontrol eder."""
        print(f"\n  {Colors.BLUE}[*] Güvenlik başlıkları kontrol ediliyor...{Colors.RESET}")

        required_headers = {
            "X-Content-Type-Options": {"expected": "nosniff", "severity": "LOW", "desc": "MIME sniffing koruması eksik"},
            "X-Frame-Options": {"expected": ["DENY", "SAMEORIGIN"], "severity": "MEDIUM", "desc": "Clickjacking koruması eksik"},
            "X-XSS-Protection": {"expected": "1", "severity": "LOW", "desc": "XSS filtresi eksik"},
            "Strict-Transport-Security": {"expected": "max-age", "severity": "MEDIUM", "desc": "HSTS başlığı eksik"},
            "Content-Security-Policy": {"expected": None, "severity": "HIGH", "desc": "CSP başlığı eksik - XSS riski"},
            "Referrer-Policy": {"expected": None, "severity": "LOW", "desc": "Referrer-Policy başlığı eksik"},
            "Permissions-Policy": {"expected": None, "severity": "LOW", "desc": "Permissions-Policy başlığı eksik"},
            "Cross-Origin-Opener-Policy": {"expected": None, "severity": "LOW", "desc": "COOP başlığı eksik"},
            "Cross-Origin-Resource-Policy": {"expected": None, "severity": "LOW", "desc": "CORP başlığı eksik"},
        }

        missing = []
        for header, config in required_headers.items():
            if header not in self.headers_info:
                missing.append(header)
                self.reporter.add_finding(
                    vuln_type="MISSING_HEADER",
                    severity=config["severity"],
                    title=f"Eksik güvenlik başlığı: {header}",
                    description=config["desc"],
                    evidence=f"{header} başlığı sunucu yanıtında bulunamadı",
                    url=self.target,
                )
            else:
                value = self.headers_info[header]
                expected = config.get("expected")
                if expected:
                    if isinstance(expected, list):
                        if not any(e in value for e in expected):
                            self.reporter.add_finding(
                                vuln_type="WEAK_HEADER",
                                severity="LOW",
                                title=f"Zayıf başlık değeri: {header}",
                                description=f"{header}={value}, beklenen: {expected}",
                                evidence=value,
                                url=self.target,
                            )
                    elif isinstance(expected, str) and expected not in value:
                        self.reporter.add_finding(
                            vuln_type="WEAK_HEADER",
                            severity="LOW",
                            title=f"Zayıf başlık değeri: {header}",
                            description=f"{header}={value}, beklenen: {expected} içermeli",
                            evidence=value,
                            url=self.target,
                        )

        if missing:
            print(f"    {Colors.YELLOW}[!] {len(missing)} eksik güvenlik başlığı: {', '.join(missing)}{Colors.RESET}")
        else:
            print(f"    {Colors.GREEN}[+] Tüm güvenlik başlıkları mevcut{Colors.RESET}")

    def _compile_results(self):
        """Keşif sonuçlarını derler."""
        return {
            "target": self.target,
            "headers": self.headers_info,
            "tech_stack": self.tech_stack,
            "links_count": len(self.links),
            "links": self.links[:50],
            "forms": self.forms,
            "interesting_paths": self.interesting_paths,
            "js_files": self.js_files,
            "api_endpoints": self.api_endpoints,
            "emails": self.emails,
            "comments_count": len(self.comments),
            "cookies": dict(self.session.cookies),
            "robots_txt": self.robots_txt[:500] if self.robots_txt else None,
            "sitemap_found": bool(self.sitemap_xml),
        }
