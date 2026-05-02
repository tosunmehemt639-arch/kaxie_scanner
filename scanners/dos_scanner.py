"""
KAXIE Scanner - DoS/DDoS Test Modülü
Not: Sadece yetkili penetrasyon testlerinde kullanılır.
"""

import time
import threading
import requests
import random
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from config import SCAN_CONFIG, Colors
from utils.stealth import StealthManager


class DOSScanner:
    """DoS/DDoS zafiyet tarama ve test sınıfı."""

    def __init__(self, target, reporter, ai_engine=None):
        self.target = target
        self.reporter = reporter
        self.ai_engine = ai_engine
        self.stealth = StealthManager()
        self.parsed = urlparse(target)
        self.host = self.parsed.hostname or self.parsed.netloc
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.results = []
        self._stop_event = threading.Event()

    def run(self):
        """Tüm DoS testlerini çalıştırır."""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] DOS/DDOS ZAFİYET TESTİ BAŞLADI{Colors.RESET}")
        print(f"{Colors.CYAN}  [*] Hedef: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

        self._test_rate_limiting()
        self._test_slowloris()
        self._test_http_flood()
        self._test_large_payload()
        self._test_concurrent_connections()
        self._test_resource_exhaustion()

        if self.ai_engine and self.ai_engine.selected_model and self.results:
            print(f"\n{Colors.MAGENTA}  [*] AI DoS analiz yapılıyor...{Colors.RESET}")
            for r in self.results:
                analysis = self.ai_engine.analyze_vulnerability(
                    vuln_type="DOS",
                    target=self.target,
                    evidence=r["evidence"],
                    response_snippet=r.get("details", ""),
                )
                if analysis:
                    self.reporter.add_ai_analysis("DOS", analysis)

        return self.results

    def _test_rate_limiting(self):
        """Rate limiting mekanizmasını test eder."""
        print(f"\n  {Colors.BLUE}[*] Rate limiting testi...{Colors.RESET}")

        success_count = 0
        total_requests = 50
        start_time = time.time()
        response_times = []

        for i in range(total_requests):
            try:
                headers = self.stealth.get_headers(self.target)
                req_start = time.time()
                resp = requests.get(
                    self.target,
                    headers=headers,
                    timeout=SCAN_CONFIG["timeout"],
                    verify=SCAN_CONFIG["verify_ssl"],
                    allow_redirects=SCAN_CONFIG["follow_redirects"],
                )
                req_time = time.time() - req_start
                response_times.append(req_time)

                if resp.status_code == 200:
                    success_count += 1
                elif resp.status_code == 429:
                    print(f"    {Colors.GREEN}[+] Rate limiting aktif (429 alındı, istek #{i+1}){Colors.RESET}")
                    return

                self.stealth.jitter_delay()

            except Exception:
                pass

        elapsed = time.time() - start_time
        avg_time = sum(response_times) / len(response_times) if response_times else 0
        rps = total_requests / elapsed if elapsed > 0 else 0

        if success_count == total_requests:
            self.reporter.add_finding(
                vuln_type="DOS",
                severity="MEDIUM",
                title="Rate limiting mekanizması yok",
                description=f"{total_requests} istek gönderildi, hiçbiri engellenmedi. RPS: {rps:.2f}",
                evidence=f"Success: {success_count}/{total_requests}, RPS: {rps:.2f}, Avg: {avg_time:.3f}s",
                url=self.target,
            )
            self.results.append({
                "test": "rate_limiting",
                "vulnerable": True,
                "evidence": f"No rate limiting. {total_requests}/{total_requests} succeeded. RPS: {rps:.2f}",
                "details": f"Avg response: {avg_time:.3f}s",
            })
        else:
            print(f"    {Colors.GREEN}[+] Rate limiting mekanizması tespit edildi{Colors.RESET}")

    def _test_slowloris(self):
        """Slowloris tipi yavaş bağlantı testi."""
        print(f"\n  {Colors.BLUE}[*] Slowloris testi...{Colors.RESET}")

        try:
            connections = []
            num_connections = 20
            successful = 0

            for i in range(num_connections):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.host, self.port))

                    if self.parsed.scheme == "https":
                        import ssl
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=self.host)

                    request = f"GET / HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: Kaxie-Scanner\r\n"
                    sock.send(request.encode())
                    connections.append(sock)
                    successful += 1

                except Exception:
                    pass

            time.sleep(3)

            keep_alive_sent = 0
            for sock in connections:
                try:
                    sock.send(b"X-a: b\r\n")
                    keep_alive_sent += 1
                except Exception:
                    pass

            time.sleep(2)

            alive = 0
            for sock in connections:
                try:
                    sock.send(b"X-c: d\r\n")
                    alive += 1
                except Exception:
                    try:
                        sock.close()
                    except Exception:
                        pass

            if alive > num_connections * 0.7:
                self.reporter.add_finding(
                    vuln_type="DOS",
                    severity="HIGH",
                    title="Slowloris zafiyeti tespit edildi",
                    description="Sunucu yavaş bağlantıları kapatmıyor. Slowloris saldırısına karşı savunmasız.",
                    evidence=f"{alive}/{num_connections} bağlantı hala açık",
                    url=self.target,
                )
                self.results.append({
                    "test": "slowloris",
                    "vulnerable": True,
                    "evidence": f"{alive}/{num_connections} connections alive after slowloris test",
                    "details": f"Successful connections: {successful}",
                })
            else:
                print(f"    {Colors.GREEN}[+] Slowloris koruması mevcut ({alive}/{num_connections} açık){Colors.RESET}")

            for sock in connections:
                try:
                    sock.close()
                except Exception:
                    pass

        except Exception as e:
            print(f"    {Colors.YELLOW}[-] Slowloris testi hatası: {e}{Colors.RESET}")

    def _test_http_flood(self):
        """HTTP flood dayanıklılık testi."""
        print(f"\n  {Colors.BLUE}[*] HTTP flood dayanıklılık testi...{Colors.RESET}")

        num_requests = 30
        success = 0
        errors = 0
        response_codes = {}
        response_times = []

        def send_request():
            nonlocal success, errors
            try:
                headers = self.stealth.get_headers(self.target)
                start = time.time()
                resp = requests.get(
                    self.target,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=True,
                )
                elapsed = time.time() - start
                response_times.append(elapsed)

                code = resp.status_code
                response_codes[code] = response_codes.get(code, 0) + 1
                if code == 200:
                    success += 1
                elif code >= 500:
                    errors += 1

            except requests.exceptions.Timeout:
                errors += 1
                response_codes["timeout"] = response_codes.get("timeout", 0) + 1
            except Exception:
                errors += 1

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(send_request) for _ in range(num_requests)]
            for f in as_completed(futures):
                pass

        if errors > num_requests * 0.3:
            self.reporter.add_finding(
                vuln_type="DOS",
                severity="HIGH",
                title="HTTP flood zafiyeti",
                description=f"{num_requests} istekle %{(errors/num_requests)*100:.0f} hata oranı. Sunucu yük altında çöküyor.",
                evidence=f"Errors: {errors}/{num_requests}, Codes: {response_codes}",
                url=self.target,
            )
            self.results.append({
                "test": "http_flood",
                "vulnerable": True,
                "evidence": f"Error rate: {(errors/num_requests)*100:.1f}%",
                "details": f"Response codes: {response_codes}",
            })
        else:
            avg_time = sum(response_times) / len(response_times) if response_times else 0
            print(f"    {Colors.GREEN}[+] HTTP flood dayanıklılığı iyi (Hata: {errors}/{num_requests}, Ortalama: {avg_time:.3f}s){Colors.RESET}")

    def _test_large_payload(self):
        """Büyük payload ile bellek tüketimi testi."""
        print(f"\n  {Colors.BLUE}[*] Büyük payload testi...{Colors.RESET}")

        large_payload = "A" * 100000
        test_params = [
            {"name": "large_get", "method": "GET", "url": f"{self.target}?data={large_payload[:2000]}"},
            {"name": "large_post", "method": "POST", "url": self.target, "data": {"input": large_payload}},
            {"name": "large_json", "method": "POST", "url": self.target, "data": f'{{"data":"{large_payload}"}}', "content_type": "application/json"},
        ]

        for test in test_params:
            try:
                headers = self.stealth.get_headers(self.target)
                if test.get("content_type"):
                    headers["Content-Type"] = test["content_type"]

                start = time.time()
                if test["method"] == "GET":
                    resp = requests.get(
                        test["url"],
                        headers=headers,
                        timeout=15,
                        verify=False,
                    )
                else:
                    resp = requests.post(
                        test["url"],
                        data=test.get("data"),
                        headers=headers,
                        timeout=15,
                        verify=False,
                    )

                elapsed = time.time() - start

                if resp.status_code == 413:
                    print(f"    {Colors.GREEN}[+] Payload boyutu sınırı mevcut (413){Colors.RESET}")
                elif resp.status_code >= 500:
                    self.reporter.add_finding(
                        vuln_type="DOS",
                        severity="HIGH",
                        title=f"Büyük payload ile sunucu hatası ({test['name']})",
                        description="Sunucu büyük payload karşısında 500 hatası veriyor.",
                        evidence=f"Status: {resp.status_code}, Time: {elapsed:.2f}s",
                        url=test["url"],
                    )
                    self.results.append({
                        "test": f"large_payload_{test['name']}",
                        "vulnerable": True,
                        "evidence": f"Server error {resp.status_code} with large payload",
                        "details": f"Response time: {elapsed:.2f}s",
                    })
                elif elapsed > 10:
                    self.reporter.add_finding(
                        vuln_type="DOS",
                        severity="MEDIUM",
                        title=f"Büyük payload ile yavaş yanıt ({test['name']})",
                        description="Sunucu büyük payload karşısında aşırı yavaş yanıt veriyor.",
                        evidence=f"Response time: {elapsed:.2f}s",
                        url=test["url"],
                    )

            except requests.exceptions.Timeout:
                self.reporter.add_finding(
                    vuln_type="DOS",
                    severity="HIGH",
                    title=f"Büyük payload ile timeout ({test['name']})",
                    description="Sunucu büyük payload karşısında zaman aşımına uğradı.",
                    evidence="Request timed out after 15s",
                    url=test["url"],
                )
            except Exception:
                pass

    def _test_concurrent_connections(self):
        """Eşzamanlı bağlantı sınırı testi."""
        print(f"\n  {Colors.BLUE}[*] Eşzamanlı bağlantı testi...{Colors.RESET}")

        max_concurrent = 50
        successful = 0
        failed = 0

        def test_connection():
            nonlocal successful, failed
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.host, self.port))
                successful += 1
                time.sleep(2)
                sock.close()
            except Exception:
                failed += 1

        threads = []
        for _ in range(max_concurrent):
            t = threading.Thread(target=test_connection)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        if successful > max_concurrent * 0.8:
            self.reporter.add_finding(
                vuln_type="DOS",
                severity="MEDIUM",
                title="Yüksek eşzamanlı bağlantı sınırı yok",
                description=f"{max_concurrent} eşzamanlı bağlantı açılabildi. Sunucu bağlantı sınırı uygulamıyor.",
                evidence=f"Successful: {successful}, Failed: {failed}",
                url=self.target,
            )
            self.results.append({
                "test": "concurrent_connections",
                "vulnerable": True,
                "evidence": f"{successful}/{max_concurrent} concurrent connections established",
                "details": f"Failed: {failed}",
            })
        else:
            print(f"    {Colors.GREEN}[+] Bağlantı sınırı mevcut ({successful}/{max_concurrent}){Colors.RESET}")

    def _test_resource_exhaustion(self):
        """Kaynak tüketimi testi."""
        print(f"\n  {Colors.BLUE}[*] Kaynak tüketimi testi...{Colors.RESET}")

        baseline_resp = None
        baseline_time = 0

        try:
            headers = self.stealth.get_headers(self.target)
            start = time.time()
            baseline_resp = requests.get(
                self.target,
                headers=headers,
                timeout=10,
                verify=False,
            )
            baseline_time = time.time() - start
        except Exception:
            print(f"    {Colors.YELLOW}[-] Temel yanıt alınamadı{Colors.RESET}")
            return

        for i in range(5):
            try:
                headers = self.stealth.get_headers(self.target)
                start = time.time()
                resp = requests.get(
                    self.target,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
                elapsed = time.time() - start

                if elapsed > baseline_time * 5 and baseline_time > 0:
                    self.reporter.add_finding(
                        vuln_type="DOS",
                        severity="MEDIUM",
                        title="Kaynak tüketimi zafiyeti",
                        description="Sunucu yanıt süresi önemli ölçüde arttı.",
                        evidence=f"Baseline: {baseline_time:.3f}s, Current: {elapsed:.3f}s",
                        url=self.target,
                    )
                    self.results.append({
                        "test": "resource_exhaustion",
                        "vulnerable": True,
                        "evidence": f"Response time increased from {baseline_time:.3f}s to {elapsed:.3f}s",
                        "details": f"Degradation: {((elapsed - baseline_time) / baseline_time) * 100:.1f}%",
                    })
                    break

            except Exception:
                pass

            time.sleep(1)

        print(f"    {Colors.GREEN}[+] Kaynak tüketimi testi tamamlandı{Colors.RESET}")

    def stop(self):
        """Taramayı durdurur."""
        self._stop_event.set()
