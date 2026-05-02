#!/usr/bin/env python3
"""
KAXIE SCANNER v2026.1
All-in-One Full Stack Web Vulnerability Scanner
AI-Augmented | Stealth | CVE-2026+ Ready
"""

import sys
import os
import argparse
import signal
import threading
import time
from datetime import datetime
import urllib3
from config import Colors, SCAN_CONFIG
from ai_engine import AIEngine
from utils.reporter import ReportManager
from utils.stealth import StealthManager
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.recon import ReconScanner
from scanners.dos_scanner import DOSScanner
from scanners.rce_scanner import RCEScanner
from scanners.cve_scanner import CVEScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.lfi_rfi import LFIRFIScanner
from scanners.ssrf_scanner import SSRFScanner
from scanners.waf_bypass import WAFBypassScanner
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def banner():
    print(f"""{Colors.BOLD}{Colors.RED}
    ██╗  ██╗ █████╗ ██╗  ██╗██╗███████╗
    ██║ ██╔╝██╔══██╗╚██╗██╔╝██║██╔════╝
    █████╔╝ ███████║ ╚███╔╝ ██║█████╗  
    ██╔═██╗ ██╔══██║ ██╔██╗ ██║██╔══╝  
    ██║  ██╗██║  ██║██╔╝ ██╗██║███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝
    {Colors.CYAN}All-in-One Full Stack Web Vulnerability Scanner{Colors.RESET}
    {Colors.DIM}AI-Augmented | Stealth Mode | CVE-2026+ | API: medpi.gotdns.ch{Colors.RESET}
    {Colors.RED}{'='*60}{Colors.RESET}
    """)


class KaxieScanner:
    """Ana tarayıcı orkestratörü."""

    def __init__(self, target, args):
        self.target = target.rstrip("/")
        self.args = args
        self.reporter = ReportManager(self.target)
        self.ai_engine = AIEngine() if not args.no_ai else None
        self.stealth = StealthManager()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}[!] Sinyal alındı. Tarama durduruluyor...{Colors.RESET}")
        self._stop_event.set()

    def _check_stop(self):
        if self._stop_event.is_set():
            raise KeyboardInterrupt

    def run(self):
        """Ana tarama akışını çalıştırır."""
        self.reporter.scan_stats["start_time"] = datetime.now().isoformat()

        # ─── FAZ 0: AI MODEL SEÇİMİ ───
        if self.ai_engine:
            print(f"{Colors.MAGENTA}[*] AI Motoru başlatılıyor...{Colors.RESET}")
            ai_ready = self.ai_engine.interactive_select()
            if not ai_ready:
                print(f"{Colors.YELLOW}[!] AI devre dışı, manuel tarama devam ediyor.{Colors.RESET}")

        # ─── FAZ 1: KEŞİF (RECON) ───
        self._check_stop()
        recon = ReconScanner(self.target, self.reporter, self.ai_engine)
        recon_data = recon.run()

        forms = recon_data.get("forms", [])
        links = recon_data.get("links", [])

        # ─── FAZ 2: WAF TESPİT / BYPASS ───
        self._check_stop()
        if not self.args.skip_waf:
            waf_scanner = WAFBypassScanner(self.target, self.reporter, self.ai_engine)
            waf_scanner.run()

        # ─── FAZ 3: ZAFİYET TARAMALARI ───
        scanners_to_run = []

        if not self.args.skip_sqli:
            scanners_to_run.append(("SQL Injection", SQLiScanner(self.target, self.reporter, self.ai_engine, forms, links)))
        if not self.args.skip_xss:
            scanners_to_run.append(("XSS", XSSScanner(self.target, self.reporter, self.ai_engine, forms, links)))
        if not self.args.skip_rce:
            scanners_to_run.append(("RCE", RCEScanner(self.target, self.reporter, self.ai_engine, forms, links)))
        if not self.args.skip_lfi:
            scanners_to_run.append(("LFI/RFI", LFIRFIScanner(self.target, self.reporter, self.ai_engine, forms, links)))
        if not self.args.skip_ssrf:
            scanners_to_run.append(("SSRF", SSRFScanner(self.target, self.reporter, self.ai_engine, forms, links)))
        if not self.args.skip_cve:
            scanners_to_run.append(("CVE-2026+", CVEScanner(self.target, self.reporter, self.ai_engine, recon_data)))
        if not self.args.skip_dos:
            scanners_to_run.append(("DoS/Stress", DOSScanner(self.target, self.reporter, self.ai_engine)))

        for name, scanner in scanners_to_run:
            self._check_stop()
            try:
                scanner.run()
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"{Colors.RED}[!] {name} modülünde hata: {e}{Colors.RESET}")

        # ─── FAZ 4: FİNAL AI ANALİZİ ───
        if self.ai_engine and self.ai_engine.selected_model and self.reporter.findings:
            self._final_ai_analysis()

        # ─── FAZ 5: RAPORLAMA ───
        self.reporter.scan_stats["end_time"] = datetime.now().isoformat()
        self.reporter.print_summary()

        if self.args.json or self.args.all_reports:
            self.reporter.save_json_report()
        if self.args.html or self.args.all_reports:
            self.reporter.save_html_report()

        return self.reporter.findings

    def _final_ai_analysis(self):
        """Tüm bulgular üzerinden genel AI analizi."""
        print(f"\n{Colors.MAGENTA}[*] Final AI risk değerlendirmesi yapılıyor...{Colors.RESET}")

        critical_count = self.reporter.scan_stats["CRITICAL"]
        high_count = self.reporter.scan_stats["HIGH"]

        if critical_count > 0:
            prompt = (
                f"Hedefte {critical_count} kritik ve {high_count} yüksek riskli zafiyet tespit edildi. "
                f"Bu zafiyetlerin birlikte kullanımı (kill chain) ile hedefin tamamen ele geçirilmesi mümkün mü? "
                f"Özet bir saldırı senaryosu ve öncelikli düzeltme adımları sun."
            )
            analysis = self.ai_engine.chat_completion(
                system_prompt="Sen ileri düzey bir penetrasyon test uzmanısın. Tespit edilen zafiyetlerin kombinasyonunu analiz et.",
                user_message=prompt,
                max_tokens=1500,
            )
            if analysis:
                print(f"\n{Colors.MAGENTA}═══ AI KILL CHAIN ANALİZİ ═══{Colors.RESET}")
                print(f"{Colors.MAGENTA}{analysis}{Colors.RESET}")
                self.reporter.add_ai_analysis("FINAL_KILLCHAIN", analysis)


def build_parser():
    parser = argparse.ArgumentParser(
        description="KAXIE Scanner - All-in-One Full Stack Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Kullanım Örnekleri:{Colors.RESET}
  python3 kaxie_scanner.py -u https://hedef.com
  python3 kaxie_scanner.py -u https://hedef.com --all-reports --no-ai
  python3 kaxie_scanner.py -u https://hedef.com --skip-dos --skip-cve
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Hedef URL (https://example.com)")
    parser.add_argument("--threads", type=int, default=25, help="Eşzamanlı istek sayısı")
    parser.add_argument("--timeout", type=int, default=15, help="İstek zaman aşımı (saniye)")
    parser.add_argument("--stealth", action="store_true", default=True, help="Gizli mod aktif")
    parser.add_argument("--no-stealth", action="store_true", help="Gizli mod pasif")

    parser.add_argument("--no-ai", action="store_true", help="AI motorunu devre dışı bırak")
    parser.add_argument("--json", action="store_true", help="JSON raporu kaydet")
    parser.add_argument("--html", action="store_true", help="HTML raporu kaydet")
    parser.add_argument("--all-reports", action="store_true", help="Tüm rapor formatlarını kaydet")

    parser.add_argument("--skip-recon", action="store_true", help="Keşif fazını atla")
    parser.add_argument("--skip-waf", action="store_true", help="WAF taramasını atla")
    parser.add_argument("--skip-sqli", action="store_true", help="SQLi taramasını atla")
    parser.add_argument("--skip-xss", action="store_true", help="XSS taramasını atla")
    parser.add_argument("--skip-rce", action="store_true", help="RCE taramasını atla")
    parser.add_argument("--skip-lfi", action="store_true", help="LFI/RFI taramasını atla")
    parser.add_argument("--skip-ssrf", action="store_true", help="SSRF taramasını atla")
    parser.add_argument("--skip-cve", action="store_true", help="CVE taramasını atla")
    parser.add_argument("--skip-dos", action="store_true", help="DoS testlerini atla")

    return parser


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print(f"{Colors.RED}[!] Geçerli bir URL girin: http:// veya https:// ile başlamalı{Colors.RESET}")
        sys.exit(1)

    SCAN_CONFIG["concurrent_requests"] = args.threads
    SCAN_CONFIG["timeout"] = args.timeout
    SCAN_CONFIG["stealth_mode"] = False if args.no_stealth else args.stealth

    print(f"{Colors.CYAN}[*] Hedef: {args.url}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Threads: {args.threads} | Timeout: {args.timeout}s | Stealth: {SCAN_CONFIG['stealth_mode']}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Başlangıç: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")

    scanner = KaxieScanner(args.url, args)

    try:
        findings = scanner.run()
        print(f"\n{Colors.GREEN}[+] Tarama tamamlandı. Toplam bulgu: {len(findings)}{Colors.RESET}")
        sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Kullanıcı tarafından durduruldu.{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Kritik hata: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
