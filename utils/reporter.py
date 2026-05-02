"""
KAXIE Scanner - Raporlama Modülü
"""

import json
import os
from datetime import datetime
from config import Colors


class ReportManager:
    """Tarama sonuçlarını yöneten ve raporlayan sınıf."""

    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        self.findings = []
        self.recon_data = {}
        self.ai_analyses = []
        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "total_requests": 0,
            "vulns_found": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

    def add_finding(self, vuln_type, severity, title, description, evidence, url, ai_analysis=None):
        """Yeni zafiyet bulgusu ekler."""
        finding = {
            "vuln_type": vuln_type,
            "severity": severity.upper(),
            "title": title,
            "description": description,
            "evidence": evidence,
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "ai_analysis": ai_analysis,
        }

        self.findings.append(finding)
        self.scan_stats["vulns_found"] += 1

        sev = severity.upper()
        if sev in self.scan_stats:
            self.scan_stats[sev] += 1

        # Konsol çıktısı
        color_map = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.BLUE,
            "INFO": Colors.DIM,
        }
        c = color_map.get(sev, Colors.WHITE)
        print(f"  {c}[{sev}]{Colors.RESET} {title} -> {url}")
        if evidence:
            print(f"         {Colors.DIM}Kanıt: {evidence[:100]}{Colors.RESET}")

    def add_ai_analysis(self, vuln_type, analysis):
        """AI analiz sonucunu kaydeder."""
        self.ai_analyses.append({
            "vuln_type": vuln_type,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat(),
        })

    def print_summary(self):
        """Tarama özetini yazdırır."""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  KAXIE SCANNER - TARAMA RAPORU{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"  Hedef: {Colors.WHITE}{self.target}{Colors.RESET}")
        print(f"  Zafiyet Sayısı: {Colors.RED}{self.scan_stats['vulns_found']}{Colors.RESET}")
        print(f"    {Colors.RED}Kritik: {self.scan_stats['CRITICAL']}{Colors.RESET}")
        print(f"    {Colors.RED}Yüksek: {self.scan_stats['HIGH']}{Colors.RESET}")
        print(f"    {Colors.YELLOW}Orta:   {self.scan_stats['MEDIUM']}{Colors.RESET}")
        print(f"    {Colors.BLUE}Düşük:  {self.scan_stats['LOW']}{Colors.RESET}")
        print(f"    {Colors.DIM}Bilgi:  {self.scan_stats['INFO']}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")

        if self.findings:
            print(f"\n{Colors.BOLD}  BULGULAR:{Colors.RESET}")
            for i, f in enumerate(self.findings, 1):
                color_map = {
                    "CRITICAL": Colors.RED + Colors.BOLD,
                    "HIGH": Colors.RED,
                    "MEDIUM": Colors.YELLOW,
                    "LOW": Colors.BLUE,
                    "INFO": Colors.DIM,
                }
                c = color_map.get(f["severity"], Colors.WHITE)
                print(f"\n  {c}[{i}] [{f['severity']}] {f['title']}{Colors.RESET}")
                print(f"      Tip: {f['vuln_type']}")
                print(f"      URL: {f['url']}")
                print(f"      Açıklama: {f['description'][:150]}")
                if f.get("evidence"):
                    print(f"      Kanıt: {f['evidence'][:150]}")
                if f.get("ai_analysis"):
                    print(f"      {Colors.CYAN}AI Analizi: {f['ai_analysis'][:200]}...{Colors.RESET}")

        if self.ai_analyses:
            print(f"\n{Colors.BOLD}{Colors.CYAN}  AI ANALİZ SONUÇLARI:{Colors.RESET}")
            for a in self.ai_analyses:
                print(f"\n  [{a['vuln_type']}]")
                print(f"  {a['analysis'][:500]}")

    def save_json_report(self):
        """JSON formatında rapor kaydeder."""
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        filename = f"{report_dir}/kaxie_report_{self.safe_target}_{self.timestamp}.json"

        report = {
            "target": self.target,
            "timestamp": self.timestamp,
            "scan_stats": self.scan_stats,
            "recon_data": self.recon_data,
            "findings": self.findings,
            "ai_analyses": self.ai_analyses,
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"{Colors.GREEN}[+] JSON raporu kaydedildi: {filename}{Colors.RESET}")
        return filename

    def save_html_report(self):
        """HTML formatında rapor kaydeder."""
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        filename = f"{report_dir}/kaxie_report_{self.safe_target}_{self.timestamp}.html"

        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#e74c3c",
            "MEDIUM": "#f39c12",
            "LOW": "#3498db",
            "INFO": "#95a5a6",
        }

        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            color = severity_colors.get(f["severity"], "#333")
            ai_section = ""
            if f.get("ai_analysis"):
                ai_section = f'<div class="ai-analysis"><h4>AI Analizi</h4><pre>{f["ai_analysis"]}</pre></div>'

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <h3>[{i}] [{f['severity']}] {f['title']}</h3>
                <p><strong>Tip:</strong> {f['vuln_type']}</p>
                <p><strong>URL:</strong> {f['url']}</p>
                <p><strong>Açıklama:</strong> {f['description']}</p>
                <p><strong>Kanıt:</strong> <code>{f.get('evidence', 'N/A')}</code></p>
                {ai_section}
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>KAXIE Scanner Report - {self.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }}
        .stat {{ background: #1a1a2e; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat h3 {{ margin: 0; font-size: 2em; }}
        .stat p {{ margin: 5px 0 0; color: #888; }}
        .finding {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }}
        .finding h3 {{ margin: 0 0 10px; }}
        .finding code {{ background: #0f3460; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
        .ai-analysis {{ background: #1a1a2e; padding: 10px; margin-top: 10px; border-radius: 5px; border-left: 3px solid #9b59b6; }}
        .ai-analysis h4 {{ color: #9b59b6; margin: 0 0 5px; }}
        .ai-analysis pre {{ white-space: pre-wrap; font-size: 0.85em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>KAXIE Scanner - Güvenlik Raporu</h1>
        <p><strong>Hedef:</strong> {self.target}</p>
        <p><strong>Tarih:</strong> {self.timestamp}</p>
        <div class="stats">
            <div class="stat"><h3 style="color:#dc3545">{self.scan_stats['CRITICAL']}</h3><p>Kritik</p></div>
            <div class="stat"><h3 style="color:#e74c3c">{self.scan_stats['HIGH']}</h3><p>Yüksek</p></div>
            <div class="stat"><h3 style="color:#f39c12">{self.scan_stats['MEDIUM']}</h3><p>Orta</p></div>
            <div class="stat"><h3 style="color:#3498db">{self.scan_stats['LOW']}</h3><p>Düşük</p></div>
            <div class="stat"><h3 style="color:#95a5a6">{self.scan_stats['INFO']}</h3><p>Bilgi</p></div>
        </div>
        <h2>Bulgular</h2>
        {findings_html}
    </div>
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"{Colors.GREEN}[+] HTML raporu kaydedildi: {filename}{Colors.RESET}")
        return filename
