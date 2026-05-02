"""
KAXIE Scanner - AI Motor Entegrasyonu
Medusa AI API üzerinden model seçimi ve akıllı analiz
"""

import requests
import json
import time
from datetime import datetime
from config import API_BASE_URL, SCAN_CONFIG, USER_AGENTS, Colors


class AIEngine:
    """AI model seçimi ve zafiyet analizi için motor sınıfı."""

    def __init__(self):
        self.base_url = API_BASE_URL
        self.selected_model = None
        self.models = []
        self.conversation_history = []
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENTS[0],
        }

    def fetch_models(self):
        """API'den kullanılabilir modelleri çeker."""
        try:
            print(f"{Colors.CYAN}[*] Modeller çekiliyor: {self.base_url}/models{Colors.RESET}")
            resp = requests.get(
                f"{self.base_url}/models",
                headers=self.headers,
                timeout=SCAN_CONFIG["timeout"],
                verify=SCAN_CONFIG["verify_ssl"],
            )
            resp.raise_for_status()
            data = resp.json()

            self.models = []
            if isinstance(data, dict) and "data" in data:
                for m in data["data"]:
                    model_id = m.get("id", "unknown")
                    self.models.append({
                        "id": model_id,
                        "object": m.get("object", "model"),
                        "owned_by": m.get("owned_by", "unknown"),
                    })
            elif isinstance(data, list):
                for m in data:
                    if isinstance(m, dict):
                        model_id = m.get("id", m.get("name", "unknown"))
                        self.models.append({
                            "id": model_id,
                            "object": m.get("object", "model"),
                            "owned_by": m.get("owned_by", "unknown"),
                        })
                    elif isinstance(m, str):
                        self.models.append({"id": m, "object": "model", "owned_by": "unknown"})

            return self.models

        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[!] API sunucusuna bağlanılamadı: {self.base_url}{Colors.RESET}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[!] Model çekme hatası: {e}{Colors.RESET}")
            return []

    def display_models(self):
        """Kullanılabilir modelleri listeler."""
        if not self.models:
            print(f"{Colors.YELLOW}[!] Kullanılabilir model bulunamadı.{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}║              KULLANILABİLİR AI MODELLER                     ║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}╠══════════════════════════════════════════════════════════════╣{Colors.RESET}")

        for idx, model in enumerate(self.models, 1):
            mid = model.get("id", "unknown")
            owner = model.get("owned_by", "unknown")
            print(f"{Colors.BOLD}{Colors.MAGENTA}║{Colors.RESET} {Colors.GREEN}[{idx}]{Colors.RESET} {Colors.WHITE}{mid:<45} {Colors.DIM}({owner}){Colors.RESET}")

        print(f"{Colors.BOLD}{Colors.MAGENTA}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")

    def select_model(self, choice):
        """Kullanıcının seçtiği modeli ayarlar."""
        if 1 <= choice <= len(self.models):
            self.selected_model = self.models[choice - 1]["id"]
            print(f"{Colors.GREEN}[+] Seçilen model: {self.selected_model}{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[!] Geçersiz seçim.{Colors.RESET}")
            return False

    def interactive_select(self):
        """Etkileşimli model seçimi."""
        self.fetch_models()
        if not self.models:
            print(f"{Colors.YELLOW}[!] Model bulunamadı, AI desteği olmadan devam edilecek.{Colors.RESET}")
            return False

        self.display_models()

        try:
            choice = int(input(f"\n{Colors.CYAN}Model seçin (numara): {Colors.RESET}"))
            return self.select_model(choice)
        except ValueError:
            print(f"{Colors.RED}[!] Geçersiz giriş.{Colors.RESET}")
            return False

    def chat_completion(self, system_prompt, user_message, max_tokens=2048, temperature=0.7):
        """AI modeline istek gönderir ve yanıt alır."""
        if not self.selected_model:
            return None

        messages = [
            {"role": "system", "content": system_prompt},
        ]

        self.conversation_history.append({"role": "user", "content": user_message})
        messages.extend(self.conversation_history[-10:])

        payload = {
            "model": self.selected_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=60,
                verify=SCAN_CONFIG["verify_ssl"],
            )
            resp.raise_for_status()
            data = resp.json()

            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0].get("message", {}).get("content", "")
                self.conversation_history.append({"role": "assistant", "content": content})
                return content

            return None

        except requests.exceptions.Timeout:
            print(f"{Colors.YELLOW}[!] AI zaman aşımı - analiz atlanıyor{Colors.RESET}")
            return None
        except Exception as e:
            print(f"{Colors.YELLOW}[!] AI hatası: {e}{Colors.RESET}")
            return None

    def analyze_vulnerability(self, vuln_type, target, evidence, response_snippet=""):
        """Tespit edilen zafiyeti AI ile derin analiz eder."""
        system_prompt = (
            "Sen profesyonel bir siber güvenlik uzmanısın. Zafiyet analizi, exploit geliştirme "
            "ve remediation konularında uzmansın. Verilen zafiyet bilgisini derinlemesine analiz et, "
            "risk seviyesini belirle, sömürü senaryolarını açıkla ve düzeltme önerileri sun. "
            "Yanıtlarını Türkçe ver. Teknik ve detaylı ol."
        )

        user_msg = (
            f"HEDEF: {target}\n"
            f"ZAFİYET TİPİ: {vuln_type}\n"
            f"KANIT: {evidence}\n"
        )

        if response_snippet:
            user_msg += f"YANIT PARÇASI: {response_snippet[:500]}\n"

        user_msg += (
            "\nLütfen şu yapıda analiz yap:\n"
            "1. ZAFİYET AÇIKLAMASI\n"
            "2. RİSK SEVİYESİ (Kritik/Yüksek/Orta/Düşük)\n"
            "3. SÖMÜRÜ SENARYOSU\n"
            "4. POC (Proof of Concept)\n"
            "5. DÜZELTME ÖNERİLERİ\n"
            "6. CVE REFERANSLARI"
        )

        return self.chat_completion(system_prompt, user_msg, max_tokens=2048)

    def suggest_scan_strategy(self, target, recon_data):
        """Hedef için tarama stratejisi önerisi alır."""
        system_prompt = (
            "Sen deneyimli bir penetrasyon test uzmanısın. Verilen hedef ve keşif verilerine "
            "göre en etkili tarama stratejisini öner. Hangi zafiyet sınıflarına öncelik verilmesi "
            "gerektiğini, olası saldırı vektörlerini ve özel payload önerilerini belirt. "
            "Yanıtlarını Türkçe ver."
        )

        user_msg = (
            f"HEDEF: {target}\n"
            f"KEŞİF VERİLERİ: {json.dumps(recon_data, indent=2, ensure_ascii=False)[:2000]}\n"
            "\nBu hedef için:\n"
            "1. Öncelikli zafiyet sınıfları\n"
            "2. Olası saldırı vektörleri\n"
            "3. Özel payload önerileri\n"
            "4. WAF atlatma stratejileri\n"
            "5. Gizlilik önerileri"
        )

        return self.chat_completion(system_prompt, user_msg, max_tokens=2048)

    def generate_payloads(self, vuln_type, context=""):
        """AI ile zafiyet tipine özel payload üretir."""
        system_prompt = (
            "Sen exploit geliştirme uzmanısın. Verilen zafiyet tipi için gelişmiş, "
            "WAF-atlatma özellikli payload'lar üret. Her payload için açıklama ekle. "
            "Yanıtlarını Türkçe ver, payload'ları orijinal haliyle ver."
        )

        user_msg = (
            f"ZAFİYET TİPİ: {vuln_type}\n"
        )

        if context:
            user_msg += f"BAĞLAM: {context}\n"

        user_msg += "\nBu zafiyet tipi için 10 adet gelişmiş payload üret."

        return self.chat_completion(system_prompt, user_msg, max_tokens=2048)

    def analyze_cve(self, cve_id, target_info=""):
        """CVE hakkında AI analizi alır."""
        system_prompt = (
            "Sen CVE analizi uzmanısın. Verilen CVE numarasını derinlemesine analiz et, "
            "sömürü yöntemlerini ve etkisini açıkla. Yanıtlarını Türkçe ver."
        )

        user_msg = (
            f"CVE ID: {cve_id}\n"
            f"HEDEF BİLGİSİ: {target_info}\n"
            "\nAnaliz yap:\n"
            "1. Zafiyet açıklaması\n"
            "2. Etkilenen sistemler\n"
            "3. Sömürü zorluğu\n"
            "4. POC\n"
            "5. Etki analizi\n"
            "6. Yama durumu"
        )

        return self.chat_completion(system_prompt, user_msg, max_tokens=2048)
