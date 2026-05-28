"""
report_generator.py
-------------------
AnalysisResult -> incident_report.txt (insan okunaklı SOC raporu).

Format ilhamı: NIST SP 800-61 (Computer Security Incident Handling).
Bölümler:
  1. Executive Summary
  2. Detayli Findings (IP başına)
  3. Recommendations
"""

import os
from datetime import datetime

from analyzer.detector import AnalysisResult
from utils.constants import (
    APP_NAME,
    APP_VERSION,
    REPORTS_DIR,
    DEFAULT_REPORT_FILENAME,
)
from utils.helpers import ensure_dir, format_count


class ReportGenerator:
    """
    Tek sorumluluğu rapor üretmek. AnalysisResult -> string + dosya.
    """

    def __init__(self, output_dir: str = REPORTS_DIR) -> None:
        self.output_dir = output_dir

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(
        self,
        result: AnalysisResult,
        source_file: str = "N/A",
        filename: str = DEFAULT_REPORT_FILENAME,
    ) -> str:
        """
        Raporu üretir, diske yazar ve TAM yolu döndürür.
        """
        ensure_dir(self.output_dir)
        report_text = self._build_text(result, source_file)
        full_path = os.path.join(self.output_dir, filename)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        return full_path

    # ------------------------------------------------------------------
    # Rapor metnini ÜRETEN (saf fonksiyon - kolay test edilir)
    # ------------------------------------------------------------------
    def _build_text(self, result: AnalysisResult, source_file: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: list[str] = []

        # ====== HEADER ======
        lines.append("=" * 72)
        lines.append(f"  {APP_NAME} — SSH BRUTE-FORCE INCIDENT REPORT")
        lines.append(f"  Generated : {ts}")
        lines.append(f"  Source    : {source_file}")
        lines.append(f"  Tool      : {APP_NAME} v{APP_VERSION}")
        lines.append("=" * 72)
        lines.append("")

        # ====== 1) EXECUTIVE SUMMARY ======
        lines.append("[1] EXECUTIVE SUMMARY")
        lines.append("-" * 72)
        lines.append(f"  Total log events parsed      : {format_count(result.total_events)}")
        lines.append(f"  Failed authentication events : {format_count(result.total_failed)}")
        lines.append(f"  Successful authentications   : {format_count(result.total_success)}")
        lines.append(f"  Unique attacker IPs          : {format_count(len(result.attackers))}")
        lines.append(f"  Suspicious IPs (MED/HIGH)    : {format_count(result.suspicious_count)}")

        if result.top_attacker:
            ta = result.top_attacker
            lines.append(
                f"  Top attacker IP              : {ta.ip} "
                f"({format_count(ta.failed_attempts)} failed attempts, "
                f"risk={ta.risk_level})"
            )
        lines.append("")

        # ====== 2) TOP TARGETED USERNAMES ======
        lines.append("[2] MOST TARGETED USERNAMES")
        lines.append("-" * 72)
        if result.top_usernames:
            for user, count in result.top_usernames:
                lines.append(f"  - {user:<20} {format_count(count)} attempt(s)")
        else:
            lines.append("  No failed login data.")
        lines.append("")

        # ====== 3) DETAYLI BULGULAR (IP başına) ======
        lines.append("[3] DETAILED FINDINGS PER ATTACKER IP")
        lines.append("-" * 72)
        if not result.attackers:
            lines.append("  No attacker activity detected.")
        else:
            for idx, a in enumerate(result.attackers, start=1):
                lines.append(f"  #{idx}  IP: {a.ip}")
                lines.append(f"      Risk Level        : {a.risk_level}")
                lines.append(f"      Failed Attempts   : {format_count(a.failed_attempts)}")
                lines.append(f"      Successful Logins : {format_count(a.successful_logins)}")
                if a.is_breached:
                    lines.append("      ⚠  POSSIBLE BREACH: successful login after failures!")
                lines.append(
                    f"      Usernames Tried   : "
                    f"{', '.join(sorted(a.usernames_tried))[:200]}"
                )
                lines.append(f"      First Seen        : {a.first_seen or 'N/A'}")
                lines.append(f"      Last Seen         : {a.last_seen or 'N/A'}")
                lines.append("")

        # ====== 4) ÖNERİLER ======
        lines.append("[4] RECOMMENDATIONS")
        lines.append("-" * 72)
        lines.append("  - Block HIGH-risk IPs at firewall (iptables / ufw / cloud SG).")
        lines.append("  - Enforce SSH key-based authentication; disable password auth.")
        lines.append("  - Deploy Fail2Ban or CrowdSec for automated mitigation.")
        lines.append("  - Move SSH off port 22 (security through obscurity layer).")
        lines.append("  - Enable 2FA via Google Authenticator PAM module.")
        lines.append("  - Forward auth.log to a central SIEM (Wazuh / ELK / Splunk).")
        lines.append("")
        lines.append("=" * 72)
        lines.append("  END OF REPORT")
        lines.append("=" * 72)

        return "\n".join(lines)
