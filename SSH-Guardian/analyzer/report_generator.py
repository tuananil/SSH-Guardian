"""
report_generator.py
-------------------
AnalysisResult -> incident_report.txt (insan okunaklı SOC raporu).

Format ilhamı: NIST SP 800-61 (Computer Security Incident Handling).
"""

import os
from datetime import datetime

from analyzer.detector import AnalysisResult
from utils.constants import (
    APP_NAME, APP_VERSION,
    REPORTS_DIR, DEFAULT_REPORT_FILENAME,
)
from utils.helpers import ensure_dir, format_count


class ReportGenerator:
    """AnalysisResult'tan incident_report.txt üretir."""

    def __init__(self, output_dir: str = REPORTS_DIR) -> None:
        self.output_dir = output_dir

    # ------------------------------------------------------------------
    def generate(
        self,
        result: AnalysisResult,
        source_file: str = "N/A",
        filename: str = DEFAULT_REPORT_FILENAME,
    ) -> str:
        ensure_dir(self.output_dir)
        text = self._build_text(result, source_file)
        full_path = os.path.join(self.output_dir, filename)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(text)
        return full_path

    # ------------------------------------------------------------------
    def _build_text(self, result: AnalysisResult, source_file: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: list[str] = []

        # ----- HEADER -----
        lines.append("=" * 72)
        lines.append(f"  {APP_NAME} — SSH BRUTE-FORCE INCIDENT REPORT")
        lines.append(f"  Generated : {ts}")
        lines.append(f"  Source    : {source_file}")
        lines.append(f"  Tool      : {APP_NAME} v{APP_VERSION}")
        lines.append("=" * 72)
        lines.append("")

        # ----- 1) EXECUTIVE SUMMARY -----
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
                f"({format_count(ta.failed_attempts)} failed, "
                f"risk={ta.risk_level}, country={ta.country})"
            )

        # Saatlik pik
        if result.hourly_failures:
            peak_hour, peak_count = max(result.hourly_failures, key=lambda t: t[1])
            lines.append(
                f"  Peak attack hour             : {peak_hour} "
                f"({format_count(peak_count)} failed attempts)"
            )
        lines.append("")

        # ----- 2) TOP USERNAMES -----
        lines.append("[2] MOST TARGETED USERNAMES")
        lines.append("-" * 72)
        if result.top_usernames:
            for user, count in result.top_usernames:
                lines.append(f"  - {user:<20} {format_count(count)} attempt(s)")
        else:
            lines.append("  No failed login data.")
        lines.append("")

        # ----- 3) COUNTRY BREAKDOWN -----
        if result.country_counts:
            lines.append("[3] GEOGRAPHIC DISTRIBUTION (top 10)")
            lines.append("-" * 72)
            for country, count in result.country_counts:
                lines.append(f"  - {country:<25} {format_count(count)} failed attempts")
            lines.append("")

        # ----- 4) DETAILED FINDINGS -----
        lines.append("[4] DETAILED FINDINGS PER ATTACKER IP")
        lines.append("-" * 72)
        if not result.attackers:
            lines.append("  No attacker activity detected.")
        else:
            for idx, a in enumerate(result.attackers, start=1):
                lines.append(f"  #{idx}  IP: {a.ip}  [{a.country}]")
                lines.append(f"      Risk Level        : {a.risk_level}")
                lines.append(f"      Failed Attempts   : {format_count(a.failed_attempts)}")
                lines.append(f"      Successful Logins : {format_count(a.successful_logins)}")
                if a.is_breached:
                    lines.append("      !! POSSIBLE BREACH: successful login after failures !!")
                lines.append(
                    f"      Usernames Tried   : "
                    f"{', '.join(sorted(a.usernames_tried))[:200]}"
                )
                lines.append(f"      First Seen        : {a.first_seen or 'N/A'}")
                lines.append(f"      Last Seen         : {a.last_seen or 'N/A'}")
                lines.append("")

        # ----- 5) RECOMMENDATIONS -----
        lines.append("[5] RECOMMENDATIONS")
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
