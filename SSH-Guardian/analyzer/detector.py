"""
detector.py
-----------
Parse edilmiş log olaylarından SUÇLU/ŞÜPHELİ IP'leri tespit eder.

Cybersecurity kavramları:
- Brute Force: kısa sürede çok sayıda hatalı şifre denemesi.
- IoC (Indicator of Compromise): saldırgan IP, saldırgan kullanıcı adı.
- 'Slow brute force': eşik altında kalmak için yavaş deneme (gelecek geliştirme).
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from analyzer.parser import LogEvent
from utils.helpers import classify_risk


# ----------------------------------------------------------------------
# VERİ MODELİ: Tek bir saldırgan IP hakkındaki tüm bilgi
# ----------------------------------------------------------------------
@dataclass
class AttackerProfile:
    ip: str
    failed_attempts: int = 0
    successful_logins: int = 0          # 'breach' (sızma) göstergesi olabilir!
    usernames_tried: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ports: set[int] = field(default_factory=set)

    @property
    def risk_level(self) -> str:
        """failed_attempts'a göre LOW/MEDIUM/HIGH döner."""
        return classify_risk(self.failed_attempts)

    @property
    def is_breached(self) -> bool:
        """
        Aynı IP hem fail hem accept yaptıysa: brute-force BAŞARILI olmuş olabilir!
        SOC için kritik alarm.
        """
        return self.failed_attempts > 0 and self.successful_logins > 0


# ----------------------------------------------------------------------
# ANALİZ SONUCU: Tüm rapor için özet veri
# ----------------------------------------------------------------------
@dataclass
class AnalysisResult:
    attackers: list[AttackerProfile]   # IP başına profil
    total_events: int
    total_failed: int
    total_success: int
    top_usernames: list[tuple[str, int]]  # ('root', 543) gibi

    @property
    def suspicious_count(self) -> int:
        """MEDIUM veya HIGH risk taşıyan IP sayısı."""
        return sum(1 for a in self.attackers if a.risk_level != "LOW")

    @property
    def top_attacker(self) -> AttackerProfile | None:
        """En çok başarısız deneme yapan IP."""
        return self.attackers[0] if self.attackers else None


# ----------------------------------------------------------------------
# DETECTOR SINIFI
# ----------------------------------------------------------------------
class BruteForceDetector:
    """
    LogEvent stream'ini alır, IP başına profil çıkarır.

    Tasarım: tek bir 'analyze()' metodu var. Test yazmak için ideal.
    """

    def __init__(self, brute_force_threshold: int = 5) -> None:
        """
        Args:
            brute_force_threshold: Bu sayıdan fazla başarısız deneme = brute force.
            (constants.py'deki risk eşiklerinden bağımsız, kullanıcı override edebilir)
        """
        self.threshold = brute_force_threshold

    def analyze(self, events: Iterable[LogEvent]) -> AnalysisResult:
        """
        Tüm event stream'ini tek geçişte (single-pass) analiz eder. O(n).
        """
        # IP -> AttackerProfile sözlüğü
        profiles: dict[str, AttackerProfile] = {}
        username_counter: Counter[str] = Counter()

        total_events = 0
        total_failed = 0
        total_success = 0

        for ev in events:
            total_events += 1

            # IP profili yoksa oluştur
            profile = profiles.get(ev.ip)
            if profile is None:
                profile = AttackerProfile(ip=ev.ip)
                profiles[ev.ip] = profile

            # Sayaçları güncelle
            if ev.success:
                profile.successful_logins += 1
                total_success += 1
            else:
                profile.failed_attempts += 1
                total_failed += 1
                # Yalnızca başarısız denemelerdeki kullanıcı adlarını sayarız
                username_counter[ev.username] += 1

            # Username/port toplama
            profile.usernames_tried.add(ev.username)
            profile.ports.add(ev.port)

            # Zaman penceresi (first/last seen)
            if ev.timestamp is not None:
                if profile.first_seen is None or ev.timestamp < profile.first_seen:
                    profile.first_seen = ev.timestamp
                if profile.last_seen is None or ev.timestamp > profile.last_seen:
                    profile.last_seen = ev.timestamp

        # En çok deneme yapana göre azalan sırala (en tehlikeli ilkte)
        attackers_sorted = sorted(
            profiles.values(),
            key=lambda p: p.failed_attempts,
            reverse=True,
        )

        return AnalysisResult(
            attackers=attackers_sorted,
            total_events=total_events,
            total_failed=total_failed,
            total_success=total_success,
            top_usernames=username_counter.most_common(10),
        )

    # ------------------------------------------------------------------
    # Yardımcı: yalnızca brute-force eşiğini geçenleri döndür
    # ------------------------------------------------------------------
    def filter_brute_force(
        self, result: AnalysisResult
    ) -> list[AttackerProfile]:
        """Sadece self.threshold'tan fazla deneme yapan IP'leri filtreler."""
        return [a for a in result.attackers if a.failed_attempts >= self.threshold]
