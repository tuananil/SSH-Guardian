"""
detector.py
-----------
Parse edilmiş log olaylarından SUÇLU/ŞÜPHELİ IP'leri tespit eder.
Ayrıca saatlik attack timeline ve GeoIP enrichment desteği sağlar.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

from analyzer.parser import LogEvent
from analyzer.geoip import GeoIPLookup
from utils.helpers import classify_risk


# ----------------------------------------------------------------------
# Tek bir saldırgan IP profili
# ----------------------------------------------------------------------
@dataclass
class AttackerProfile:
    ip: str
    failed_attempts: int = 0
    successful_logins: int = 0
    usernames_tried: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ports: set[int] = field(default_factory=set)
    country: str = "N/A"        # GeoIP enrichment alanı

    @property
    def risk_level(self) -> str:
        return classify_risk(self.failed_attempts)

    @property
    def is_breached(self) -> bool:
        """Aynı IP hem fail hem accept yaptıysa = olası başarılı brute force."""
        return self.failed_attempts > 0 and self.successful_logins > 0


# ----------------------------------------------------------------------
# Tüm rapor için özet veri
# ----------------------------------------------------------------------
@dataclass
class AnalysisResult:
    attackers: list[AttackerProfile]
    total_events: int
    total_failed: int
    total_success: int
    top_usernames: list[tuple[str, int]]
    # Saatlik bucket: (datetime_hour, failed_count). Grafik çizmek için.
    hourly_failures: list[tuple[datetime, int]] = field(default_factory=list)
    # Ülke -> başarısız deneme sayısı (geo dashboard için)
    country_counts: list[tuple[str, int]] = field(default_factory=list)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for a in self.attackers if a.risk_level != "LOW")

    @property
    def top_attacker(self) -> AttackerProfile | None:
        return self.attackers[0] if self.attackers else None


# ----------------------------------------------------------------------
# Detector
# ----------------------------------------------------------------------
class BruteForceDetector:
    """LogEvent stream'inden AnalysisResult üretir."""

    def __init__(
        self,
        brute_force_threshold: int = 5,
        geoip: Optional[GeoIPLookup] = None,
    ) -> None:
        self.threshold = brute_force_threshold
        self.geoip = geoip   # opsiyonel GeoIPLookup nesnesi

    def analyze(self, events: Iterable[LogEvent]) -> AnalysisResult:
        profiles: dict[str, AttackerProfile] = {}
        username_counter: Counter[str] = Counter()
        hourly_counter: Counter[datetime] = Counter()
        total_events = 0
        total_failed = 0
        total_success = 0

        for ev in events:
            total_events += 1
            profile = profiles.get(ev.ip)
            if profile is None:
                profile = AttackerProfile(ip=ev.ip)
                profiles[ev.ip] = profile

            if ev.success:
                profile.successful_logins += 1
                total_success += 1
            else:
                profile.failed_attempts += 1
                total_failed += 1
                username_counter[ev.username] += 1
                # Saatlik bucket: timestamp'i saat başına yuvarla
                if ev.timestamp is not None:
                    bucket = ev.timestamp.replace(minute=0, second=0, microsecond=0)
                    hourly_counter[bucket] += 1

            profile.usernames_tried.add(ev.username)
            profile.ports.add(ev.port)

            if ev.timestamp is not None:
                if profile.first_seen is None or ev.timestamp < profile.first_seen:
                    profile.first_seen = ev.timestamp
                if profile.last_seen is None or ev.timestamp > profile.last_seen:
                    profile.last_seen = ev.timestamp

        # GeoIP enrichment (opsiyonel)
        if self.geoip and self.geoip.is_enabled:
            for p in profiles.values():
                p.country = self.geoip.country(p.ip)

        attackers_sorted = sorted(
            profiles.values(),
            key=lambda p: p.failed_attempts,
            reverse=True,
        )

        # Hourly list (zaman sıralı)
        hourly_sorted = sorted(hourly_counter.items(), key=lambda t: t[0])

        # Country aggregation
        country_counter: Counter[str] = Counter()
        for p in profiles.values():
            if p.country and p.country != "N/A":
                country_counter[p.country] += p.failed_attempts
        country_sorted = country_counter.most_common(10)

        return AnalysisResult(
            attackers=attackers_sorted,
            total_events=total_events,
            total_failed=total_failed,
            total_success=total_success,
            top_usernames=username_counter.most_common(10),
            hourly_failures=hourly_sorted,
            country_counts=country_sorted,
        )

    def filter_brute_force(self, result: AnalysisResult) -> list[AttackerProfile]:
        return [a for a in result.attackers if a.failed_attempts >= self.threshold]
