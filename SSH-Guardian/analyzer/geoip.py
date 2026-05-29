"""
geoip.py
--------
IP -> ülke/şehir çözümleyici (MaxMind GeoLite2, lokal mmdb dosyası).

Kütüphane: 'maxminddb' (saf-Python okuyucu, internet gerektirmez).
DB dosyası: MaxMind hesabıyla ücretsiz indirilir, `assets/GeoLite2-Country.mmdb`.

Tasarım: GeoIP OPSİYONELDİR. mmdb yoksa veya kütüphane kurulu değilse,
GeoIPLookup sessizce devre dışı kalır ("N/A" döner). Bu sayede uygulama
yine de çalışır — sadece coğrafi bilgi gösterilmez.
"""

import os
from typing import Optional

from utils.constants import GEOIP_DB_PATH

# 'maxminddb' kurulu olmayabilir; import'u try/except içine alıyoruz.
try:
    import maxminddb  # type: ignore
    _MAXMIND_AVAILABLE = True
except Exception:
    _MAXMIND_AVAILABLE = False


class GeoIPLookup:
    """
    Tek bir GeoLite2 mmdb dosyasını açar, IP -> ülke kodu/adı çevirir.

    Kullanım:
        geo = GeoIPLookup()
        if geo.is_enabled:
            country = geo.country("8.8.8.8")   # "United States"
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or GEOIP_DB_PATH
        self._reader = None
        self._enabled = False
        self._open()

    # ------------------------------------------------------------------
    def _open(self) -> None:
        """mmdb dosyasını açmaya çalışır. Olmazsa devre dışı kalır."""
        if not _MAXMIND_AVAILABLE:
            return
        if not os.path.isfile(self.db_path):
            return
        try:
            self._reader = maxminddb.open_database(self.db_path)
            self._enabled = True
        except Exception:
            self._reader = None
            self._enabled = False

    # ------------------------------------------------------------------
    @property
    def is_enabled(self) -> bool:
        """GeoIP kullanılabilir mi?"""
        return self._enabled

    # ------------------------------------------------------------------
    def country(self, ip: str) -> str:
        """
        Verilen IP için 'United States' gibi ülke adı döner.
        Bulunamaz / GeoIP kapalıysa 'N/A' döner.
        """
        if not self._enabled or not self._reader:
            return "N/A"
        try:
            data = self._reader.get(ip)
            if not data:
                return "Unknown"
            # GeoLite2-Country yapısı: {'country': {'names': {'en': 'United States'}}}
            country = data.get("country") or data.get("registered_country") or {}
            names = country.get("names") or {}
            return names.get("en", "Unknown")
        except Exception:
            return "Unknown"

    # ------------------------------------------------------------------
    def country_code(self, ip: str) -> str:
        """ISO-2 kod ('US', 'CN', 'TR'). Bulunamazsa '--' döner."""
        if not self._enabled or not self._reader:
            return "--"
        try:
            data = self._reader.get(ip)
            if not data:
                return "--"
            country = data.get("country") or data.get("registered_country") or {}
            return country.get("iso_code", "--")
        except Exception:
            return "--"

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
            self._enabled = False
