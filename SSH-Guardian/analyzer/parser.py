"""
parser.py
---------
Linux /var/log/auth.log satırlarını okur ve YAPILANDIRILMIŞ veriye çevirir.

Cybersecurity bağlamı:
- auth.log, SSH/sudo/PAM gibi kimlik doğrulama olaylarını tutar.
- SOC analistinin ilk durağıdır: 'kim, ne zaman, nereden, başarılı mı?'
- Bizim parser'ımız bu sorulara cevap çıkaran 'log normalization' adımıdır.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator

from utils.constants import FAILED_LOGIN_PATTERN, ACCEPTED_LOGIN_PATTERN
from utils.helpers import parse_log_timestamp


# ----------------------------------------------------------------------
# VERİ MODELİ (dataclass)
# ----------------------------------------------------------------------
# @dataclass: Boilerplate __init__ / __repr__ kodunu otomatik üretir.
# Bir 'log event' tek bir auth.log satırını temsil eder.
@dataclass
class LogEvent:
    timestamp: datetime | None
    username: str
    ip: str
    port: int
    success: bool          # True = Accepted, False = Failed
    raw_line: str = field(repr=False)  # debug için ham satır


# ----------------------------------------------------------------------
# PARSER SINIFI
# ----------------------------------------------------------------------
class LogParser:
    """
    SSH auth.log dosyasını okur, regex ile satır satır ayrıştırır.

    Tasarım kararları:
    - re.compile ile pattern'i 1 kez derler (performans).
    - Generator (yield) kullanır: BÜYÜK log dosyalarını belleğe sığdırmak
      için satır satır işler (lazy evaluation). 100MB log için kritik!
    """

    def __init__(self) -> None:
        # re.compile -> her satırda yeniden compile etmemek için.
        self._failed_re = re.compile(FAILED_LOGIN_PATTERN)
        self._accepted_re = re.compile(ACCEPTED_LOGIN_PATTERN)

        # İstatistik takibi (UI için faydalı)
        self.total_lines = 0
        self.matched_lines = 0

    # ------------------------------------------------------------------
    # Tek satırı işleyen yardımcı (private metod - alt çizgi prefix'i)
    # ------------------------------------------------------------------
    def _match_line(self, line: str) -> LogEvent | None:
        """
        Bir satırı önce 'Failed', sonra 'Accepted' regex'ine karşı kontrol eder.
        Eşleşme yoksa None döner (önemli olmayan satır).
        """
        # ----- Başarısız login -----
        m = self._failed_re.search(line)
        if m:
            return LogEvent(
                timestamp=parse_log_timestamp(
                    m.group("month"), m.group("day"), m.group("time")
                ),
                username=m.group("user"),
                ip=m.group("ip"),
                port=int(m.group("port")),
                success=False,
                raw_line=line.rstrip("\n"),
            )

        # ----- Başarılı login -----
        m = self._accepted_re.search(line)
        if m:
            return LogEvent(
                timestamp=parse_log_timestamp(
                    m.group("month"), m.group("day"), m.group("time")
                ),
                username=m.group("user"),
                ip=m.group("ip"),
                port=int(m.group("port")),
                success=True,
                raw_line=line.rstrip("\n"),
            )

        return None

    # ------------------------------------------------------------------
    # Public API: dosyadan stream şeklinde event döndürür (generator)
    # ------------------------------------------------------------------
    def parse_file(self, file_path: str) -> Iterator[LogEvent]:
        """
        Dosyayı satır satır okur ve LogEvent nesneleri üretir.

        Generator kullanımı:
            for event in parser.parse_file("auth.log"):
                process(event)
        """
        self.total_lines = 0
        self.matched_lines = 0

        # encoding='utf-8', errors='ignore' -> bozuk karakterler uygulamayı çökertmesin
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                self.total_lines += 1
                event = self._match_line(line)
                if event is not None:
                    self.matched_lines += 1
                    yield event

    # ------------------------------------------------------------------
    # Iterable bir kaynaktan (örn. real-time watcher) parse etmek için
    # ------------------------------------------------------------------
    def parse_iterable(self, lines: Iterable[str]) -> Iterator[LogEvent]:
        """
        Bellekteki satır listesinden veya bir stream'den olay üretir.
        Real-time monitoring (tail -f) için kullanışlı.
        """
        for line in lines:
            self.total_lines += 1
            event = self._match_line(line)
            if event is not None:
                self.matched_lines += 1
                yield event
