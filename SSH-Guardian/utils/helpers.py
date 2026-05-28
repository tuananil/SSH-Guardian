"""
helpers.py
----------
Küçük yardımcı (utility) fonksiyonlar.

İlke: Bir fonksiyon = bir iş (Single Responsibility Principle).
Bu fonksiyonlar saf (pure) ve test edilebilir olmalı.
"""

import re
import os
from datetime import datetime
from utils.constants import (
    LOW_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
)


def classify_risk(attempt_count: int) -> str:
    """
    Başarısız deneme sayısına bakarak risk seviyesi döndürür.

    Bu, SOC analistlerinin yaptığı 'triage' (önceliklendirme) işlemidir.
    Yüksek skor = öncelikli olarak bakılması gereken IP.

    Args:
        attempt_count: Aynı IP'den yapılan başarısız login sayısı.

    Returns:
        "LOW", "MEDIUM" veya "HIGH".
    """
    if attempt_count <= LOW_RISK_THRESHOLD:
        return RISK_LOW
    if attempt_count <= MEDIUM_RISK_THRESHOLD:
        return RISK_MEDIUM
    return RISK_HIGH


def is_valid_ipv4(ip: str) -> bool:
    """
    Verilen string geçerli bir IPv4 adresi mi?
    Regex zaten yakaladı ama defansif programlama için tekrar doğrularız.
    (Güvenlik: 'never trust input')
    """
    pattern = r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)" \
              r"(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
    return re.match(pattern, ip) is not None


def parse_log_timestamp(month: str, day: str, time_str: str,
                       year: int | None = None) -> datetime | None:
    """
    auth.log zaman damgasını (örn. 'Nov 12 06:39:18') datetime nesnesine çevirir.

    NOT: auth.log dosyası YIL bilgisini İÇERMEZ (Linux geleneği).
    Bu yüzden ya parametre olarak alırız ya da mevcut yılı varsayarız.
    """
    if year is None:
        year = datetime.now().year
    try:
        return datetime.strptime(
            f"{year} {month} {day} {time_str}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        # Bozuk satır geldiyse uygulamayı çökertmeyiz, sadece None döneriz.
        return None


def ensure_dir(path: str) -> None:
    """
    Klasör yoksa oluşturur. Rapor yazmadan önce çağrılır.
    """
    os.makedirs(path, exist_ok=True)


def format_count(n: int) -> str:
    """
    Sayıyı binlik ayırıcıyla biçimlendirir: 1234 -> '1,234'.
    GUI'de daha okunabilir görünür.
    """
    return f"{n:,}"
