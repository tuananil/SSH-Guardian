"""
constants.py
------------
SSH Guardian uygulamasının tüm SABİT değerlerini barındırır.

Neden ayrı dosya?
- Magic number/string'leri kodun içine gömmek yerine tek yerde tutarız.
- Eşik değer (threshold) değiştirmek istersek sadece burayı düzenleriz.
- Bu, "Single Source of Truth" (Tek Doğruluk Kaynağı) prensibidir.
"""

# ----------------------------------------------------------------------
# BRUTE-FORCE EŞİK DEĞERLERİ (Risk Sınıflandırması)
# ----------------------------------------------------------------------
# Bir IP'den gelen başarısız login sayısına göre risk seviyesi belirleriz.
# SOC analistleri genellikle 5+ denemeyi "şüpheli" sayar.
LOW_RISK_THRESHOLD = 3      # 1-3  başarısız deneme  -> LOW
MEDIUM_RISK_THRESHOLD = 10  # 4-10 başarısız deneme  -> MEDIUM
# 10+ deneme                                          -> HIGH (brute-force)

# ----------------------------------------------------------------------
# REGEX DESENLERİ
# ----------------------------------------------------------------------
# Linux auth.log satır örneği:
# "Nov 12 06:39:18 ip-172-31-25 sshd[24773]: Failed password for root from 218.92.0.158 port 53362 ssh2"
#
# Neden regex? Çünkü log satırları yapılandırılmamış (unstructured) metindir.
# Regex ile içinden IP, kullanıcı adı, port gibi bilgileri "yakalarız".
FAILED_LOGIN_PATTERN = (
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<port>\d+)"
)

ACCEPTED_LOGIN_PATTERN = (
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"port (?P<port>\d+)"
)

# ----------------------------------------------------------------------
# RİSK SEVİYELERİ (string sabitler)
# ----------------------------------------------------------------------
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

# Risk -> renk eşlemesi (GUI'de kullanılacak)
RISK_COLORS = {
    RISK_LOW: "#3DDC97",     # yeşil
    RISK_MEDIUM: "#FFB454",  # turuncu
    RISK_HIGH: "#FF4D6D",    # kırmızı
}

# ----------------------------------------------------------------------
# DOSYA YOLLARI
# ----------------------------------------------------------------------
REPORTS_DIR = "reports"
DEFAULT_REPORT_FILENAME = "incident_report.txt"

# ----------------------------------------------------------------------
# UYGULAMA METADATA
# ----------------------------------------------------------------------
APP_NAME = "SSH Guardian"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Cybersecurity Portfolio Project"
