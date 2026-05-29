"""
constants.py
------------
SSH Guardian uygulamasının tüm SABİT değerlerini barındırır.

Tek doğruluk kaynağı (Single Source of Truth).
"""

# ----------------------------------------------------------------------
# BRUTE-FORCE / RİSK EŞİKLERİ
# ----------------------------------------------------------------------
LOW_RISK_THRESHOLD = 3      # 1-3  başarısız -> LOW
MEDIUM_RISK_THRESHOLD = 10  # 4-10 başarısız -> MEDIUM
# 10+ başarısız                              -> HIGH

# ----------------------------------------------------------------------
# REGEX DESENLERİ
# ----------------------------------------------------------------------
# Örnek satır:
# "Nov 12 06:39:18 host sshd[24773]: Failed password for root from 218.92.0.158 port 53362 ssh2"
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
# RİSK ETİKETLERİ
# ----------------------------------------------------------------------
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

RISK_COLORS = {
    RISK_LOW: "#3DDC97",
    RISK_MEDIUM: "#FFB454",
    RISK_HIGH: "#FF4D6D",
}

# ----------------------------------------------------------------------
# DOSYA YOLLARI
# ----------------------------------------------------------------------
REPORTS_DIR = "reports"
DEFAULT_REPORT_FILENAME = "incident_report.txt"

# SQLite veritabanı
DB_PATH = "ssh_guardian.db"

# MaxMind GeoLite2 mmdb dosya konumu (opsiyonel)
# Kullanıcı maxmind.com'dan ücretsiz indirip buraya koyacak.
GEOIP_DB_PATH = "assets/GeoLite2-Country.mmdb"

# ----------------------------------------------------------------------
# WATCHER
# ----------------------------------------------------------------------
WATCHER_POLL_MS = 1000   # ms; auth.log her saniye kontrol edilecek

# ----------------------------------------------------------------------
# UYGULAMA METADATA
# ----------------------------------------------------------------------
APP_NAME = "SSH Guardian"
APP_VERSION = "1.1.0"
APP_AUTHOR = "Cybersecurity Portfolio Project"
