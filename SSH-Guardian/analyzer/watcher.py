"""
watcher.py
----------
Real-time auth.log izleyicisi (tail -f benzeri).

Tasarım:
- QObject + QTimer kullanır (QFileSystemWatcher tek başına yetersiz; dosya boyutu
  değişiminde ek satırları okumak için manuel offset takibi gerekir).
- Her POLL_MS'de dosya boyutunu kontrol eder; arttıysa son offset'ten itibaren
  yeni satırları okur ve Qt SIGNAL olarak yayımlar.
- Dashboard bu sinyali dinleyip parser'a yollar, sonucu canlı günceller.

NEDEN POLLING + QFILESYSTEMWATCHER DEĞİL?
- QFileSystemWatcher Linux'ta inotify, macOS'ta FSEvents kullanır ama bazı
  durumlarda (örn. logrotate ile dosya rename) sinyal ÜRETMEZ.
- Polling daha taşınabilir ve büyük dosyalarda 1-2 saniyelik gecikme kabul edilebilir.
"""

import os
from PyQt5.QtCore import QObject, QTimer, pyqtSignal

from utils.constants import WATCHER_POLL_MS


class LogWatcher(QObject):
    """
    Bir log dosyasını sürekli izler ve yeni eklenen satırları sinyal olarak yayar.

    Kullanım:
        watcher = LogWatcher()
        watcher.new_lines.connect(slot_function)
        watcher.start("/var/log/auth.log")
        ...
        watcher.stop()
    """

    # ----- Qt Signals -----
    new_lines = pyqtSignal(list)    # list[str] - yeni log satırları
    started = pyqtSignal(str)       # str - izlenen dosya yolu
    stopped = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._file_path: str | None = None
        self._offset: int = 0           # son okunan byte konumu
        self._timer = QTimer(self)
        self._timer.setInterval(WATCHER_POLL_MS)
        self._timer.timeout.connect(self._poll)
        self._running = False

    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def file_path(self) -> str | None:
        return self._file_path

    # ------------------------------------------------------------------
    def start(self, file_path: str) -> None:
        """İzlemeyi başlat. Dosyanın MEVCUT sonundan itibaren başlar."""
        self.stop()
        if not os.path.isfile(file_path):
            self.error.emit(f"File not found: {file_path}")
            return
        self._file_path = file_path
        try:
            # Mevcut dosya sonuna 'seek' et — geçmiş satırları YENİDEN okuma.
            self._offset = os.path.getsize(file_path)
        except OSError as e:
            self.error.emit(f"Cannot stat file: {e}")
            return
        self._running = True
        self._timer.start()
        self.started.emit(file_path)

    # ------------------------------------------------------------------
    def stop(self) -> None:
        if self._running:
            self._timer.stop()
            self._running = False
            self.stopped.emit()

    # ------------------------------------------------------------------
    def _poll(self) -> None:
        """QTimer her tick'te dosyayı kontrol eder."""
        if not self._file_path:
            return
        try:
            current_size = os.path.getsize(self._file_path)
        except OSError as e:
            self.error.emit(f"Stat failed: {e}")
            return

        # Dosya küçülmüş (logrotate veya truncate) -> offset'i sıfırla.
        if current_size < self._offset:
            self._offset = 0

        # Yeni veri yoksa çık.
        if current_size == self._offset:
            return

        # Yeni byte'ları oku.
        try:
            with open(self._file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._offset)
                chunk = f.read()
                self._offset = f.tell()
        except OSError as e:
            self.error.emit(f"Read failed: {e}")
            return

        # Yeni satırları emit et.
        # splitlines() son '\n' sonrası boş elemanı üretmez — temiz liste.
        lines = chunk.splitlines()
        if lines:
            self.new_lines.emit(lines)
