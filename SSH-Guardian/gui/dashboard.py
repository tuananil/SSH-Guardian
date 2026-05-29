"""
dashboard.py
------------
SSH Guardian'ın ana pencere arayüzü (PyQt5) — v1.1.

Sayfalar (Sidebar ile):
  1. Dashboard   — KPI kartları, top attacker, top usernames, country özet
  2. Attackers   — Tüm saldırgan IP'leri (Country kolonu dahil) ranking
  3. Chart       — Saatlik failed-login bar grafiği (matplotlib)
  4. History     — SQLite'tan geçmiş oturumlar
  5. Raw Logs    — Ham log içeriği

Yeni özellikler:
  - Real-time monitoring (LogWatcher + 'Watch' butonu)
  - GeoIP enrichment (mmdb varsa)
  - Persistence (HistoryDB)
"""

import os
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QBrush
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel,
    QStackedWidget, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QPlainTextEdit, QSpinBox, QMessageBox, QGridLayout,
    QButtonGroup,
)

from analyzer.parser import LogParser
from analyzer.detector import BruteForceDetector, AnalysisResult
from analyzer.report_generator import ReportGenerator
from analyzer.geoip import GeoIPLookup
from analyzer.watcher import LogWatcher

from storage.database import HistoryDB

from gui.styles import (
    APP_QSS, COLOR_DANGER, COLOR_WARNING, COLOR_SUCCESS, COLOR_ACCENT,
)
from gui.widgets import StatCard
from gui.charts import AttackChartWidget

from utils.constants import APP_NAME, APP_VERSION, RISK_HIGH, RISK_MEDIUM
from utils.helpers import format_count


class DashboardWindow(QMainWindow):
    """Ana pencere."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — v{APP_VERSION}")
        self.resize(1360, 820)
        self.setStyleSheet(APP_QSS)

        # ----- İŞ MANTIĞI nesneleri -----
        self.parser = LogParser()
        self.geoip = GeoIPLookup()           # mmdb yoksa pasif
        self.detector = BruteForceDetector(
            brute_force_threshold=5, geoip=self.geoip,
        )
        self.reporter = ReportGenerator()
        self.db = HistoryDB()
        self.watcher = LogWatcher()

        # Watcher sinyallerini bağla
        self.watcher.new_lines.connect(self._on_watcher_lines)
        self.watcher.error.connect(self._on_watcher_error)

        # Durum
        self.last_result: AnalysisResult | None = None
        self.last_file: str | None = None
        # Real-time akümülatör — watcher yeni satır verdikçe büyür
        self._live_events: list = []

        # ----- UI -----
        self._build_ui()
        self._refresh_history_table()

        # Status bar başlangıç mesajı (GeoIP durumu dahil)
        geo_msg = "GeoIP: ENABLED" if self.geoip.is_enabled else "GeoIP: disabled (no mmdb)"
        self.statusBar().showMessage(f"Ready  •  {geo_msg}")

    # ==================================================================
    # UI BUILD
    # ==================================================================
    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = self._build_sidebar()
        root.addWidget(sidebar)

        self.pages = QStackedWidget()
        self.page_dashboard = self._build_page_dashboard()
        self.page_attackers = self._build_page_attackers()
        self.page_chart = self._build_page_chart()
        self.page_history = self._build_page_history()
        self.page_logs = self._build_page_logs()

        self.pages.addWidget(self.page_dashboard)   # 0
        self.pages.addWidget(self.page_attackers)   # 1
        self.pages.addWidget(self.page_chart)       # 2
        self.pages.addWidget(self.page_history)     # 3
        self.pages.addWidget(self.page_logs)        # 4
        root.addWidget(self.pages, stretch=1)

        self.setCentralWidget(central)

    # ------------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(240)

        v = QVBoxLayout(side)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        title = QLabel("🛡  SSH GUARDIAN")
        title.setObjectName("SidebarTitle")
        subtitle = QLabel(f"Brute-Force Analyzer v{APP_VERSION}")
        subtitle.setObjectName("SidebarSubtitle")
        v.addWidget(title)
        v.addWidget(subtitle)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_items = [
            ("  📊  Dashboard",  0),
            ("  🌐  Attackers",  1),
            ("  📈  Chart",      2),
            ("  🗂  History",    3),
            ("  📜  Raw Logs",   4),
        ]
        for text, idx in nav_items:
            btn = QPushButton(text)
            btn.setObjectName("SidebarBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, i=idx: self.pages.setCurrentIndex(i))
            self.nav_group.addButton(btn, idx)
            v.addWidget(btn)

        self.nav_group.button(0).setChecked(True)
        v.addStretch(1)

        footer = QLabel(" © Cybersecurity Portfolio ")
        footer.setStyleSheet("color: #5a6573; padding: 16px;")
        v.addWidget(footer)
        return side

    # ------------------------------------------------------------------
    # PAGE 1 : DASHBOARD
    # ------------------------------------------------------------------
    def _build_page_dashboard(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        # Header
        header = QHBoxLayout()
        title = QLabel("Security Overview")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch(1)

        thr_label = QLabel("Brute-force threshold:")
        thr_label.setStyleSheet("color: #8B98A5;")
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(2, 100)
        self.threshold_spin.setValue(5)
        self.threshold_spin.valueChanged.connect(self._on_threshold_changed)
        header.addWidget(thr_label)
        header.addWidget(self.threshold_spin)

        self.btn_import = QPushButton("📂  Import auth.log")
        self.btn_import.setObjectName("PrimaryBtn")
        self.btn_import.setCursor(Qt.PointingHandCursor)
        self.btn_import.clicked.connect(self._on_import_clicked)
        header.addWidget(self.btn_import)

        self.btn_watch = QPushButton("👁  Watch Live")
        self.btn_watch.setObjectName("SecondaryBtn")
        self.btn_watch.setCheckable(True)
        self.btn_watch.setCursor(Qt.PointingHandCursor)
        self.btn_watch.clicked.connect(self._on_watch_toggled)
        header.addWidget(self.btn_watch)

        self.btn_report = QPushButton("📄  Report")
        self.btn_report.setObjectName("SecondaryBtn")
        self.btn_report.setCursor(Qt.PointingHandCursor)
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self._on_generate_report)
        header.addWidget(self.btn_report)

        layout.addLayout(header)

        # KPI cards
        grid = QGridLayout()
        grid.setSpacing(14)
        self.card_total = StatCard("Total Events", "0", "accent")
        self.card_failed = StatCard("Failed Logins", "0", "danger")
        self.card_attackers = StatCard("Unique Attacker IPs", "0", "warning")
        self.card_suspicious = StatCard("Suspicious IPs", "0", "danger")
        grid.addWidget(self.card_total, 0, 0)
        grid.addWidget(self.card_failed, 0, 1)
        grid.addWidget(self.card_attackers, 0, 2)
        grid.addWidget(self.card_suspicious, 0, 3)
        layout.addLayout(grid)

        # Top attacker
        self.top_card = QFrame()
        self.top_card.setObjectName("StatCard")
        top_layout = QVBoxLayout(self.top_card)
        self.top_title = QLabel("TOP ATTACKER")
        self.top_title.setStyleSheet(
            "color: #8B98A5; font-size: 11px; letter-spacing: 1px;"
        )
        self.top_info = QLabel("— No data yet —")
        self.top_info.setStyleSheet("font-size: 16px; color: #E6EDF3;")
        top_layout.addWidget(self.top_title)
        top_layout.addWidget(self.top_info)
        layout.addWidget(self.top_card)

        # Iki kolon: usernames + countries
        two_col = QHBoxLayout()
        two_col.setSpacing(14)

        # Usernames
        users_box = QVBoxLayout()
        users_title = QLabel("Most Targeted Usernames")
        users_title.setStyleSheet("font-size: 15px; font-weight: 600;")
        users_box.addWidget(users_title)
        self.users_table = QTableWidget(0, 2)
        self.users_table.setHorizontalHeaderLabels(["Username", "Attempts"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.users_table.verticalHeader().setVisible(False)
        self.users_table.setAlternatingRowColors(True)
        self.users_table.setEditTriggers(QTableWidget.NoEditTriggers)
        users_box.addWidget(self.users_table)
        two_col.addLayout(users_box, 1)

        # Countries (GeoIP)
        countries_box = QVBoxLayout()
        countries_title = QLabel("Attacks by Country (GeoIP)")
        countries_title.setStyleSheet("font-size: 15px; font-weight: 600;")
        countries_box.addWidget(countries_title)
        self.countries_table = QTableWidget(0, 2)
        self.countries_table.setHorizontalHeaderLabels(["Country", "Failed"])
        self.countries_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.countries_table.verticalHeader().setVisible(False)
        self.countries_table.setAlternatingRowColors(True)
        self.countries_table.setEditTriggers(QTableWidget.NoEditTriggers)
        countries_box.addWidget(self.countries_table)
        two_col.addLayout(countries_box, 1)

        layout.addLayout(two_col, stretch=1)
        return page

    # ------------------------------------------------------------------
    # PAGE 2 : ATTACKERS
    # ------------------------------------------------------------------
    def _build_page_attackers(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Attacker IP Intelligence")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        subtitle = QLabel(
            "All IPs observed in the imported auth log, ranked by failed attempts."
        )
        subtitle.setStyleSheet("color: #8B98A5;")
        layout.addWidget(subtitle)

        self.attacker_table = QTableWidget(0, 7)
        self.attacker_table.setHorizontalHeaderLabels(
            ["IP", "Country", "Failed", "Success", "Usernames", "First Seen", "Risk"]
        )
        h = self.attacker_table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.Stretch)
        self.attacker_table.verticalHeader().setVisible(False)
        self.attacker_table.setAlternatingRowColors(True)
        self.attacker_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.attacker_table, stretch=1)
        return page

    # ------------------------------------------------------------------
    # PAGE 3 : CHART (matplotlib)
    # ------------------------------------------------------------------
    def _build_page_chart(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Hourly Attack Timeline")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Failed SSH login attempts aggregated by hour. "
            "Helps detect coordinated brute-force bursts."
        )
        subtitle.setStyleSheet("color: #8B98A5;")
        layout.addWidget(subtitle)

        self.chart_widget = AttackChartWidget()
        layout.addWidget(self.chart_widget, stretch=1)
        return page

    # ------------------------------------------------------------------
    # PAGE 4 : HISTORY (SQLite)
    # ------------------------------------------------------------------
    def _build_page_history(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Analysis History")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Past analysis sessions persisted in SQLite. "
            "Double-click a row to view its attackers."
        )
        subtitle.setStyleSheet("color: #8B98A5;")
        layout.addWidget(subtitle)

        # Üst tablo: sessions
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(
            ["ID", "Source", "Created", "Events", "Failed", "Suspicious"]
        )
        h = self.history_table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.itemSelectionChanged.connect(self._on_history_selected)
        layout.addWidget(self.history_table, stretch=1)

        # Aksiyonlar
        actions = QHBoxLayout()
        actions.addStretch(1)
        self.btn_delete_session = QPushButton("🗑  Delete selected")
        self.btn_delete_session.setObjectName("SecondaryBtn")
        self.btn_delete_session.clicked.connect(self._on_delete_session)
        actions.addWidget(self.btn_delete_session)
        layout.addLayout(actions)

        # Alt tablo: seçili oturumun attackers'ı
        attackers_lbl = QLabel("Attackers in selected session")
        attackers_lbl.setStyleSheet("font-size: 15px; font-weight: 600;")
        layout.addWidget(attackers_lbl)

        self.history_attackers_table = QTableWidget(0, 6)
        self.history_attackers_table.setHorizontalHeaderLabels(
            ["IP", "Country", "Failed", "Success", "Risk", "Last Seen"]
        )
        hh = self.history_attackers_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        self.history_attackers_table.verticalHeader().setVisible(False)
        self.history_attackers_table.setAlternatingRowColors(True)
        self.history_attackers_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.history_attackers_table, stretch=1)
        return page

    # ------------------------------------------------------------------
    # PAGE 5 : RAW LOGS
    # ------------------------------------------------------------------
    def _build_page_logs(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Raw auth.log (read-only)")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Import a log file to view its content here…")
        layout.addWidget(self.log_view, stretch=1)
        return page

    # ==================================================================
    # SLOTS
    # ==================================================================
    def _on_threshold_changed(self, value: int) -> None:
        self.detector.threshold = value
        self.statusBar().showMessage(f"Brute-force threshold set to {value}")

    # ------------------------------------------------------------------
    def _on_import_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select auth.log file", "",
            "Log files (*.log *.txt);;All files (*)",
        )
        if not path:
            return
        try:
            self._analyze_file(path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze file:\n{e}")

    # ------------------------------------------------------------------
    def _analyze_file(self, path: str) -> None:
        self.statusBar().showMessage(f"Parsing {path} …")
        events = list(self.parser.parse_file(path))
        result = self.detector.analyze(events)

        self.last_result = result
        self.last_file = path
        self._live_events = list(events)   # watch için hazır tut

        self._apply_result_to_ui(result)
        self._refresh_log_view(path)

        # Veritabanına otomatik kaydet
        try:
            self.db.save_session(path, result)
            self._refresh_history_table()
        except Exception as e:
            print(f"DB save failed: {e}")

        self.btn_report.setEnabled(True)
        self.statusBar().showMessage(
            f"Done — {self.parser.matched_lines}/{self.parser.total_lines} "
            f"lines matched in {os.path.basename(path)}"
        )

    # ------------------------------------------------------------------
    # WATCH (real-time)
    # ------------------------------------------------------------------
    def _on_watch_toggled(self, checked: bool) -> None:
        if checked:
            # Eğer henüz dosya seçilmediyse, kullanıcıdan iste
            path = self.last_file
            if not path:
                path, _ = QFileDialog.getOpenFileName(
                    self, "Select file to WATCH live", "",
                    "Log files (*.log *.txt);;All files (*)",
                )
                if not path:
                    self.btn_watch.setChecked(False)
                    return
                self.last_file = path
                # Mevcut içeriği bir kez analiz et
                self._analyze_file(path)

            self.watcher.start(path)
            self.btn_watch.setText("⏹  Stop Watching")
            self.statusBar().showMessage(f"WATCHING {path} (live)")
        else:
            self.watcher.stop()
            self.btn_watch.setText("👁  Watch Live")
            self.statusBar().showMessage("Watcher stopped")

    def _on_watcher_lines(self, lines: list) -> None:
        """Watcher yeni satırlar yolladı — incremental analiz."""
        if not lines:
            return
        new_events = list(self.parser.parse_iterable(lines))
        if not new_events:
            return
        self._live_events.extend(new_events)
        # Tüm event listesini yeniden analiz et (kullanıcı dosyası mb'ler büyük
        # değilse hızlıdır; aksi takdirde ileride 'merge' edebiliriz).
        result = self.detector.analyze(self._live_events)
        self.last_result = result
        self._apply_result_to_ui(result)

        self.statusBar().showMessage(
            f"LIVE +{len(new_events)} new event(s) — "
            f"total failed: {format_count(result.total_failed)}"
        )

    def _on_watcher_error(self, msg: str) -> None:
        QMessageBox.warning(self, "Watcher error", msg)

    # ------------------------------------------------------------------
    def _on_generate_report(self) -> None:
        if not self.last_result:
            return
        try:
            full_path = self.reporter.generate(
                self.last_result, source_file=self.last_file or "N/A",
            )
            QMessageBox.information(
                self, "Report generated",
                f"Incident report saved:\n{full_path}",
            )
            self.statusBar().showMessage(f"Report saved → {full_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to write report:\n{e}")

    # ==================================================================
    # HISTORY
    # ==================================================================
    def _refresh_history_table(self) -> None:
        sessions = self.db.list_sessions()
        self.history_table.setRowCount(0)
        for s in sessions:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            cells = [
                str(s.id), s.source_file, s.created_at,
                format_count(s.total_events),
                format_count(s.total_failed),
                format_count(s.suspicious),
            ]
            for col, text in enumerate(cells):
                self.history_table.setItem(row, col, QTableWidgetItem(text))

    def _on_history_selected(self) -> None:
        rows = self.history_table.selectionModel().selectedRows()
        if not rows:
            self.history_attackers_table.setRowCount(0)
            return
        session_id = int(self.history_table.item(rows[0].row(), 0).text())
        attackers = self.db.get_session_attackers(session_id)
        self.history_attackers_table.setRowCount(0)
        for a in attackers:
            row = self.history_attackers_table.rowCount()
            self.history_attackers_table.insertRow(row)
            cells = [
                a["ip"], a.get("country") or "N/A",
                format_count(a["failed"]),
                format_count(a["successful"]),
                a["risk"],
                a.get("last_seen") or "—",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 4:
                    color = (
                        COLOR_DANGER if a["risk"] == RISK_HIGH else
                        COLOR_WARNING if a["risk"] == RISK_MEDIUM else
                        COLOR_SUCCESS
                    )
                    item.setForeground(QBrush(QColor(color)))
                    f = item.font()
                    f.setBold(True)
                    item.setFont(f)
                self.history_attackers_table.setItem(row, col, item)

    def _on_delete_session(self) -> None:
        rows = self.history_table.selectionModel().selectedRows()
        if not rows:
            return
        session_id = int(self.history_table.item(rows[0].row(), 0).text())
        reply = QMessageBox.question(
            self, "Confirm delete",
            f"Delete session #{session_id} and all its attackers?",
        )
        if reply == QMessageBox.Yes:
            self.db.delete_session(session_id)
            self._refresh_history_table()
            self.history_attackers_table.setRowCount(0)

    # ==================================================================
    # REFRESH HELPERS
    # ==================================================================
    def _apply_result_to_ui(self, result: AnalysisResult) -> None:
        # KPI
        self.card_total.set_value(format_count(result.total_events))
        self.card_failed.set_value(format_count(result.total_failed))
        self.card_attackers.set_value(format_count(len(result.attackers)))
        self.card_suspicious.set_value(format_count(result.suspicious_count))

        # Top attacker
        if result.top_attacker:
            ta = result.top_attacker
            color = COLOR_DANGER if ta.risk_level == RISK_HIGH else (
                COLOR_WARNING if ta.risk_level == RISK_MEDIUM else COLOR_SUCCESS
            )
            self.top_info.setText(
                f"<span style='color:{color}; font-weight:700;'>{ta.ip}</span>"
                f" &nbsp;[{ta.country}]&nbsp;—&nbsp; "
                f"{format_count(ta.failed_attempts)} failed attempts"
                f" &nbsp;•&nbsp; risk: <b>{ta.risk_level}</b>"
                + ("  <span style='color:#FF4D6D;'>⚠ POSSIBLE BREACH</span>"
                   if ta.is_breached else "")
            )
        else:
            self.top_info.setText("— No attacker data —")

        # Usernames
        self.users_table.setRowCount(0)
        for user, count in result.top_usernames:
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            self.users_table.setItem(row, 0, QTableWidgetItem(user))
            self.users_table.setItem(row, 1, QTableWidgetItem(format_count(count)))

        # Countries
        self.countries_table.setRowCount(0)
        for country, count in result.country_counts:
            row = self.countries_table.rowCount()
            self.countries_table.insertRow(row)
            self.countries_table.setItem(row, 0, QTableWidgetItem(country))
            self.countries_table.setItem(row, 1, QTableWidgetItem(format_count(count)))

        # Attackers tablosu
        self.attacker_table.setRowCount(0)
        for a in result.attackers:
            row = self.attacker_table.rowCount()
            self.attacker_table.insertRow(row)
            cells = [
                a.ip,
                a.country,
                format_count(a.failed_attempts),
                format_count(a.successful_logins),
                ", ".join(sorted(a.usernames_tried))[:80],
                str(a.first_seen) if a.first_seen else "—",
                a.risk_level,
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 6:
                    color = (
                        COLOR_DANGER if a.risk_level == RISK_HIGH else
                        COLOR_WARNING if a.risk_level == RISK_MEDIUM else
                        COLOR_SUCCESS
                    )
                    item.setForeground(QBrush(QColor(color)))
                    f = item.font()
                    f.setBold(True)
                    item.setFont(f)
                self.attacker_table.setItem(row, col, item)

        # Chart
        self.chart_widget.update_data(result.hourly_failures)

    # ------------------------------------------------------------------
    def _refresh_log_view(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= 5000:
                        lines.append("\n… [truncated for preview] …")
                        break
                    lines.append(line)
                self.log_view.setPlainText("".join(lines))
        except Exception as e:
            self.log_view.setPlainText(f"<error reading file: {e}>")

    # ==================================================================
    # CLEANUP
    # ==================================================================
    def closeEvent(self, event):
        """Pencere kapanırken kaynakları temizle."""
        try:
            self.watcher.stop()
            self.db.close()
            self.geoip.close()
        finally:
            super().closeEvent(event)
