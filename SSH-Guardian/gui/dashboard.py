"""
dashboard.py
------------
SSH Guardian'ın ana pencere arayüzü (PyQt5).

GUI Mimarisi:
┌──────────────────────────────────────────────┐
│ Sidebar │           Stacked Pages            │
│         │  (Dashboard / Attackers / Logs)    │
│  Logo   │                                    │
│  Nav    │                                    │
│         │                                    │
└──────────────────────────────────────────────┘
- Sidebar: QPushButton'lardan oluşan dikey navigasyon.
- Stacked: Aynı anda yalnızca BİR sayfa görünür (QStackedWidget).
- Signals/Slots: Buton tıklandığında ilgili sayfa açılır.
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

from gui.styles import (
    APP_QSS, COLOR_DANGER, COLOR_WARNING, COLOR_SUCCESS, COLOR_TEXT,
)
from gui.widgets import StatCard

from utils.constants import APP_NAME, APP_VERSION, RISK_HIGH, RISK_MEDIUM
from utils.helpers import format_count


class DashboardWindow(QMainWindow):
    """
    SSH Guardian'ın ana penceresi.
    """

    # ------------------------------------------------------------------
    # KURUCU
    # ------------------------------------------------------------------
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — v{APP_VERSION}")
        self.resize(1280, 780)
        self.setStyleSheet(APP_QSS)

        # ----- İŞ MANTIĞI nesneleri (Composition over Inheritance) -----
        self.parser = LogParser()
        self.detector = BruteForceDetector(brute_force_threshold=5)
        self.reporter = ReportGenerator()

        # Son analiz sonucu (raporlama için sakla)
        self.last_result: AnalysisResult | None = None
        self.last_file: str | None = None

        # ----- UI'yi kur -----
        self._build_ui()
        self.statusBar().showMessage("Ready. Import an auth.log file to begin.")

    # ------------------------------------------------------------------
    # UI İNŞASI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # Merkez widget = yatay layout (sidebar + içerik)
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # 1) SIDEBAR
        sidebar = self._build_sidebar()
        root.addWidget(sidebar)

        # 2) STACKED PAGES
        self.pages = QStackedWidget()
        self.page_dashboard = self._build_page_dashboard()
        self.page_attackers = self._build_page_attackers()
        self.page_logs = self._build_page_logs()

        self.pages.addWidget(self.page_dashboard)   # index 0
        self.pages.addWidget(self.page_attackers)   # index 1
        self.pages.addWidget(self.page_logs)        # index 2
        root.addWidget(self.pages, stretch=1)

        self.setCentralWidget(central)

    # ------------------------------------------------------------------
    # SIDEBAR
    # ------------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(230)

        v = QVBoxLayout(side)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # Logo / başlık
        title = QLabel("🛡  SSH GUARDIAN")
        title.setObjectName("SidebarTitle")
        subtitle = QLabel(f"Brute-Force Analyzer v{APP_VERSION}")
        subtitle.setObjectName("SidebarSubtitle")
        v.addWidget(title)
        v.addWidget(subtitle)

        # Menü butonları — checkable, aynı grupta (radio davranışı)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_items = [
            ("  📊  Dashboard", 0),
            ("  🌐  Attackers", 1),
            ("  📜  Raw Logs",  2),
        ]
        for text, idx in nav_items:
            btn = QPushButton(text)
            btn.setObjectName("SidebarBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            # Tıklayınca ilgili sayfayı göster (lambda + default arg ile closure tuzağından kaçınma)
            btn.clicked.connect(lambda _, i=idx: self.pages.setCurrentIndex(i))
            self.nav_group.addButton(btn, idx)
            v.addWidget(btn)

        # İlk butonu seçili göster
        self.nav_group.button(0).setChecked(True)

        v.addStretch(1)

        # Footer
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

        # === Başlık ve aksiyon butonları ===
        header = QHBoxLayout()
        title = QLabel("Security Overview")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch(1)

        # Threshold spinbox (kullanıcı brute-force eşiğini ayarlasın)
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

        self.btn_report = QPushButton("📄  Generate Report")
        self.btn_report.setObjectName("SecondaryBtn")
        self.btn_report.setCursor(Qt.PointingHandCursor)
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self._on_generate_report)
        header.addWidget(self.btn_report)

        layout.addLayout(header)

        # === Stat kartları (4'lü grid) ===
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

        # === Top attacker özet kartı ===
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

        # === En çok hedef alınan kullanıcılar tablosu ===
        users_title = QLabel("Most Targeted Usernames")
        users_title.setStyleSheet("font-size: 15px; font-weight: 600; margin-top:8px;")
        layout.addWidget(users_title)

        self.users_table = QTableWidget(0, 2)
        self.users_table.setHorizontalHeaderLabels(["Username", "Attempts"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.users_table.verticalHeader().setVisible(False)
        self.users_table.setAlternatingRowColors(True)
        self.users_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.users_table, stretch=1)

        return page

    # ------------------------------------------------------------------
    # PAGE 2 : ATTACKERS TABLE
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

        self.attacker_table = QTableWidget(0, 6)
        self.attacker_table.setHorizontalHeaderLabels(
            ["IP", "Failed", "Success", "Usernames", "First Seen", "Risk"]
        )
        h = self.attacker_table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.Stretch)  # usernames esnek
        self.attacker_table.verticalHeader().setVisible(False)
        self.attacker_table.setAlternatingRowColors(True)
        self.attacker_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.attacker_table, stretch=1)

        return page

    # ------------------------------------------------------------------
    # PAGE 3 : RAW LOG VIEWER
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
    # ============   SLOTS / EVENT HANDLERS   ==========================
    # ==================================================================

    def _on_threshold_changed(self, value: int) -> None:
        """Brute-force eşik değeri değiştiğinde detector'ı güncelle."""
        self.detector.threshold = value
        self.statusBar().showMessage(f"Brute-force threshold set to {value}")

    def _on_import_clicked(self) -> None:
        """Kullanıcı 'Import auth.log' tıkladığında çalışır."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select auth.log file",
            "",
            "Log files (*.log *.txt);;All files (*)",
        )
        if not path:
            return

        try:
            self._analyze_file(path)
        except Exception as e:
            # Hatayı kullanıcıya nazikçe bildir (uygulamayı çökertme)
            QMessageBox.critical(self, "Error", f"Failed to analyze file:\n{e}")

    def _analyze_file(self, path: str) -> None:
        """Parse + detect + UI güncellemesi."""
        self.statusBar().showMessage(f"Parsing {path} …")
        events = list(self.parser.parse_file(path))   # generator -> list
        result = self.detector.analyze(events)

        self.last_result = result
        self.last_file = path

        # UI'yı güncelle
        self._refresh_dashboard(result)
        self._refresh_attackers_table(result)
        self._refresh_log_view(path)

        self.btn_report.setEnabled(True)
        self.statusBar().showMessage(
            f"Done — {self.parser.matched_lines}/{self.parser.total_lines} "
            f"lines matched in {os.path.basename(path)}"
        )

    def _on_generate_report(self) -> None:
        """Incident report üret ve kullanıcıya yolu göster."""
        if not self.last_result:
            return
        try:
            full_path = self.reporter.generate(
                self.last_result,
                source_file=self.last_file or "N/A",
            )
            QMessageBox.information(
                self, "Report generated",
                f"Incident report saved:\n{full_path}",
            )
            self.statusBar().showMessage(f"Report saved → {full_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to write report:\n{e}")

    # ==================================================================
    # ============   UI REFRESH HELPERS   ==============================
    # ==================================================================

    def _refresh_dashboard(self, result: AnalysisResult) -> None:
        self.card_total.set_value(format_count(result.total_events))
        self.card_failed.set_value(format_count(result.total_failed))
        self.card_attackers.set_value(format_count(len(result.attackers)))
        self.card_suspicious.set_value(format_count(result.suspicious_count))

        if result.top_attacker:
            ta = result.top_attacker
            color = COLOR_DANGER if ta.risk_level == RISK_HIGH else (
                COLOR_WARNING if ta.risk_level == RISK_MEDIUM else COLOR_SUCCESS
            )
            self.top_info.setText(
                f"<span style='color:{color}; font-weight:700;'>{ta.ip}</span> "
                f"&nbsp;—&nbsp; {format_count(ta.failed_attempts)} failed attempts "
                f"&nbsp;•&nbsp; risk: <b>{ta.risk_level}</b>"
            )
        else:
            self.top_info.setText("— No attacker data —")

        # Username table
        self.users_table.setRowCount(0)
        for user, count in result.top_usernames:
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            self.users_table.setItem(row, 0, QTableWidgetItem(user))
            self.users_table.setItem(row, 1, QTableWidgetItem(format_count(count)))

    def _refresh_attackers_table(self, result: AnalysisResult) -> None:
        self.attacker_table.setRowCount(0)
        for a in result.attackers:
            row = self.attacker_table.rowCount()
            self.attacker_table.insertRow(row)

            cells = [
                a.ip,
                format_count(a.failed_attempts),
                format_count(a.successful_logins),
                ", ".join(sorted(a.usernames_tried))[:80],
                str(a.first_seen) if a.first_seen else "—",
                a.risk_level,
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 5:  # Risk hücresine renk ver
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

    def _refresh_log_view(self, path: str) -> None:
        """Ham log dosyasını (ilk ~5000 satırı) görüntüler."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                # Çok büyük dosyalar için ilk 5000 satır yeterli
                lines = []
                for i, line in enumerate(f):
                    if i >= 5000:
                        lines.append("\n… [truncated for preview] …")
                        break
                    lines.append(line)
                self.log_view.setPlainText("".join(lines))
        except Exception as e:
            self.log_view.setPlainText(f"<error reading file: {e}>")
